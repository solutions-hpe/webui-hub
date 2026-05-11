"""ACME certificate management for Hub.

Handles certificate requests and renewals via the ACME protocol (Let's Encrypt,
ZeroSSL, or any RFC 8555-compliant CA). Configured entirely through the web UI —
no env vars required.

Config is stored in the hub's global settings JSON (DATA_DIR/acme.json).
Account key is stored at DATA_DIR/tls/acme_account.pem.
Issued cert/key replace DATA_DIR/tls/cert.pem and DATA_DIR/tls/key.pem.

Challenge type: DNS-01 only.
Supported providers: cloudflare (full), hurricane_electric (full),
                     azure_dns (stub), route53 (stub).

Hurricane Electric DNS setup:
  1. In dns.he.net, create a TXT record for _acme-challenge.<domain>
  2. Enable DDNS on that record and note the generated DDNS key
  3. Enter the DDNS key as the credential — the hostname is derived automatically
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from .config import get_settings
from .crypto import decrypt_dict, encrypt_dict

logger = logging.getLogger(__name__)
_CA_DIRECTORY = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
}
_cloudflare_records: dict[tuple[str, str], tuple[str, str, dict[str, str]]] = {}
_he_records: dict[tuple[str, str], str] = {}  # (domain, txt_record) → acme-challenge hostname
_acme_status: dict[str, Any] = {
    "running": False,
    "status": "idle",
    "last_result": None,
    "last_error": None,
    "last_log": "",
    "last_log_at": "",
}


class AcmeLogCapture:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def append(self, message: str) -> None:
        line = f"[{_iso(_utcnow())}] {message}"
        self.lines.append(line)
        _set_acme_status(last_log=self.text(), last_log_at=_iso(_utcnow()))

    def append_exception(self, exc: Exception) -> None:
        self.append(f"ERROR: {exc}")
        details = traceback.format_exc().strip()
        if details and details != "NoneType: None":
            self.append("Traceback:")
            self.lines.extend(details.splitlines())
            _set_acme_status(last_log=self.text(), last_log_at=_iso(_utcnow()))

    def text(self) -> str:
        return "\n".join(self.lines).strip()


def _set_acme_status(**updates: Any) -> None:
    _acme_status.update(updates)


def _derive_status(current: dict[str, Any], cfg: AcmeConfig | None = None) -> str:
    if current.get("running"):
        return "running"
    result = current.get("last_result")
    if isinstance(result, dict):
        if result.get("success") is True:
            return "success"
        if result.get("success") is False:
            return "failed"
    if current.get("last_error") or (cfg and cfg.last_error):
        return "error"
    return "idle"


def get_acme_status() -> dict[str, Any]:
    cfg = load_acme_config()
    status = dict(_acme_status)
    if not status.get("last_log"):
        status["last_log"] = cfg.last_log
    if not status.get("last_log_at"):
        status["last_log_at"] = cfg.last_log_at
    if not status.get("last_error"):
        status["last_error"] = cfg.last_error or None
    status["status"] = _derive_status(status, cfg)
    return status


@dataclass
class AcmeConfig:
    enabled: bool = False
    domain: str = ""
    email: str = ""
    challenge: str = "dns-01"
    ca: str = "letsencrypt"
    dns_provider: str = ""
    dns_credentials: dict = field(default_factory=dict)
    last_renewed: str = ""
    last_error: str = ""
    cert_expiry: str = ""
    last_log: str = ""
    last_log_at: str = ""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str:
    if not dt:
        return ""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _cfg_path(data_dir: Path | None = None) -> Path:
    base = data_dir or Path(get_settings().data_dir)
    return base / "acme.json"


def _cert_path(data_dir: Path | None = None) -> Path:
    base = data_dir or Path(get_settings().data_dir)
    return base / "tls" / "cert.pem"


def _challenge_store() -> dict[str, str]:
    return {}


def _serialize_config(cfg: AcmeConfig, *, encrypt_credentials: bool) -> dict[str, Any]:
    data = asdict(cfg)
    creds = dict(cfg.dns_credentials or {})
    data["dns_credentials"] = encrypt_dict(creds) if encrypt_credentials and creds else ("" if encrypt_credentials else creds)
    return data


def _load_acme_config(path: Path) -> AcmeConfig:
    if not path.exists():
        return AcmeConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to read ACME config %s: %s", path, exc)
        return AcmeConfig()
    creds = raw.get("dns_credentials")
    if isinstance(creds, str) and creds:
        try:
            raw["dns_credentials"] = decrypt_dict(creds)
        except Exception as exc:
            logger.warning("Failed to decrypt ACME DNS credentials: %s", exc)
            raw["dns_credentials"] = {}
    elif not isinstance(creds, dict):
        raw["dns_credentials"] = {}
    allowed = {field.name for field in AcmeConfig.__dataclass_fields__.values()}
    return AcmeConfig(**{key: raw.get(key) for key in allowed if key in raw})


def load_acme_config() -> AcmeConfig:
    return _load_acme_config(_cfg_path())


def save_acme_config(cfg: AcmeConfig) -> None:
    path = _cfg_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_serialize_config(cfg, encrypt_credentials=True), indent=2), encoding="utf-8")


def _get_cert_info(path: Path) -> dict:
    if not path.exists():
        return {"source": "none"}
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    try:
        domain = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        domain = ""
    issuer = ""
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = cert.issuer.get_attributes_for_oid(oid)
        if attrs:
            issuer = attrs[0].value
            break
    expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
    remaining = max(0, int((expires - _utcnow()).total_seconds() // 86400))
    is_self_signed = cert.issuer == cert.subject
    source = "self-signed" if is_self_signed else "custom"
    cfg = load_acme_config()
    if cfg.last_renewed and cfg.domain and cfg.domain == domain:
        source = "acme"
    return {
        "domain": domain,
        "issuer": issuer,
        "expires": _iso(expires),
        "days_remaining": remaining,
        "is_self_signed": is_self_signed,
        "source": source,
    }


def get_cert_info() -> dict:
    return _get_cert_info(_cert_path())


def _ca_directory(ca: str) -> str:
    return _CA_DIRECTORY.get(ca, _CA_DIRECTORY["letsencrypt"])


def _get_or_create_account_key(key_path: Path) -> josepy.JWKRSA:
    from josepy import JWKRSA

    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        private_key = load_pem_private_key(key_path.read_bytes(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return JWKRSA(key=private_key)


async def _dns01_cloudflare(domain: str, txt_record: str, credentials: dict, log: AcmeLogCapture | None = None) -> None:
    import httpx

    token = (credentials or {}).get("cf_api_token", "").strip()
    email = (credentials or {}).get("cf_email", "").strip()
    api_key = (credentials or {}).get("cf_api_key", "").strip()
    if token:
        headers = {"Authorization": f"Bearer {token}"}
    elif email and api_key:
        headers = {"X-Auth-Email": email, "X-Auth-Key": api_key}
    else:
        raise ValueError("Cloudflare credentials must include cf_api_token or cf_email + cf_api_key")
    headers["Content-Type"] = "application/json"

    labels = domain.split(".")
    zone_id = ""
    zone_name = ""
    if log:
        log.append(f"Preparing Cloudflare DNS-01 challenge for {domain}")
    async with httpx.AsyncClient(timeout=20) as client:
        for index in range(1, len(labels)):
            candidate = ".".join(labels[index:])
            if log:
                log.append(f"Checking Cloudflare zone candidate {candidate}")
            response = await client.get("https://api.cloudflare.com/client/v4/zones", params={"name": candidate}, headers=headers)
            response.raise_for_status()
            payload = response.json()
            result = payload.get("result") or []
            if result:
                zone_id = result[0]["id"]
                zone_name = candidate
                break
        if not zone_id:
            raise ValueError(f"Could not determine Cloudflare zone for {domain}")
        record_name = f"_acme-challenge.{domain}" if domain != zone_name else f"_acme-challenge.{zone_name}"
        if log:
            log.append(f"Creating TXT record {record_name} in Cloudflare zone {zone_name}")
        response = await client.post(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers,
            json={"type": "TXT", "name": record_name, "content": txt_record, "ttl": 120},
        )
        response.raise_for_status()
        result = response.json().get("result") or {}
        record_id = result.get("id")
        if not record_id:
            raise ValueError("Cloudflare did not return a DNS record id")
        _cloudflare_records[(domain, txt_record)] = (zone_id, record_id, headers)
    if log:
        log.append("Cloudflare TXT record created; waiting 10 seconds for propagation")
    await asyncio.sleep(10)


async def _cleanup_cloudflare_record(domain: str, txt_record: str) -> None:
    import httpx

    record = _cloudflare_records.pop((domain, txt_record), None)
    if not record:
        return
    zone_id, record_id, headers = record
    async with httpx.AsyncClient(timeout=20) as client:
        with contextlib.suppress(Exception):
            await client.delete(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
                headers=headers,
            )


async def _dns01_hurricane_electric(domain: str, txt_record: str, credentials: dict, log: AcmeLogCapture | None = None) -> None:
    """Set _acme-challenge TXT record via Hurricane Electric DDNS API.

    Prerequisites (one-time setup in dns.he.net):
      1. Create a TXT record named _acme-challenge.<domain>
      2. Enable DDNS on that record — HE generates a DDNS key
      3. Supply that key as ``he_ddns_key`` in credentials
    """
    import httpx

    ddns_key = (credentials or {}).get("he_ddns_key", "").strip()
    if not ddns_key:
        raise ValueError("Hurricane Electric DNS requires he_ddns_key credential")

    challenge_hostname = f"_acme-challenge.{domain}"
    if log:
        log.append(f"Updating Hurricane Electric TXT record {challenge_hostname}")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://dyn.dns.he.net/nic/update",
            data={"hostname": challenge_hostname, "password": ddns_key, "txt": txt_record},
        )
        body = response.text.strip()
        if response.status_code not in (200, 204) or body.startswith("badauth"):
            raise ValueError(f"HE DNS update failed ({response.status_code}): {body}")
        if not (body.startswith("good") or body.startswith("nochg")):
            raise ValueError(f"HE DNS unexpected response: {body}")

    _he_records[(domain, txt_record)] = challenge_hostname
    if log:
        log.append("Hurricane Electric TXT record updated; waiting 15 seconds for propagation")
    # Allow time for DNS propagation before CA checks
    await asyncio.sleep(15)


async def _cleanup_he_record(domain: str, txt_record: str, ddns_key: str = "") -> None:
    """Clear the _acme-challenge TXT record after validation."""
    import httpx

    entry = _he_records.pop((domain, txt_record), None)
    if not entry or not ddns_key:
        return
    async with httpx.AsyncClient(timeout=20) as client:
        with contextlib.suppress(Exception):
            await client.post(
                "https://dyn.dns.he.net/nic/update",
                data={"hostname": entry, "password": ddns_key, "txt": ""},
            )


async def _dns01_azure(domain: str, txt_record: str, credentials: dict) -> None:
    logger.warning("Azure DNS provider not yet implemented")
    raise NotImplementedError("Azure DNS provider not yet implemented")


async def _dns01_route53(domain: str, txt_record: str, credentials: dict) -> None:
    logger.warning("Route53 provider not yet implemented")
    raise NotImplementedError("Route53 provider not yet implemented")


async def request_certificate(cfg: AcmeConfig, data_dir: Path) -> dict:
    data_dir = Path(data_dir)
    tls_dir = data_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    account_key_path = tls_dir / "acme_account.pem"
    server: asyncio.AbstractServer | None = None
    dns_cleanup: tuple[str, str, str] | None = None
    token: str | None = None
    log = AcmeLogCapture()
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = new_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    domain = cfg.domain.strip()
    _set_acme_status(running=True, status="running", last_result=None, last_error=None, last_log="", last_log_at="")
    log.append(
        f"Starting ACME certificate request for {domain or '(unset domain)'} "
        f"via {cfg.ca or 'letsencrypt'} using dns-01"
    )

    try:
        if not domain:
            raise ValueError("Domain is required")
        if not cfg.dns_provider:
            raise ValueError("DNS provider is required for dns-01")

        from acme import client, messages

        log.append("Loading ACME account key")
        account_key = _get_or_create_account_key(account_key_path)
        network = client.ClientNetwork(account_key, user_agent="webui-hub-acme")
        directory_url = _ca_directory(cfg.ca)
        log.append(f"Fetching ACME directory {directory_url}")
        directory = messages.Directory.from_json(network.get(directory_url).json())
        acme_client = client.ClientV2(directory, network)

        contact = [f"mailto:{cfg.email.strip()}"] if cfg.email.strip() else ()
        log.append("Registering or reusing ACME account")
        await asyncio.to_thread(
            acme_client.new_account,
            messages.NewRegistration.from_data(email=contact, terms_of_service_agreed=True),
        )

        log.append(f"Creating CSR for {domain}")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(new_key, hashes.SHA256())
        )
        log.append("Creating ACME order")
        order = await asyncio.to_thread(acme_client.new_order, csr.public_bytes(serialization.Encoding.PEM))

        challenge_body = None
        authz_domain = domain
        for authorization in getattr(order, "authorizations", []):
            identifier = getattr(getattr(authorization, "body", None), "identifier", None)
            if getattr(identifier, "value", ""):
                authz_domain = identifier.value
            for candidate in getattr(getattr(authorization, "body", None), "challenges", []):
                challenge_obj = getattr(candidate, "chall", candidate)
                if getattr(challenge_obj, "typ", "") == cfg.challenge:
                    challenge_body = candidate
                    break
            if challenge_body is not None:
                break
        if challenge_body is None:
            raise RuntimeError(f"No dns-01 challenge offered for {domain}")

        challenge_obj = getattr(challenge_body, "chall", challenge_body)
        response = challenge_body.response(account_key) if hasattr(challenge_body, "response") else challenge_obj.response(account_key)

        validation = challenge_body.validation(account_key) if hasattr(challenge_body, "validation") else challenge_obj.validation(account_key)
        if cfg.dns_provider == "cloudflare":
            await _dns01_cloudflare(authz_domain, validation, cfg.dns_credentials, log=log)
            dns_cleanup = (authz_domain, validation, "cloudflare")
        elif cfg.dns_provider == "hurricane_electric":
            await _dns01_hurricane_electric(authz_domain, validation, cfg.dns_credentials, log=log)
            dns_cleanup = (authz_domain, validation, "hurricane_electric")
        elif cfg.dns_provider == "azure_dns":
            await _dns01_azure(authz_domain, validation, cfg.dns_credentials)
        elif cfg.dns_provider == "route53":
            await _dns01_route53(authz_domain, validation, cfg.dns_credentials)
        else:
            raise ValueError(f"Unsupported DNS provider: {cfg.dns_provider}")

        log.append("Answering ACME challenge")
        await asyncio.to_thread(acme_client.answer_challenge, challenge_body, response)
        deadline = _utcnow() + timedelta(seconds=60)
        log.append("Waiting for ACME validation and certificate finalization")
        order = await asyncio.to_thread(acme_client.poll_and_finalize, order, deadline)
        fullchain_pem = getattr(order, "fullchain_pem", "")
        if not fullchain_pem:
            raise RuntimeError("ACME CA did not return a certificate chain")

        cert_path = tls_dir / "cert.pem"
        key_path = tls_dir / "key.pem"
        log.append(f"Writing certificate to {cert_path}")
        cert_path.write_text(fullchain_pem, encoding="utf-8")
        key_path.write_bytes(key_pem)

        cert_info = _get_cert_info(cert_path)
        cfg.last_renewed = _iso(_utcnow())
        cfg.cert_expiry = cert_info.get("expires", "")
        cfg.last_error = ""
        log.append(f"Certificate issued successfully; expires {cfg.cert_expiry or 'unknown'}")
        cfg.last_log = log.text()
        cfg.last_log_at = _iso(_utcnow())
        save_acme_config(cfg)
        result = {"success": True, "expires": cfg.cert_expiry, "domain": cert_info.get("domain") or domain}
        _set_acme_status(
            running=False,
            status="success",
            last_result=result,
            last_error=None,
            last_log=cfg.last_log,
            last_log_at=cfg.last_log_at,
        )
        return result
    except Exception as exc:
        log.append_exception(exc)
        cfg.last_error = str(exc)
        cfg.last_log = log.text()
        cfg.last_log_at = _iso(_utcnow())
        save_acme_config(cfg)
        logger.exception("ACME certificate request failed for %s", cfg.domain)
        result = {"success": False, "error": str(exc)}
        _set_acme_status(
            running=False,
            status="failed",
            last_result=result,
            last_error=str(exc),
            last_log=cfg.last_log,
            last_log_at=cfg.last_log_at,
        )
        return result
    finally:
        if server is not None:
            log.append("Stopping HTTP-01 challenge server")
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()
        if token:
            _challenge_store().pop(token, None)
        if dns_cleanup:
            domain_c, txt_c, provider_c = dns_cleanup
            if provider_c == "hurricane_electric":
                log.append(f"Cleaning up Hurricane Electric TXT record for {domain_c}")
                await _cleanup_he_record(domain_c, txt_c, (cfg.dns_credentials or {}).get("he_ddns_key", ""))
            else:
                log.append(f"Cleaning up Cloudflare TXT record for {domain_c}")
                await _cleanup_cloudflare_record(domain_c, txt_c)
        if cfg.last_log != log.text():
            cfg.last_log = log.text()
            cfg.last_log_at = _iso(_utcnow())
            save_acme_config(cfg)
            _set_acme_status(last_log=cfg.last_log, last_log_at=cfg.last_log_at)


async def renew_if_needed(data_dir: Path) -> bool:
    data_dir = Path(data_dir)
    cfg = _load_acme_config(_cfg_path(data_dir))
    if not cfg.enabled:
        return False
    cert_info = _get_cert_info(_cert_path(data_dir))
    if cert_info.get("source") == "none":
        result = await request_certificate(cfg, data_dir)
        return bool(result.get("success"))
    expires = cert_info.get("expires")
    if not expires:
        return False
    expiry_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    if expiry_dt - _utcnow() < timedelta(days=30):
        result = await request_certificate(cfg, data_dir)
        return bool(result.get("success"))
    return False

# Hub — Client-Sim Central Platform

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-JSON%20Hub-009688)
![Docker](https://img.shields.io/badge/deployment-Docker%20%7C%20ACI%20%7C%20BYOD-2496ED)
![TLS](https://img.shields.io/badge/TLS-self--signed%20by%20default-success)
![Release](https://img.shields.io/badge/release-v2.30-success)

Hub is the central management plane for the HPE Client-Sim hub-and-spoke platform. It provides a FastAPI-based, multi-tenant backend that stores operational state in JSON under `/data/`. The browser UI is sourced from the shared `cs-webui` repository; Hub serves that frontend and injects `WEBUI_MODE=hub` at runtime.

## Overview

Hub is designed for operators who need to manage many spoke environments from one control plane while keeping tenant boundaries intact.

### Key capabilities

- Multi-tenant management for Aruba Central-backed tenants and manually created tenants
- Role-based access with **superadmin**, **admin**, and **operator** scopes
- Registration, approval, and lifecycle management for webui-spoke servers, including tenant onboarding PSKs for zero-touch spoke approval
- Centralized or distributed execution for Aruba polling, notifications, schedules, gkill, heartbeat, repo sync, and tenant-level dongle allocation policy
- JSON file store under `/data/` instead of PostgreSQL, SQLite, or SQLAlchemy
- HTTPS by default on port **8443** with self-signed certificate generation at startup
- Local JWT authentication plus hub-side LDAP/AD, RADIUS, and TACACS+ provider support; OIDC remains stubbed for future work
- GitHub-first tenant config editors for `simulation.conf` and `user-overrides.conf`, with hub override mode pushed to spokes
- Deployment options for Docker, Azure Container Instance, and BYOD Linux hosts
- Per-spoke command queue, inbox/ack relay, and 7-day rolling audit history
- Sites monitoring that compares current wireless clients against a sticky 7-day rolling baseline alarm

## Architecture

Hub sits in the center of the platform, serving the shared `cs-webui` frontend in hub mode while approved spokes poll for work and report telemetry.

```text
                           +-----------------------------------+
                           |               Hub                 |
                           | FastAPI + cs-webui frontend + JSON Store |
                           | /data users, tenants, queue, audit|
                           +-----------------+-----------------+
                                             |
                    HTTPS 8443 / JWT / X-API-Key relay per tenant
                                             |
        +------------------------------------+------------------------------------+
        |                                    |                                    |
+-------v--------+                    +------v--------+                    +-------v--------+
|  webui-spoke  |                    |  webui-spoke |        ...         |  webui-spoke  |
| client-sim     |                    | client-sim    |                    | client-sim     |
| poll inbox     |                    | send telemetry|                    | run commands    |
+-------+--------+                    +------+--------+                    +-------+--------+
        |                                      |                                     |
   up to 24 clients                       up to 24 clients                      up to 24 clients
        |                                      |                                     |
   +----v----+                            +----v----+                           +----v----+
   | Clients |                            | Clients |                           | Clients |
   +---------+                            +---------+                           +---------+
```

**Target scale:** up to **420 spokes** and roughly **10,000 simulation clients** across multiple tenants.

## Frontend dependency (`cs-webui`)

Hub no longer owns a separate frontend codebase. Instead, it depends on `cs-webui` for the shared browser assets used by both hub and spoke deployments.

- `app/main.py` serves `static/index.html` and replaces `{{WEBUI_MODE}}` with `hub` before returning the page.
- `static/index.html`, `static/app.js`, and `static/style.css` are sourced from `cs-webui`.
- Each hub deploy stamps `VERSION` with the git SHA and serves `app.js` / `style.css` as `...?v=<sha>` so browsers do not keep stale assets.
- The footer version pills are populated from `frontend/SEMVER` (`CS-WebUI v…`) and `CLIENT_SIM_VERSION` (`GitHub Repo v…`).
- Branch alignment matters: `main` is the production branch across `webui-hub`, `client-sim`, and `cs-webui`.
- For automated image builds, `.github/workflows/build-push.yml` clones `cs-webui` from the matching branch before the Docker build begins.


## Tenant config editors

Hub exposes two tenant config editors that stay aligned with the shared frontend in `cs-webui`.

- **`simulation.conf`** uses one unified collapsible-card layout for `[simulation]`, `[server]`, `[address]`, and `s0`–`s9`. Text/select fields render in a responsive grid, boolean flags render inline, and slot sections always show the full standard key set.
- **`user-overrides.conf`** uses per-user cards with an **Add User** modal, delete actions, hostname search, and a **↗ Override** shortcut from the Simulation Clients table to prefill from the client's current bucket.
- `GET /api/{tenant_id}/config/user-overrides-conf` now mirrors the dual-mode behavior of `simulation.conf`: Hub reads from GitHub when a repo token is configured, but a saved hub override takes precedence until it is cleared.

## Backup & Azure Storage

Hub v1.0 includes an Azure-backed VM backup path for spoke Proxmox hosts. The storage account key is **never** stored in plaintext: a superadmin sends it to `POST /api/backup/config/key`, where Hub encrypts it with `ENCRYPTION_KEY` before saving `azure_key_enc` in the JSON store. The default backup target is the private Azure Blob container `csvmstorage/vms`.

Key pieces of the flow:

- `GET /api/backup/installer/sas-token` returns a **2-hour read-only container SAS URL** after the caller supplies `X-Installer-Key` matching `INSTALLER_API_KEY`.
- Hub-triggered Proxmox backup jobs use the stored Azure account key to enqueue spoke backup work and upload VM snapshots into Azure Blob Storage.
- The Proxmox installer and reseed flows use the SAS URL so they can download private blobs without ever receiving the raw storage account key.
- Hub mode in `cs-webui` exposes VM backup, reseed, and recovery controls through the VM Server workflows.

## Quick Start (Docker)

### 1) Generate keys

```bash
export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export ADMIN_PASSWORD='change-this-now'
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export INSTALLER_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

### 2) Copy the example environment file

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```dotenv
WEBUI_SECRET_KEY=...
SECRET_KEY=...
ADMIN_PASSWORD=...
ENCRYPTION_KEY=...
INSTALLER_API_KEY=...
```

### 3) Start the stack

```bash
docker compose up -d --build
```

Then open:

```text
https://localhost:8443
```

> Hub generates a self-signed certificate if `TLS_CERT_PATH` and `TLS_KEY_PATH` are not supplied.

## Deployment

### Docker

#### Prerequisites

- Docker Engine with Compose support
- A persistent Docker volume or bind mount for `/data`
- Access to the `cs-webui` repository at the `main` branch
- Secure values for `WEBUI_SECRET_KEY`, `SECRET_KEY`, `ADMIN_PASSWORD`, `ENCRYPTION_KEY`, and `INSTALLER_API_KEY`

#### Required environment variables

```bash
export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export ADMIN_PASSWORD='change-this-now'
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export INSTALLER_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

#### Steps

1. Clone the repository.
2. Copy `.env.example` to `.env`.
3. Set strong production secrets.
4. Optionally mount your own PEM certificate and key.
5. Start the service.

```bash
git clone https://github.com/solutions-hpe/webui-hub.git
cd webui-hub
cp .env.example .env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up -d --build
```

#### What `docker-compose.yml` does

- Builds the local Dockerfile
- Exposes `${HUB_PORT:-8443}` on container port `8443`
- Mounts persistent storage at `/data`
- Runs as a non-root `hub` user
- Performs HTTPS health checks against `/api/health`

#### Optional bring-your-own certificate

Uncomment or add a bind mount like this:

```yaml
volumes:
  - ./certs/cert.pem:/data/tls/cert.pem:ro
  - ./certs/key.pem:/data/tls/key.pem:ro
```

Or set explicit paths:

```dotenv
TLS_CERT_PATH=/data/tls/cert.pem
TLS_KEY_PATH=/data/tls/key.pem
```

### Azure Container Instance (ACI)

For v1.0 production deployments, **`deploy-azure-quickstart.sh` is the recommended path**. It generates all five required secrets (`WEBUI_SECRET_KEY`, `SECRET_KEY`, `ADMIN_PASSWORD`, `ENCRYPTION_KEY`, `INSTALLER_API_KEY`), saves them to `.deploy-secrets.env` (gitignored), and then calls `deploy-azure.sh`.

#### Recommended quick deployment path

```bash
bash deploy-azure-quickstart.sh
```

Use `deploy-azure.sh` directly when you want to supply secrets and Azure naming inputs yourself. Many local deployments also use `~/Documents/deploy-hub-azure.sh` as a wrapper around the same rollout flow.

#### Prerequisites

- Azure CLI (`az`) installed and logged in
- Permission to create resource groups, ACR, storage, and ACI resources
- Exported secrets before running the script

#### Required environment variables

```bash
export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export ADMIN_PASSWORD='change-this-now'
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export INSTALLER_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

#### Optional deployment variables

```bash
export RG=hub-rg
export LOCATION=eastus
export ACR_NAME=hubregistry12345
export CONTAINER_NAME=hub
export STORAGE_ACCOUNT=hubstorage12345
export FILE_SHARE=hubdata
export IMAGE_TAG=latest
export HUB_PORT=8443
export DNS_LABEL=hub-example
```

#### Deploy

```bash
bash deploy-azure.sh
```

The script will:

- Create the resource group
- Create Azure Container Registry
- Build and push the Hub image
- Create a storage account and Azure File Share
- Deploy the container with `/data` mounted from Azure Files
- Inject `WEBUI_SECRET_KEY`, `SECRET_KEY`, `ADMIN_PASSWORD`, `ENCRYPTION_KEY`, and `INSTALLER_API_KEY` as secure environment variables

Resulting endpoint format:

```text
https://<dns-label>.<region>.azurecontainer.io:8443
```

### GitHub Actions image build

`.github/workflows/build-push.yml` runs on pushes to `main`. The workflow:

1. checks out `webui-hub`
2. clones `cs-webui` from the matching branch, falling back to `main` if that branch does not exist
3. copies `static/` plus `templates/index.html` from `cs-webui`, writing the shared HTML to `static/index.html` in the Docker build context
4. builds and pushes `ghcr.io/solutions-hpe/webui-hub:latest` plus SHA-based tags


### BYOD Linux

`install.sh` installs Hub directly onto a Linux host and creates a hardened `systemd` service.

#### Prerequisites

- Linux host with Python **3.9+**
- Root or sudo access
- Internet access to clone the repository and install Python packages

#### Supported install-time variables

```bash
export INSTALL_DIR=/opt/hub
export DATA_DIR=/var/lib/hub
export HUB_PORT=8443
export ADMIN_PASSWORD='change-this-now'
export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
```

#### Install

```bash
sudo bash install.sh
```

The installer will:

- Create a dedicated `hub` system user
- Clone or update the repository in `INSTALL_DIR`
- Build a Python virtual environment
- Install `requirements.txt`
- Initialize the data directory and TLS location
- Write `.env`
- Install and start a `systemd` unit named `hub`

Useful operational commands:

```bash
systemctl status hub
journalctl -u hub -f
```

## Configuration

Runtime configuration comes from environment variables or `.env`.

| Variable | Default | Required | Description |
|---|---:|---|---|
| `HUB_PORT` | `8443` | No | HTTPS listener port used by Docker Compose, ACI, and BYOD start scripts. |
| `WEBUI_SECRET_KEY` | empty | **Yes** in production | Fernet master key for core Hub secrets at rest. If omitted, Hub generates an ephemeral key and encrypted values will not survive restart. |
| `SECRET_KEY` | `change-me-in-production` | **Yes** in production | JWT signing key for login sessions. |
| `ENCRYPTION_KEY` | empty | **Yes** for backup/reseed | Fernet key used by `app/crypto.py` to encrypt the Azure storage account key at rest before it is written to the JSON store. |
| `INSTALLER_API_KEY` | empty | **Yes** for hub-assisted installs/backups | Shared secret required by `GET /api/backup/installer/sas-token`. Installers send it as `X-Installer-Key` to obtain a short-lived read-only SAS URL for Azure blob downloads. |
| `ALGORITHM` | `HS256` | No | JWT signing algorithm. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | No | JWT access token lifetime in minutes. |
| `FIRST_ADMIN_USERNAME` | `admin` | No | Username used for the bootstrap superadmin account. |
| `ADMIN_PASSWORD` | `changeme` | Yes for first boot | Preferred bootstrap password variable for the first superadmin. |
| `FIRST_ADMIN_PASSWORD` | `changeme` | No | Legacy alias accepted in place of `ADMIN_PASSWORD`. |
| `DATA_DIR` | `./data` locally, `/data` in container | Yes | Root directory for JSON data, pending registrations, queue files, audit logs, and generated TLS material. |
| `TLS_CERT_PATH` | empty | No | Optional absolute or container-local path to a PEM certificate. If unset, a self-signed certificate is generated under `DATA_DIR/tls/`. |
| `TLS_KEY_PATH` | empty | No | Optional absolute or container-local path to a PEM private key matching `TLS_CERT_PATH`. |
| `OIDC_ENABLED` | `false` | No | Enables OIDC provider visibility. Authentication flow is stubbed, not yet implemented. |
| `OIDC_DISCOVERY_URL` | empty | No | OIDC discovery endpoint for future SSO support. |
| `OIDC_CLIENT_ID` | empty | No | OIDC client ID. |
| `OIDC_CLIENT_SECRET` | empty | No | OIDC client secret. |
| `LDAP_ENABLED` | `false` | No | Enables LDAP/AD provider visibility. Authentication flow is stubbed, not yet implemented. |
| `LDAP_URL` | empty | No | LDAP or LDAPS server URL. |
| `LDAP_BIND_DN` | empty | No | Service account DN used for LDAP searches. |
| `LDAP_BIND_PASSWORD` | empty | No | Service account password for LDAP searches. |
| `LDAP_USER_SEARCH_BASE` | empty | No | Search base for locating users in LDAP/AD. |
| `RADIUS_ENABLED` | `false` | No | Enables RADIUS provider visibility. Authentication flow is stubbed, not yet implemented. |
| `RADIUS_HOST` | empty | No | RADIUS server hostname or IP. |
| `RADIUS_PORT` | `1812` | No | RADIUS server UDP port. |
| `RADIUS_SECRET` | empty | No | Shared secret for future RADIUS support. |

## First-Time Setup

After the service is running:

1. Browse to `https://<hub-host>:8443`.
2. Log in with the bootstrap account:
   - Username: `admin` (or `FIRST_ADMIN_USERNAME`)
   - Password: `ADMIN_PASSWORD`
3. In the superadmin area, create a tenant:
   - Use the Aruba Central CID if the tenant maps to an Aruba MSP customer
   - Use an auto-generated UUID-backed tenant for manual or lab-only tenants
4. Approve pending spokes and assign each one to the correct tenant.
5. Configure tenant settings:
   - Aruba Central credentials under tenant settings or the superadmin Aruba workflow
   - Notification settings for Teams and/or SMTP if desired
   - Default processing mode for the tenant
   - **Setup → Tenant Setup → Use All Available Dongles** if the tenant should overflow to the other certified dongle type when the preferred type runs out
   - **Setup → Onboarding** if you want to generate a PSK for spoke auto-approval
6. Create additional tenant admins and operators as needed.

## Spoke Registration

The spoke registration flow is intentionally two-stage so a superadmin can verify identity and tenant assignment.

### Step 1 — spoke registers itself

The spoke POSTs to:

```text
POST /api/spokes/register
```

Example payload:

```json
{
  "hostname": "spoke-001",
  "label": "Lab Spoke 001",
  "config": {
    "vm_silent_timeout": 24,
    "reclone_schedule_enabled": "off"
  }
}
```

Response:

- `201 Created`
- Status is `pending`
- Hub stores the registration in `/data/pending/<spoke_id>.json`

### Optional fast path — onboarding PSK auto-approval

Tenant admins can generate a per-tenant onboarding PSK in **Setup → Onboarding**. When a spoke registers with `tenant_id_hint`, `spoke_name`, and a matching `onboarding_psk`, Hub skips the pending queue and immediately returns approved credentials.

Current spoke install command:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/solutions-hpe/client-sim/main/install-lxc.sh) \
  --hub-url https://hub.example.com:8443 \
  --hub-tenant <tenant-id> \
  --hub-psk <psk>
```

### Step 2 — superadmin approves and assigns a tenant

The superadmin reviews:

```text
GET /api/superadmin/pending-spokes
```

Then approves:

```text
POST /api/superadmin/pending-spokes/{spoke_id}/approve
```

With a body like:

```json
{
  "tenant_id": "1234567",
  "label": "Spoke 001"
}
```

Approval performs four actions:

1. Creates the spoke record under the tenant
2. Generates a new API key and stores it encrypted at rest
3. Deletes the pending registration file
4. Queues a `config_update` command containing:
   - `relay_spoke_id`
   - `relay_api_key`
   - `relay_tenant_id`
   - `relay_server_url`

### Step 3 — spoke polls inbox and receives relay credentials

The spoke polls its tenant-scoped inbox using the new route pattern:

```text
GET /api/{tenant_id}/spokes/{spoke_id}/inbox
```

Hub returns queued commands, including the one-time registration payload with the API key. The spoke must persist those relay settings locally for all future telemetry, inbox, and ack calls.

## API Reference

### Auth (JWT)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/login` | None | Exchange username/password for JWT bearer token |
| `GET` | `/api/auth/me` | JWT | Return current user identity, superadmin flag, and tenant roles |
| `GET` | `/api/auth/providers` | None | List configured auth providers |
| `POST` | `/api/auth/change-password` | JWT | Change local password |

### Spoke relay (no JWT, uses `X-API-Key`)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/spokes/register` | None | Register a spoke and create a pending spoke record |
| `POST` | `/api/{tenant_id}/spokes/{spoke_id}/telemetry` | `X-API-Key` | Push telemetry and heartbeat data |
| `GET` | `/api/{tenant_id}/spokes/{spoke_id}/inbox` | `X-API-Key` | Pull queued commands and config updates |
| `POST` | `/api/{tenant_id}/spokes/{spoke_id}/ack` | `X-API-Key` | Acknowledge command execution and optionally report task results |

Hub heartbeat monitoring treats a spoke as offline after 300 seconds without telemetry.

### Tenant-scoped management (JWT)

| Category | Method | Path | Role |
|---|---|---|---|
| Spokes | `GET` | `/api/{tenant_id}/spokes` | superadmin, admin, operator |
| Spoke detail | `GET` | `/api/{tenant_id}/spokes/{spoke_id}` | superadmin, admin, operator |
| Spoke revoke | `POST` | `/api/{tenant_id}/spokes/{spoke_id}/revoke` | superadmin, admin |
| Spoke delete | `DELETE` | `/api/{tenant_id}/spokes/{spoke_id}` | superadmin, admin |
| Spoke config | `PATCH` | `/api/{tenant_id}/spokes/{spoke_id}/config` | superadmin, admin |
| Spoke label | `PATCH` | `/api/{tenant_id}/spokes/{spoke_id}/label` | superadmin, admin |
| Commands | `POST` | `/api/commands` | superadmin, admin, operator with tenant access |
| Commands list | `GET` | `/api/{tenant_id}/commands` | superadmin, admin, operator |
| Repo sync | `POST` | `/api/{tenant_id}/spokes/{spoke_id}/repo-sync` | superadmin, admin, operator |
| Onboarding PSK status | `GET` | `/api/tenant/{tenant_id}/onboarding-psk` | superadmin, admin |
| Onboarding PSK generate | `POST` | `/api/tenant/{tenant_id}/onboarding-psk` | superadmin, admin |
| Onboarding PSK revoke | `DELETE` | `/api/tenant/{tenant_id}/onboarding-psk` | superadmin, admin |
| Settings | `GET` | `/api/{tenant_id}/settings` | superadmin, admin |
| User overrides config | `GET` | `/api/{tenant_id}/config/user-overrides-conf` | superadmin, admin |
| User overrides config | `PUT` | `/api/{tenant_id}/config/user-overrides-conf` | superadmin, admin |
| Aruba settings | `POST` | `/api/{tenant_id}/settings/aruba` | superadmin, admin |
| Notification settings | `POST` | `/api/{tenant_id}/settings/notifications` | superadmin, admin |
| Processing mode | `GET` | `/api/{tenant_id}/settings/processing-mode` | superadmin, admin |
| Processing mode | `POST` | `/api/{tenant_id}/settings/processing-mode` | superadmin, admin |
| Per-spoke processing mode | `PATCH` | `/api/{tenant_id}/spokes/{spoke_id}/processing-mode` | superadmin, admin |
| Processing summary | `GET` | `/api/{tenant_id}/processing-summary` | superadmin, admin, operator |
| Audit | `GET` | `/api/{tenant_id}/spokes/{spoke_id}/audit` | superadmin, admin, operator |
| T3 devices | `GET` | `/api/{tenant_id}/spokes/{spoke_id}/t3/devices` | superadmin, admin, operator |
| T3 mac-profile | `GET` | `/api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile` | superadmin, admin, operator |
| T3 mac-profile save | `PUT` | `/api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile` | superadmin, admin |
| T3 mac-profile delete | `DELETE` | `/api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile` | superadmin, admin |
| T3 push mac | `POST` | `/api/{tenant_id}/spokes/{spoke_id}/t3/push-mac` | superadmin, admin |
| T3 push oui-pool | `POST` | `/api/{tenant_id}/spokes/{spoke_id}/t3/push-oui-pool` | superadmin, admin |
| OUI pool | `GET` | `/api/oui-pool` | all |
| OUI pool replace | `PUT` | `/api/oui-pool` | superadmin |
| OUI pool import | `POST` | `/api/oui-pool/import-csv` | superadmin |
| OUI pool export | `GET` | `/api/oui-pool/export-csv` | all |

### Superadmin (JWT + superadmin role)

| Category | Method | Path | Purpose |
|---|---|---|---|
| Tenants | `POST` | `/api/superadmin/tenants` | Create tenant |
| Tenants | `GET` | `/api/superadmin/tenants` | List tenants |
| Tenant detail | `GET` | `/api/superadmin/tenants/{tenant_id}` | Get tenant metadata |
| Tenant delete | `DELETE` | `/api/superadmin/tenants/{tenant_id}` | Remove tenant and its data |
| Aruba config | `POST` | `/api/superadmin/tenants/{tenant_id}/aruba` | Save Aruba config |
| Aruba discovery | `POST` | `/api/superadmin/aruba/discover-tenants` | Discover Aruba MSP customer tenants |
| Notifications | `POST` | `/api/superadmin/tenants/{tenant_id}/notification-config` | Save notification config |
| Pending spokes | `GET` | `/api/superadmin/pending-spokes` | Review waiting spoke registrations |
| Approve spoke | `POST` | `/api/superadmin/pending-spokes/{spoke_id}/approve` | Approve + assign tenant |
| Delete pending spoke | `DELETE` | `/api/superadmin/pending-spokes/{spoke_id}` | Reject registration |
| Users | `GET` | `/api/superadmin/users` | List all users |
| Users | `POST` | `/api/superadmin/users` | Create user |
| Users | `DELETE` | `/api/superadmin/users/{user_id}` | Delete user |
| Assign tenant role | `POST` | `/api/superadmin/users/{user_id}/roles` | Assign admin/operator to tenant |
| Remove tenant role | `DELETE` | `/api/superadmin/users/{user_id}/roles/{tenant_id}` | Remove tenant role |
| GKill state | `GET` | `/api/superadmin/gkill-state` | View last fetched global kill switch value |
| Auth providers | `GET` | `/api/superadmin/auth-providers` | See provider enablement and implementation status |

## Processing Model

Hub supports two execution patterns:

- **Centralized** — Hub performs the work itself
- **Distributed** — Hub pushes configuration or commands to the spoke and the spoke performs the work locally

### Resolution model

Each tenant has a default `ProcessingMode` and each spoke can override it.

Supported feature toggles:

- `aruba_polling`
- `teams_webhook`
- `email`
- `heartbeat`
- `gkill`
- `schedules`
- `repo_sync`

If a feature override is not set, Hub falls back to the spoke's `global_mode`.

### How it works in practice

- **Centralized Aruba polling**: Hub polls Aruba Central and broadcasts findings to the UI.
- **Distributed Aruba polling**: Hub sends Aruba credentials/config to the spoke using `aruba_config_update`.
- **Centralized notifications**: Hub sends Teams or SMTP notifications itself.
- **Distributed notifications**: Hub queues `notification_push` for the spoke.
- **Distributed gkill**: Hub queues `gkill_update` after the global kill switch changes.
- **Distributed schedules**: Hub queues `reclone_schedule` when a cron-style spoke schedule matches.

### Config push path

1. Admin updates tenant or spoke config in Hub.
2. Hub stores the new JSON payload under `/data`.
3. Before saving or pushing a spoke config payload, Hub strips spoke-local auth fields such as `admin_password`, `auth_provider`, and all LDAP, RADIUS, and TACACS settings.
4. Hub queues a command in `/data/{tenant_id}/queue/{spoke_id}.json`.
5. The spoke polls `/inbox`, receives the command, applies it, and POSTs `/ack`.
6. Hub records the result in the queue and optionally appends an audit entry.

## Multi-Tenancy

Tenant IDs are first-class routing keys throughout the platform.

### Tenant lifecycle

1. A superadmin creates or imports a tenant.
2. The tenant receives an ID:
   - **Aruba Central CID** when mapped to an MSP customer
   - **UUID** when created manually for standalone deployments
3. Users are granted tenant-scoped roles.
4. Spokes are approved into exactly one tenant.
5. All spoke queue, audit, config, and access control decisions remain tenant-scoped.

### Roles

| Role | Scope | Capabilities |
|---|---|---|
| `superadmin` | All tenants | Full platform administration, tenant creation, pending spoke approval, user/role assignment |
| `admin` | One tenant | Configure tenant settings, manage spokes, view audit, change processing mode |
| `viewer` | One tenant | Read-only access to tenant-scoped operational data |

> **Note:** `operator` is accepted as an alias when assigning roles and is normalized to `viewer` on write. Internally the stored value is always `admin` or `viewer`.

## TLS

Hub serves HTTPS directly from uvicorn on port `8443`.

### Default behavior

- On startup, `start.sh` checks `TLS_CERT_PATH` and `TLS_KEY_PATH`
- If either file is missing, Hub generates a self-signed certificate under `DATA_DIR/tls/`
- Docker and BYOD deployments both follow this model

### Bring your own certificate

Provide PEM files and either:

- Mount them into the container and set `TLS_CERT_PATH` / `TLS_KEY_PATH`, or
- Place them on the BYOD host and point the environment variables at those paths

If you replace the self-signed files at `DATA_DIR/tls/cert.pem` and `DATA_DIR/tls/key.pem`, the next service restart will use them.

## Auth Providers

### Current

- **Password / JWT** — implemented and active
  - Passwords are stored as bcrypt hashes
  - `POST /api/auth/login` returns a bearer token
- **LDAP / Active Directory** — implemented as a hub-side provider
- **RADIUS** — implemented as a hub-side provider
- **TACACS+** — implemented as a hub-side provider

These provider settings stay on the hub. They are never pushed to spokes as part of config sync.

### Stubbed and ready for implementation

- **OIDC / OAuth2 SSO**

The provider registry and config flags already exist. OIDC is still exposed as future work, while spoke auth remains local to each spoke.

## Aruba Central Integration

Hub integrates with both the Classic Central API and the HPE GreenLake (New Central / CNX) API. The integration mode is set per-tenant in the Aruba config.

### Classic Central API

Uses a standard Aruba Central API gateway with an OAuth access/refresh token pair. Endpoints follow the `/monitoring/v2/...` path convention.

### New Central (GreenLake) API

Uses the HPE GreenLake authorization service with `client_credentials` grant. Tokens are short-lived (~15 minutes) and refreshed automatically.

**Authentication:**
```
POST https://global.api.greenlake.hpe.com/authorization/v2/oauth2/{workspace_id}/token
grant_type=client_credentials
```

**Browse endpoints used:**

| Endpoint | Data |
|---|---|
| `GET /network-notifications/v1/alerts` | Active alerts: severity, category, site, device type, summary |
| `GET /network-notifications/v1/insights` | AI insights: description, impacted devices + clients per site |
| `GET /network-monitoring/v1/devices` | Device inventory: APs, switches, gateways — status, model, IP, firmware |
| `GET /network-monitoring/v1/clients` | Connected clients: total, wired, wireless counts per site |
| `GET /network-monitoring/v1alpha1/sites-health` | Site health scores used by the monitored check evaluation loop |

### Central API browse tab

The **Setup → Central API** browse tab in the Hub UI provides five subtabs fed by the live endpoints above:

- **Sites** — health score, wireless client count, 7-day baseline alarm state, wrapped spoke list, and Monitor button per site
- **Alerts** — filterable by category (All / Clients / LAN / WLAN / WAN / System / Security), severity badge, device type
- **Insights** — AI-generated insight with description, impacted device + client count
- **Clients** — per-site totals with wired/wireless breakdown
- **Devices** — full device list with name, serial, type, model, status, IP, firmware

**Monitor button state:** Each row shows a **Monitor** button to add the item to the Monitored Items list. If the item is already being monitored, the button is replaced with a **✓ Monitored** badge — visible without re-adding the same item.

**Client-count alarm behavior:** The Sites page now compares each site's current hourly wireless-client average against a persisted 7-day rolling baseline. A site enters **DEGRADED** when the current value falls more than 25% below baseline, and the alarm stays active until the count recovers. During the first day of operation, Hub falls back to the 1-hour average until enough 7-day history exists.

### Centralized vs distributed mode

| Mode | How it works |
|---|---|
| **Centralized** | Hub calls the browse endpoints directly using its own Aruba credentials. Covers all sites in the workspace. |
| **Distributed** | Each spoke fetches browse data filtered to its assigned site(s) only, then includes the results in its telemetry payload. Hub aggregates data from all spokes into a single multi-site view. |

In distributed mode the spoke uses OData filters: `$filter=siteName eq 'DFW'`. The DFW spoke fetches only DFW data, the MIA spoke fetches only MIA data, and so on. This avoids rate-limiting from hub-side fan-out and keeps each spoke self-contained.

### Monitored Items

The Monitored Items list (`/api/{tenant_id}/aggregate/monitored-items`) is a tenant-level registry of alert types, insights, sites, or devices the platform actively watches. Each item drives check evaluation in the spoke poll loop and surfaces in the Hub dashboard alert tiles.

## Data Layout

All persistent state lives under `DATA_DIR`.

```text
/data/
├── users.json
├── tenants.json
├── oui_pool.json
├── pending/
│   └── <pending-spoke-id>.json
├── tls/
│   ├── cert.pem
│   └── key.pem
└── <tenant_id>/
    ├── spokes.json
    ├── mac_profiles.json
    ├── queue/
    │   └── <spoke_id>.json
    └── audit/
        └── <spoke_id>.json
```

### What each file stores

| Path | Contents |
|---|---|
| `/data/users.json` | All Hub user accounts, bcrypt password hashes, superadmin flag, and tenant role assignments |
| `/data/tenants.json` | Tenant metadata plus encrypted Aruba and notification settings |
| `/data/oui_pool.json` | Global OUI reference pool used by the T3 MAC profile builder |
| `/data/pending/*.json` | Spoke registrations waiting for superadmin approval |
| `/data/{tenant_id}/spokes.json` | Approved spokes, labels, runtime config, processing mode, telemetry, last seen timestamps |
| `/data/{tenant_id}/mac_profiles.json` | T3 MAC profiles keyed by spoke ID |
| `/data/{tenant_id}/queue/*.json` | Pending, delivered, and executed commands with 24-hour TTL |
| `/data/{tenant_id}/audit/*.json` | Rolling 7-day task and action history per spoke |
| `/data/tls/*` | Generated self-signed cert and key unless overridden |

## Security Notes

- **Protect `WEBUI_SECRET_KEY`** — it encrypts secrets at rest. If you lose it, stored secrets cannot be decrypted.
- **Change `SECRET_KEY`** — never run production with the default JWT signing key.
- **Rotate `ADMIN_PASSWORD` immediately** after first login.
- **Passwords use bcrypt** through Passlib.
- **Secrets at rest use Fernet** for API keys, Aruba credentials, SMTP credentials, and webhook URLs.
- **Container runs as non-root** via the dedicated `hub` user.
- **Self-signed TLS is convenient, not trust-managed** — use your own cert for enterprise deployments.
- **Tenant scoping is enforced in routes** for both data access and command execution.

## T3 Wireless Device Management

T3 devices are virtual wireless interfaces running on a Raspberry Pi (or equivalent Linux host). Each spoke can manage up to **25 virtual `vwlan` interfaces**, each programmed with a vendor-specific MAC address derived from an OUI pool. Hub provides fleet-wide MAC profile management and OUI pool administration.

### Architecture

```text
Hub UI  ──── PUT mac-profile ────► Hub stores profile + queues t3_mac_update command
                                            │
                                    spoke polls /inbox
                                            │
                               spoke writes mac_config.json locally
                                            │
                          T3 device polls GET /api/scripts/t3/mac_config.json
                                            │
                       wireless.sh detects hash change → gen_macs.sh regenerates interfaces
```

### T3 API endpoints (tenant-scoped, JWT)

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/{tenant_id}/spokes/{spoke_id}/t3/devices` | operator | T3 devices visible in spoke telemetry |
| `GET` | `/api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile` | operator | Stored MAC profile for a spoke |
| `PUT` | `/api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile` | admin | Save profile and queue push command |
| `DELETE` | `/api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile` | admin | Remove stored profile |
| `POST` | `/api/{tenant_id}/spokes/{spoke_id}/t3/push-mac` | admin | Re-queue push of existing profile |
| `POST` | `/api/{tenant_id}/spokes/{spoke_id}/t3/push-oui-pool` | admin | Push global OUI pool to a spoke |

### OUI pool endpoints (global, JWT)

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/oui-pool` | all | Return all OUI reference entries |
| `PUT` | `/api/oui-pool` | superadmin | Replace the OUI pool |
| `POST` | `/api/oui-pool/import-csv` | superadmin | Import `vendor,oui,device_type` CSV |
| `GET` | `/api/oui-pool/export-csv` | all | Download pool as CSV |

### MAC profile format

A MAC profile is a list of entries passed to `PUT /api/{tenant_id}/spokes/{spoke_id}/t3/mac-profile`:

```json
{
  "entries": [
    { "vendor": "Apple",     "oui": "3c:15:c2", "count": 5 },
    { "vendor": "Samsung",   "oui": "a4:50:46", "count": 4 },
    { "vendor": "Microsoft", "oui": "60:45:bd", "count": 3 }
  ]
}
```

- `oui` — first three octets of the MAC address in lowercase colon notation
- `count` — number of `vwlan` interfaces to configure with this vendor's OUI
- Total `count` across all entries must be ≤ 25

Saving a profile automatically queues a `t3_mac_update` command. The spoke applies the profile by writing `mac_config.json` locally; T3 devices then pull it on the next update cycle.

### Hub-queued T3 command types

| Command | Payload | Effect on spoke |
|---|---|---|
| `t3_mac_update` | `{mac_config: [{vendor, oui, count}, ...]}` | Writes `t3_mac_config.json` to spoke disk |
| `t3_oui_pool_update` | `{oui_pool: [{vendor, oui, device_type}, ...]}` | Writes `t3_oui_pool.json` to spoke disk |

### T3 telemetry

Spokes include a `t3` section in every telemetry push:

```json
{
  "t3": {
    "device_count": 5,
    "devices": [{ "hostname": "...", "hw_type": "t3", ... }],
    "mac_config_present": true,
    "mac_config_hash": "abc123def456...",
    "oui_pool_present": true
  }
}
```

The `mac_config_hash` is an MD5 of the on-disk `mac_config.json`. Operators can compare this against the profile last pushed from Hub to verify the T3 devices have picked up the latest configuration.

### Data layout for T3

```text
/data/
├── oui_pool.json                          ← global OUI reference pool
└── <tenant_id>/
    └── mac_profiles.json                  ← dict keyed by spoke_id
```

---

## Spoke Integration Status

The `client-sim/webui-spoke/server.py` integration work for Hub is complete. The five spoke behaviors below have been implemented and are kept here as a reference.

1. **Implemented: use the new registration flow**
   - POST `hostname`, `label`, and `config` to `/api/spokes/register`.
2. **Implemented: persist relay credentials from the approval command**
   - Read `relay_tenant_id`, `relay_spoke_id`, `relay_api_key`, and `relay_server_url` from the first `config_update` message.
3. **Implemented: move all relay traffic to tenant-scoped routes**
   - Use `/api/{tenant_id}/spokes/{spoke_id}/telemetry`, `/inbox`, and `/ack` with `X-API-Key`.
4. **Implemented: handle Hub-driven command types**
   - Support `config_update`, `aruba_config_update`, `notification_push`, `gkill_update`, `reclone_schedule`, `repo_sync`, `auto_recovery`, `t3_mac_update`, and `t3_oui_pool_update` as inbox items.
5. **Implemented: send richer ACK payloads back to Hub**
   - Include `command_id`, `status`, and `result` fields such as `success`, `task_type`, `detail`, `output`, and `timestamp` so Hub can populate audit history.

## Health Check

Hub exposes:

```text
GET /api/health
```

Expected response:

```json
{"status": "ok"}
```

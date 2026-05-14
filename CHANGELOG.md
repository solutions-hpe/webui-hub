# Changelog

## [1.0.1] — 2026-05-14

### Added
- **T3 wireless device management** — new `/api/routers/t3.py` router supporting full MAC profile lifecycle and OUI pool administration.
- MAC profile builder: `PUT /{tenant_id}/spokes/{spoke_id}/t3/mac-profile` stores a list of `{vendor, oui, count}` entries (≤ 25 total interfaces) and automatically queues a `t3_mac_update` command for the target spoke.
- OUI pool management: `GET/PUT /api/oui-pool`, `POST /api/oui-pool/import-csv` (superadmin), `GET /api/oui-pool/export-csv`.
- T3 device visibility: `GET /{tenant_id}/spokes/{spoke_id}/t3/devices` surfaces T3 client telemetry from spoke relay payloads.
- Re-push endpoints: `POST /t3/push-mac` and `POST /t3/push-oui-pool` re-queue existing profiles to a spoke without requiring a full profile edit.
- `MacProfileEntry`, `MacProfile`, and `OuiPoolEntry` Pydantic models in `data_models.py`.
- Store functions: `get/save/delete_mac_profile`, `list_mac_profiles`, `get/save_oui_pool_raw` in `store.py`.
- T3 data files: `/data/{tenant_id}/mac_profiles.json` (per-spoke profiles) and `/data/oui_pool.json` (global reference pool).

### Changed
- `app/main.py` now registers the T3 router (`prefix="/api"`, tag `"t3"`) alongside the backups router.

## [1.0.0] — 2026-05-13

Initial stable production release of the Hub platform on `main`. The `2.x` entries below capture the development history that led to this v1.0 cut.

### Added
- Multi-tenant FastAPI hub with JSON file storage under `/data/`, HTTPS on port `8443`, and self-signed certificate generation at startup
- Role-based auth with **superadmin**, **admin**, and **operator** roles
- Spoke registration, approval, tenant-scoped command queueing, and WebSocket relay between hub and spokes
- Aruba Central MSP integration plus per-tenant/per-spoke processing modes for centralized or distributed execution
- Teams/email notifications, ACME / Let's Encrypt renewal hooks, 7-day spoke audit history, 24-hour command queue TTL, GKill polling, heartbeat monitoring, and reclone schedule checks
- Azure blob backup system with `app/crypto.py`, `app/routers/backups.py`, encrypted Azure key storage, installer SAS generation, Proxmox VM backup triggering, and `BackupConfig` defaults for `csvmstorage` / `vms`
- `deploy-azure-quickstart.sh`, which generates `WEBUI_SECRET_KEY`, `SECRET_KEY`, `ADMIN_PASSWORD`, `ENCRYPTION_KEY`, and `INSTALLER_API_KEY`, then saves them to `.deploy-secrets.env`
- Aggregate fleet reclone retries with exponential backoff, the Hub Central tab for cross-spoke simulation/client aggregation, VM backup and reseed controls in the hub UI, and the superadmin reseed panel exposed to all hub users

## [2.1.0] — 2026-05-10

### Changed
- Unified frontend ownership moved to `cs-webui`; Hub now serves the shared frontend from that repo instead of maintaining a separate in-repo UI.
- Runtime page rendering now injects `WEBUI_MODE=hub` into `index.html` so the shared frontend enables hub-specific navigation and workflows.
- GitHub Actions now clones `cs-webui` from the matching branch during image builds before copying frontend assets into the Docker context.
- Documentation and platform terminology now use **spoke** naming consistently throughout the Hub architecture.

## [2.0.0] — 2025-05-09

### Breaking Changes
- **No database** — PostgreSQL/SQLite replaced with JSON file store. No migration path from v1.x.
- **Port changed** — now runs on 8443 (HTTPS) instead of 8000 (HTTP).
- **Renamed** — repo renamed from `webui` to `webui-hub`.
- **API routes changed** — spoke relay endpoints are now tenant-scoped: `/api/{tenant_id}/spokes/...`

### Added
- Multi-tenant architecture with superadmin, admin, and operator roles
- Tenant IDs sourced from Aruba Central CID or manually created
- Centralized/distributed processing mode toggle per spoke and per feature
- Task result reporting from spokes back to hub via extended `/ack` endpoint
- 7-day rolling audit log per spoke (JSON files)
- 24-hour command queue TTL with auto-purge
- Fernet encryption for all secrets at rest (API keys, Aruba tokens, SMTP credentials, webhooks)
- Self-signed TLS certificate auto-generated at startup
- Azure Container Instance deployment script (`deploy-azure.sh`) with Azure File Share for persistence
- BYOD Linux install script (`install.sh`) with systemd service and security hardening
- Multi-stage Docker build, non-root user
- OIDC / LDAP / AD / RADIUS auth provider stubs (inactive, ready for implementation)
- GKill switch poller (GitHub → all spokes)
- Per-spoke heartbeat monitor with online/offline WebSocket broadcasts
- Auto-recovery check for offline spokes
- Per-spoke schedule check (reclone cron)
- Aruba Central MSP tenant discovery endpoint
- Full UI overhaul: tenant tabs, collapsible spoke groups, spoke detail modal, processing mode panel, audit log viewer, superadmin panel

### Changed
- Auth module rewritten to use JSON store instead of SQLAlchemy
- All routers refactored for tenant-scoped access control
- Background tasks are now all tenant-aware
- `docker-compose.yml` simplified — no nginx, single TLS-enabled service

### Removed
- PostgreSQL / SQLite / SQLAlchemy / Alembic
- nginx (TLS now handled inside container by uvicorn)
- `install-azure.sh` (replaced by `deploy-azure.sh` for ACI)
- `nginx.conf`

## [1.x] — Prior versions

See git log for history prior to the v2.0 refactor.

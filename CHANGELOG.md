# Changelog

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

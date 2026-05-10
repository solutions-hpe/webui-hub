# Hub — Client-Sim Central Platform

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-JSON%20Hub-009688)
![Docker](https://img.shields.io/badge/deployment-Docker%20%7C%20ACI%20%7C%20BYOD-2496ED)
![TLS](https://img.shields.io/badge/TLS-self--signed%20by%20default-success)

Hub is the central management plane for HPE Client-Sim spoke networks. It replaces the legacy `webui` application and its PostgreSQL/SQLAlchemy stack with a FastAPI-based, multi-tenant platform that stores all operational state in JSON under `/data/`.

## Overview

Hub is designed for operators who need to manage many spoke environments from one control plane while keeping tenant boundaries intact.

### Key capabilities

- Multi-tenant management for Aruba Central-backed tenants and manually created tenants
- Role-based access with **superadmin**, **admin**, and **operator** scopes
- Registration, approval, and lifecycle management for webui-spoke servers
- Centralized or distributed execution for Aruba polling, notifications, schedules, gkill, heartbeat, and repo sync
- JSON file store under `/data/` instead of PostgreSQL, SQLite, or SQLAlchemy
- HTTPS by default on port **8443** with self-signed certificate generation at startup
- Local JWT authentication today, with OIDC, LDAP/AD, and RADIUS stubs already wired in
- Deployment options for Docker, Azure Container Instance, and BYOD Linux hosts
- Per-spoke command queue, inbox/ack relay, and 7-day rolling audit history

## Architecture

Hub sits in the center, with webui-spoke servers polling for work and reporting telemetry.

```text
                           +-----------------------------------+
                           |               Hub                 |
                           | FastAPI + Static UI + JSON Store  |
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

## Quick Start (Docker)

### 1) Generate keys

```bash
export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export ADMIN_PASSWORD='change-this-now'
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
- Secure values for `WEBUI_SECRET_KEY`, `SECRET_KEY`, and `ADMIN_PASSWORD`

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

`deploy-azure.sh` builds the image in Azure Container Registry, provisions Azure File Share storage for `/data`, and creates an Azure Container Instance.

#### Prerequisites

- Azure CLI (`az`) installed and logged in
- Permission to create resource groups, ACR, storage, and ACI resources
- Exported secrets before running the script

#### Required environment variables

```bash
export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export ADMIN_PASSWORD='change-this-now'
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
- Inject `WEBUI_SECRET_KEY` and `SECRET_KEY` as secure environment variables

Resulting endpoint format:

```text
https://<dns-label>.<region>.azurecontainer.io:8443
```

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
| `WEBUI_SECRET_KEY` | empty | **Yes** in production | Fernet master key for encrypting secrets at rest. If omitted, Hub generates an ephemeral key and encrypted values will not survive restart. |
| `SECRET_KEY` | `change-me-in-production` | **Yes** in production | JWT signing key for login sessions. |
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
6. Create additional tenant admins and operators as needed.

## Spoke Registration

The spoke registration flow is intentionally two-stage so a superadmin can verify identity and tenant assignment.

### Step 1 — spoke registers itself

The spoke POSTs to:

```text
POST /api/islands/register
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
- Hub stores the registration in `/data/pending/<island_id>.json`

### Step 2 — superadmin approves and assigns a tenant

The superadmin reviews:

```text
GET /api/superadmin/pending-islands
```

Then approves:

```text
POST /api/superadmin/pending-islands/{island_id}/approve
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
   - `relay_island_id`
   - `relay_api_key`
   - `relay_tenant_id`
   - `relay_server_url`

### Step 3 — spoke polls inbox and receives relay credentials

The spoke polls its tenant-scoped inbox using the new route pattern:

```text
GET /api/{tenant_id}/islands/{island_id}/inbox
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
| `POST` | `/api/islands/register` | None | Register a spoke and create a pending spoke record |
| `POST` | `/api/{tenant_id}/islands/{island_id}/telemetry` | `X-API-Key` | Push telemetry and heartbeat data |
| `GET` | `/api/{tenant_id}/islands/{island_id}/inbox` | `X-API-Key` | Pull queued commands and config updates |
| `POST` | `/api/{tenant_id}/islands/{island_id}/ack` | `X-API-Key` | Acknowledge command execution and optionally report task results |

### Tenant-scoped management (JWT)

| Category | Method | Path | Role |
|---|---|---|---|
| Spokes | `GET` | `/api/{tenant_id}/islands` | superadmin, admin, operator |
| Spoke detail | `GET` | `/api/{tenant_id}/islands/{island_id}` | superadmin, admin, operator |
| Spoke revoke | `POST` | `/api/{tenant_id}/islands/{island_id}/revoke` | superadmin, admin |
| Spoke delete | `DELETE` | `/api/{tenant_id}/islands/{island_id}` | superadmin, admin |
| Spoke config | `PATCH` | `/api/{tenant_id}/islands/{island_id}/config` | superadmin, admin |
| Spoke label | `PATCH` | `/api/{tenant_id}/islands/{island_id}/label` | superadmin, admin |
| Commands | `POST` | `/api/commands` | superadmin, admin, operator with tenant access |
| Commands list | `GET` | `/api/{tenant_id}/commands` | superadmin, admin, operator |
| Repo sync | `POST` | `/api/{tenant_id}/islands/{island_id}/repo-sync` | superadmin, admin, operator |
| Settings | `GET` | `/api/{tenant_id}/settings` | superadmin, admin |
| Aruba settings | `POST` | `/api/{tenant_id}/settings/aruba` | superadmin, admin |
| Notification settings | `POST` | `/api/{tenant_id}/settings/notifications` | superadmin, admin |
| Processing mode | `GET` | `/api/{tenant_id}/settings/processing-mode` | superadmin, admin |
| Processing mode | `POST` | `/api/{tenant_id}/settings/processing-mode` | superadmin, admin |
| Per-spoke processing mode | `PATCH` | `/api/{tenant_id}/islands/{island_id}/processing-mode` | superadmin, admin |
| Processing summary | `GET` | `/api/{tenant_id}/processing-summary` | superadmin, admin, operator |
| Audit | `GET` | `/api/{tenant_id}/islands/{island_id}/audit` | superadmin, admin, operator |

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
| Pending spokes | `GET` | `/api/superadmin/pending-islands` | Review waiting spoke registrations |
| Approve spoke | `POST` | `/api/superadmin/pending-islands/{island_id}/approve` | Approve + assign tenant |
| Delete pending spoke | `DELETE` | `/api/superadmin/pending-islands/{island_id}` | Reject registration |
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
3. Hub queues a command in `/data/{tenant_id}/queue/{island_id}.json`.
4. The spoke polls `/inbox`, receives the command, applies it, and POSTs `/ack`.
5. Hub records the result in the queue and optionally appends an audit entry.

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
| `operator` | One tenant | Issue commands and view tenant-scoped operational data |

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

### Stubbed and ready for implementation

- **OIDC / OAuth2 SSO**
- **LDAP / Active Directory**
- **RADIUS**

The provider registry and config flags already exist. The flows currently advertise availability state, but only local password authentication is implemented.

## Data Layout

All persistent state lives under `DATA_DIR`.

```text
/data/
├── users.json
├── tenants.json
├── pending/
│   └── <pending-island-id>.json
├── tls/
│   ├── cert.pem
│   └── key.pem
└── <tenant_id>/
    ├── islands.json
    ├── queue/
    │   └── <island_id>.json
    └── audit/
        └── <island_id>.json
```

### What each file stores

| Path | Contents |
|---|---|
| `/data/users.json` | All Hub user accounts, bcrypt password hashes, superadmin flag, and tenant role assignments |
| `/data/tenants.json` | Tenant metadata plus encrypted Aruba and notification settings |
| `/data/pending/*.json` | Spoke registrations waiting for superadmin approval |
| `/data/{tenant_id}/islands.json` | Approved spokes, labels, runtime config, processing mode, telemetry, last seen timestamps |
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

## Spoke Integration Status

The `client-sim/webui-spoke/server.py` integration work for Hub is complete. The five spoke behaviors below have been implemented and are kept here as a reference.

1. **Implemented: use the new registration flow**
   - POST `hostname`, `label`, and `config` to `/api/islands/register`.
2. **Implemented: persist relay credentials from the approval command**
   - Read `relay_tenant_id`, `relay_island_id`, `relay_api_key`, and `relay_server_url` from the first `config_update` message.
3. **Implemented: move all relay traffic to tenant-scoped routes**
   - Use `/api/{tenant_id}/islands/{island_id}/telemetry`, `/inbox`, and `/ack` with `X-API-Key`.
4. **Implemented: handle Hub-driven command types**
   - Support `config_update`, `aruba_config_update`, `notification_push`, `gkill_update`, `reclone_schedule`, `repo_sync`, and `auto_recovery` as inbox items.
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

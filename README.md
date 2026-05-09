# Client-Sim Central WebUI

Centralized management dashboard for distributed Client-Sim islands.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Azure Container Apps               │
│  ┌──────────────┐   ┌──────────────────────┐   │
│  │  FastAPI App │   │  PostgreSQL (Flexible │   │
│  │  + Vanilla JS│   │  Server)              │   │
│  └──────┬───────┘   └──────────────────────┘   │
└─────────┼───────────────────────────────────────┘
          │ HTTPS (island relay API)
   ┌──────┴──────────────────────────┐
   │  Local Islands (LXC containers) │
   │  Client-Sim WebUI v0.91+        │
   └─────────────────────────────────┘
```

## Quick Start — Docker Compose

```bash
cp .env.example .env
# Edit .env with secure passwords
docker compose up -d
# Open http://localhost
```

## Quick Start — Azure Container Apps

```bash
cp .env.example .env
# Edit .env
./install-azure.sh
```

## Island Relay API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/islands/register | none | Register island, returns pending status |
| POST | /api/islands/{id}/telemetry | X-API-Key | Push telemetry JSON |
| GET | /api/islands/{id}/inbox | X-API-Key | Poll for pending commands |
| POST | /api/islands/{id}/ack | X-API-Key | Acknowledge command execution |

API key is shown **once** on approval in management UI.

## Check States

| State | Meaning |
|-------|---------|
| 🟢 green | Last report within timeout window |
| 🟡 yellow | Last report within 2× timeout (grace period) |
| 🔴 red | No report beyond 2× timeout |
| ⚪ unknown | Never reported |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | — | PostgreSQL connection string |
| SECRET_KEY | — | JWT signing key (change in prod) |
| ADMIN_PASSWORD | admin | Initial admin password |

# Deploying Hub from the Azure Portal

This guide deploys Hub to Azure Container Instance (ACI) using a pre-built image from GitHub Container Registry. No CLI required after the one-time setup.

---

## Step 1 — Push your image (automatic)

Every push to the `main` branch automatically builds and pushes the image via GitHub Actions:

```
ghcr.io/solutions-hpe/webui-hub:latest
```

You can also trigger it manually: **GitHub repo → Actions → Build & Push Hub Image → Run workflow**.

---

## Step 2 — Create an Azure File Share (one time)

This persists your `/data` directory (users, tenants, config) across container restarts.

1. Go to **Azure Portal → Storage accounts → Create**
2. Settings:
   - Resource group: `hub-rg` (create new if needed)
   - Storage account name: e.g. `hubstorage`
   - Region: your preferred region
   - Redundancy: `LRS` (cheapest)
3. Click **Review + Create → Create**
4. Once created, go to the storage account → **File shares → + File share**
   - Name: `hubdata`
   - Tier: `Transaction optimized`
5. Note the **storage account name** and **access key** (Settings → Access keys → key1)

---

## Step 3 — Generate secrets (one time, on any machine with Python)

Run these three commands and save the output:

```bash
# Encryption key (required — save this permanently)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# JWT signing key
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# Admin password (your choice)
echo "MySecureAdminPassword"
```

---

## Step 4 — Create the Container Instance

1. Go to **Azure Portal → Container instances → Create**

2. **Basics tab:**
   | Field | Value |
   |-------|-------|
   | Resource group | `hub-rg` |
   | Container name | `hub` |
   | Region | same as storage account |
   | Image source | **Other registry** |
   | Image | `ghcr.io/solutions-hpe/webui-hub:latest` |
   | OS type | Linux |
   | Size | 1 vCPU, 1.5 GiB memory |

3. **Networking tab:**
   | Field | Value |
   |-------|-------|
   | Networking type | Public |
   | DNS name label | e.g. `my-hub` (becomes `my-hub.<region>.azurecontainer.io`) |
   | Ports | `8443` / TCP |

4. **Advanced tab → Environment variables:**

   | Name | Value | Secure |
   |------|-------|--------|
   | `DATA_DIR` | `/data` | No |
   | `ADMIN_PASSWORD` | your admin password | **Yes** |
   | `WEBUI_SECRET_KEY` | output from Step 3 (first value) | **Yes** |
   | `SECRET_KEY` | output from Step 3 (second value) | **Yes** |

5. **Advanced tab → Volume mounts → Add volume:**
   | Field | Value |
   |-------|-------|
   | Volume name | `hubdata` |
   | Volume type | Azure File |
   | Storage account name | your storage account from Step 2 |
   | Storage account key | key1 from Step 2 |
   | File share name | `hubdata` |
   | Mount path | `/data` |

6. Click **Review + Create → Create**

---

## Step 5 — Access Hub

Once deployed (takes ~2 minutes):

```
https://<your-dns-label>.<region>.azurecontainer.io:8443
```

- Login: `admin` / your `ADMIN_PASSWORD`
- The browser will warn about the self-signed TLS certificate — click **Advanced → Proceed** to accept it.

---

## Updating Hub

Push changes to `main` → GitHub Actions rebuilds the image automatically.

To pull the new image in Azure Portal:
1. Go to **Container instances → hub → Restart**

Or delete and recreate the container instance (your data is safe on the File Share).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Container stuck in "Waiting" | Check logs: Container instance → Containers → Logs |
| Can't reach the URL | Confirm port 8443 is open in Networking tab |
| Login fails | Verify `ADMIN_PASSWORD` env var is set correctly |
| Data lost after restart | Verify volume mount path is `/data` |

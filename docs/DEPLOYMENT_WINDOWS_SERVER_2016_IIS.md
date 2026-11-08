# Windows Server 2016 + IIS 10 Deployment Guide
## Universal AI Job Application Assistant (Architecture v2.1.1)

---

### 1. Architectural Topology

```
Internet / Client Browser
          │ (HTTPS: 443)
          ▼
   IIS 10 Web Server
   ├── URL Rewrite 2.1
   └── Application Request Routing (ARR) 3.0
          │ (Reverse Proxy via 127.0.0.1)
          ▼
 FastAPI ASGI Application (NSSM Windows Service)
   ├── Listening on: 127.0.0.1:8000 (Localhost only)
   ├── Process: Python 3.11 x64 (uvicorn backend.api.main:app)
   ├── Serves: React SPA frontend (/ & /assets) + REST API (/api/*)
   └── Multi-Tenant Candidate Session Manager
          │
          ▼
 Local Persistent Storage (Drive D:\)
   ├── Database:    D:\AIJobAssistantData\database\job_assistant.db
   ├── Resumes/JDs: D:\AIJobAssistantData\users\<user_id>\
   ├── Backups:     D:\AIJobAssistantData\backups\
   ├── Exports:     D:\AIJobAssistantData\exports\
   └── Logs:        D:\AIJobAssistantData\logs\
```

---

### 2. Prerequisites & Server Requirements

| Component | Minimum Version / Specification | Purpose |
| :--- | :--- | :--- |
| **Operating System** | Windows Server 2016 Standard or Datacenter | Host OS |
| **Web Server** | Internet Information Services (IIS) 10.0 | HTTPS termination, reverse proxy, reverse WebSocket |
| **Python** | Python 3.11.x x64 (installed with "Add to PATH") | Application runtime |
| **VC++ Runtime** | Visual C++ 2015-2022 Redistributable (x64) | Required by argon2-cffi, cryptography |
| **IIS Extensions** | • URL Rewrite Module 2.1<br>• Application Request Routing (ARR) 3.0<br>• IIS WebSocket Protocol | Reverse proxying and real-time Streamlit WebSocket stream |
| **Service Wrapper** | NSSM (Non-Sucking Service Manager) 2.24+ | Windows Service process supervisor & log rotator |

---

### 3. Step-by-Step Installation Instructions

#### Step 3.1: Enable Required IIS Server Roles & Features
Open an elevated **PowerShell** prompt on the server:

```powershell
# Install IIS Web Server, WebSocket Protocol, and Management Tools
Install-WindowsFeature -Name Web-Server, Web-WebSockets, Web-Mgmt-Tools -IncludeManagementTools
```

Next, download and install the official Microsoft IIS extensions:
1. **URL Rewrite Module 2.1:** [https://www.iis.net/downloads/microsoft/url-rewrite](https://www.iis.net/downloads/microsoft/url-rewrite)
2. **Application Request Routing 3.0:** [https://www.iis.net/downloads/microsoft/application-request-routing](https://www.iis.net/downloads/microsoft/application-request-routing)

After installing ARR, enable proxy mode in IIS:
1. Open **IIS Manager** (`inetmgr.exe`).
2. Click the root server node in the left pane.
3. Double-click **Application Request Routing Cache**.
4. In the right Actions pane, click **Server Proxy Settings...**.
5. Check **Enable proxy**, leave default settings, and click **Apply**.

---

#### Step 3.2: Install Python 3.11 x64 & Tools
1. Download Python 3.11 x64 Windows installer from [python.org](https://www.python.org/downloads/windows/).
2. Run installer as Administrator:
   - Check **"Add python.exe to PATH"**.
   - Choose **"Customize installation"** and install for **All Users** to `C:\Program Files\Python311`.
3. Download **NSSM** (`nssm-2.24.zip`) from [nssm.cc](https://nssm.cc/download). Extract `win64\nssm.exe` to `C:\Windows\System32\nssm.exe` (or add to system PATH).

---

#### Step 3.3: Deploy Application Codebase
Clone or copy the application files to the designated application directory:

```powershell
# Create code directory
New-Item -ItemType Directory -Path "C:\Apps\AI_Job_Application_Assistant" -Force

# Clone repository or copy release files
git clone https://github.com/pranayagrawal2116/AI_Job_Application_Assistant.git C:\Apps\AI_Job_Application_Assistant
Set-Location C:\Apps\AI_Job_Application_Assistant

# Upgrade pip and install production dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

#### Step 3.4: Configure Production Environment Variables (`.env`)
Copy the production template:

```powershell
Copy-Item .env.production.example .env
```

Generate cryptographically secure, unique 256-bit hexadecimal keys for all mandatory production secrets using the automated secrets generator:

```powershell
# Automatically populate .env with freshly generated 256-bit keys
python scripts/generate_production_secrets.py --write-env
```

Alternatively, generate individual keys via the command line:

```powershell
python -c "import secrets; print('SESSION_SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('PASSWORD_RESET_PEPPER=' + secrets.token_hex(32))"
python -c "import secrets; print('AUDIT_LOG_PEPPER=' + secrets.token_hex(32))"
python -c "import secrets; print('ACTION_TICKET_SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('SECURITY_SCAN_SIGNING_KEY=' + secrets.token_hex(32))"
```

Open `C:\Apps\AI_Job_Application_Assistant\.env` and verify the persistent production storage paths:

```ini
APP_ENV=production
LOG_LEVEL=INFO

DATABASE_PATH=D:\AIJobAssistantData\database\job_assistant.db
USER_STORAGE_BASE=D:\AIJobAssistantData\users
BACKUP_DIR=D:\AIJobAssistantData\backups
EXPORTS_DIR=D:\AIJobAssistantData\exports

# Strict safety and human-in-the-loop flags
ALLOW_AUTOMATED_SUBMISSION=false
RESPECT_ROBOTS_TXT=true
HEADLESS=true
```

To run preflight configuration verification manually before installing the service:

```powershell
python -c "from src.config.env_loader import load_production_env, validate_production_configuration; load_production_env(); validate_production_configuration(); print('CONFIGURATION_VALIDATED_SUCCESSFULLY')"
```

---

#### Step 3.5: Build React Frontend & Verify Single-Worker Execution
The modern SaaS interface uses React + TypeScript + Vite, served directly by FastAPI from `frontend/dist`.
Before running in production, build the static assets:

```powershell
Set-Location C:\Apps\AI_Job_Application_Assistant\frontend
npm ci
npm run build
Set-Location C:\Apps\AI_Job_Application_Assistant
```

> [!IMPORTANT]
> **Single-Worker Constraint (`--workers 1`):**
> JobFlow AI utilizes an embedded SQLite database engine with atomic WAL mode and in-process background worker execution for resume extraction and job discovery.
> Multiple Uvicorn worker processes must NOT be configured. Running more than 1 worker will cause concurrency conflicts during startup discovery recovery and multi-tenant locking. Exactly one worker (`--workers 1`) is officially supported and enforced in `service_install.ps1`.

To test the application interactively before registering the Windows service:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_app.ps1
```
Open a browser on the server and navigate to `http://127.0.0.1:8000/api/health`. Once verified, press `Ctrl+C` to stop.

---

#### Step 3.6: Install Windows Service with NSSM
Run the automated service installer script:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\service_install.ps1
```

This automated script performs:
1. Directory creation on `D:\AIJobAssistantData\` (`database`, `users`, `backups`, `logs`, `exports`).
2. Setting NTFS permissions so `SYSTEM` and `NETWORK SERVICE` have full control.
3. Registering the service `AIJobAssistant` running `python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --workers 1` with automatic startup (`SERVICE_AUTO_START`).
4. Configuring automatic log rotation at 10 MB per log in `D:\AIJobAssistantData\logs\`.
5. Starting the service.

Verify that the service is running:

```powershell
Get-Service -Name AIJobAssistant
```

---

#### Step 3.7: Configure IIS Reverse Proxy
1. In **IIS Manager**, create a new Web Site or select the existing `Default Web Site`.
2. Point the Physical Path to `C:\Apps\AI_Job_Application_Assistant\deploy\iis` (or copy `deploy\iis\web.config` into your designated IIS site root).
3. Bind an SSL/TLS Certificate to Port 443 (HTTPS) on your public domain (e.g., `careers-assistant.yourdomain.com`).
4. **Configure Allowed Server Variables in IIS:**
   In IIS Manager, select the site or server, open **URL Rewrite**, click **View Server Variables...** in the Actions pane, and add:
   - `HTTP_X_FORWARDED_FOR`
   - `HTTP_X_FORWARDED_PROTO`
   - `HTTP_X_FORWARDED_HOST`
5. Ensure Port 8000 is **NOT** exposed on the public Windows Firewall. Only Port 80 and Port 443 should be allowed externally.

---

### 4. Operational Runbooks

#### Health Check Verification
1. **Local Health Probe:**
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health"
   # Returns:
   # {
   #   "status": "healthy",
   #   "version": "2.1.1",
   #   "framework": "FastAPI + React SaaS",
   #   "environment": {
   #     "app_env": "production",
   #     "database_connected": true,
   #     "persistent_storage_ready": true,
   #     "database_path": "D:\\AIJobAssistantData\\database\\job_assistant.db",
   #     "storage_base": "D:\\AIJobAssistantData\\users",
   #     "db_error": null
   #   },
   #   "configuration_subsystem": {"ready": true, "error": null},
   #   "discovery_subsystem": {"ready": true, "recovery_error": null},
   #   "single_worker_mode": true
   # }
   ```
2. **External Reverse-Proxy Probe:**
   ```powershell
   Invoke-RestMethod -Uri "https://careers-assistant.yourdomain.com/api/health"
   ```

#### Service Control Commands
```powershell
# Check status
Get-Service -Name AIJobAssistant

# Restart service
Restart-Service -Name AIJobAssistant

# Stop service
Stop-Service -Name AIJobAssistant

# Start service
Start-Service -Name AIJobAssistant
```

#### Scheduled Daily Backups
To schedule automated daily database backups at 02:00 AM with SQLite integrity verification:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Apps\AI_Job_Application_Assistant\deploy\windows\backup_database.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AIJobAssistant_DailyBackup" -Description "Atomic SQLite online database backup with PRAGMA integrity_check" -User "NT AUTHORITY\SYSTEM"
```

---

### 5. Troubleshooting & FAQ

#### Q: Service fails to start with "CONFIG_PREFLIGHT_ERROR" during service_install.ps1.
- **Cause:** One or more production secrets in `.env` are still placeholder strings, have insufficient entropy, or match each other.
- **Solution:**
  Run the automated secret generator:
  ```powershell
  python scripts/generate_production_secrets.py --write-env
  ```
  Then re-run `deploy/windows/service_install.ps1`.

#### Q: Large resume or document upload fails with HTTP 413 or "Request Entity Too Large".
- **Cause:** IIS request size ceiling is exceeded.
- **Solution:** `deploy/iis/web.config` specifies `<requestLimits maxAllowedContentLength="10485760" />` (10 MB). The application enforces a strict 10 MB file cap. Resumes or job description documents exceeding 10 MB must be compressed or trimmed by the candidate.

#### Q: Database is locked error (`sqlite3.OperationalError: database is locked`).
- **Cause:** Multiple worker processes configured or SQLite database stored on a shared network drive (SMB/CIFS) rather than local storage.
- **Solution:**
  1. Strictly store the SQLite database on local physical drives (`D:\AIJobAssistantData\database\job_assistant.db`), never on network shares.
  2. Verify that Uvicorn is launched with `--workers 1`. Multiple workers must not access SQLite concurrently.

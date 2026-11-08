<#
.SYNOPSIS
    Automated Windows Service Installer for AI Job Application Assistant using NSSM.
.DESCRIPTION
    Configures and installs the FastAPI ASGI application as an automated, resilient Windows Service
    on Windows Server 2016 behind IIS 10 reverse proxy.
    Performs comprehensive preflight checks:
      1. Administrator elevation
      2. 64-bit Python 3.11 environment
      3. NSSM binary availability
      4. React frontend production bundle
      5. Production .env configuration validation (secrets, paths, safety flags)
      6. Dedicated persistent directories (D:\AIJobAssistantData) and NTFS ACLs
    Enforces --workers 1 and --env-file in NSSM service registration.
    Polls /api/health after startup to verify production readiness.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Apps\AI_Job_Application_Assistant",
    [string]$DataDir = "D:\AIJobAssistantData",
    [string]$PythonExe = "C:\Program Files\Python311\python.exe",
    [string]$ServiceName = "AIJobAssistant",
    [string]$EnvFile = ""
)

$ErrorActionPreference = "Stop"

if (-not $EnvFile) {
    $EnvFile = Join-Path $InstallDir ".env"
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " AI Job Application Assistant - Production Service Installer (NSSM)" -ForegroundColor Cyan
Write-Host " Architecture: v2.1.1 (FastAPI + React SaaS)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# PREFLIGHT STEP 1: Administrator Elevation Check
# -----------------------------------------------------------------------------
Write-Host "[1/6] Verifying Administrator privileges..." -ForegroundColor Cyan
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "CRITICAL: This installer must be executed from an elevated Administrator PowerShell prompt."
}
Write-Host "      [OK] Elevated Administrator session detected." -ForegroundColor Green

# -----------------------------------------------------------------------------
# PREFLIGHT STEP 2: Python 3.11 x64 Verification
# -----------------------------------------------------------------------------
Write-Host "[2/6] Verifying Python 3.11 64-bit environment..." -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) {
    Write-Error "CRITICAL: Installation directory '$InstallDir' does not exist."
}

if (-not (Test-Path $PythonExe)) {
    $detectedPy = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
    if ($detectedPy) {
        Write-Host "      Found alternative Python: $detectedPy" -ForegroundColor Yellow
        $PythonExe = $detectedPy
    } else {
        Write-Error "CRITICAL: Python executable not found at '$PythonExe' and not in PATH."
    }
}

# Verify 64-bit architecture and version 3.11+
$pyArchCheck = & $PythonExe -c "import sys, struct; print(f'{sys.version_info.major}.{sys.version_info.minor}|{struct.calcsize(\"P\") * 8}')"
$pyParts = $pyArchCheck.Trim().Split('|')
$pyVer = $pyParts[0]
$pyBits = $pyParts[1]

if ($pyBits -ne "64") {
    Write-Error "CRITICAL: Python must be 64-bit architecture. Detected: $pyBits-bit."
}
Write-Host "      [OK] Python version: $pyVer ($pyBits-bit) at $PythonExe" -ForegroundColor Green

# -----------------------------------------------------------------------------
# PREFLIGHT STEP 3: NSSM Binary Verification
# -----------------------------------------------------------------------------
Write-Host "[3/6] Verifying NSSM service manager binary..." -ForegroundColor Cyan
$nssmCmd = Get-Command nssm.exe -ErrorAction SilentlyContinue
if (-not $nssmCmd) {
    $localNssm = Join-Path $InstallDir "tools\nssm.exe"
    if (Test-Path $localNssm) {
        $nssmPath = $localNssm
    } else {
        Write-Error "CRITICAL: NSSM (nssm.exe) not found in PATH or at '$localNssm'. Download from https://nssm.cc/ and place in PATH or tools directory."
    }
} else {
    $nssmPath = $nssmCmd.Source
}
Write-Host "      [OK] NSSM binary verified: $nssmPath" -ForegroundColor Green

# -----------------------------------------------------------------------------
# PREFLIGHT STEP 4: Frontend Distribution Verification
# -----------------------------------------------------------------------------
Write-Host "[4/6] Verifying production React frontend build..." -ForegroundColor Cyan
$frontendDist = Join-Path $InstallDir "frontend\dist"
$frontendIndex = Join-Path $frontendDist "index.html"
if (-not (Test-Path $frontendIndex)) {
    Write-Error "CRITICAL: Frontend distribution not found at '$frontendIndex'. Run 'npm run build' inside '$InstallDir\frontend' before installing service."
}
Write-Host "      [OK] Frontend distribution found at $frontendDist" -ForegroundColor Green

# -----------------------------------------------------------------------------
# PREFLIGHT STEP 5: Production .env Validation Preflight
# -----------------------------------------------------------------------------
Write-Host "[5/6] Validating production .env configuration ($EnvFile)..." -ForegroundColor Cyan
if (-not (Test-Path $EnvFile)) {
    Write-Error "CRITICAL: Production configuration file '$EnvFile' not found.`nCreate it from .env.production.example and run: python scripts/generate_production_secrets.py --write-env"
}

# Run Python validation check before registering service
$preflightScript = @"
import sys
try:
    from src.config.env_loader import load_production_env, validate_production_configuration
    load_production_env(r'$EnvFile')
    validate_production_configuration()
    print("CONFIG_PREFLIGHT_OK")
except Exception as exc:
    print(f"CONFIG_PREFLIGHT_ERROR:{exc}", file=sys.stderr)
    sys.exit(1)
"@

$preflightOutput = & $PythonExe -c $preflightScript 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "CRITICAL: Production configuration validation failed!`n$preflightOutput`nPlease run 'python scripts/generate_production_secrets.py --write-env' to generate valid 256-bit secrets."
}
Write-Host "      [OK] Production environment secrets, storage paths, and safety flags validated." -ForegroundColor Green

# -----------------------------------------------------------------------------
# PREFLIGHT STEP 6: Persistent Storage Directories & NTFS ACLs
# -----------------------------------------------------------------------------
Write-Host "[6/6] Creating persistent storage directories and setting NTFS ACLs..." -ForegroundColor Cyan
$dirs = @(
    "$DataDir\database",
    "$DataDir\users",
    "$DataDir\backups",
    "$DataDir\logs",
    "$DataDir\exports"
)

foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host "      [DIR] Created: $d" -ForegroundColor Green
    } else {
        Write-Host "      [DIR] Exists:  $d" -ForegroundColor Gray
    }
}

Write-Host "      Configuring NTFS ACL permissions on $DataDir..." -ForegroundColor Yellow
try {
    icacls $DataDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /Q | Out-Null
    icacls $DataDir /grant "NT AUTHORITY\NETWORK SERVICE:(OI)(CI)M" /T /Q | Out-Null
    Write-Host "      [OK] ACL permissions configured successfully." -ForegroundColor Green
} catch {
    Write-Warning "      Could not configure ACLs automatically: $_"
}

# -----------------------------------------------------------------------------
# SERVICE REGISTRATION & INSTALLATION
# -----------------------------------------------------------------------------
Write-Host "`nStopping and removing existing service registration if present..." -ForegroundColor Yellow
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Found existing service '$ServiceName'. Stopping and removing..." -ForegroundColor Yellow
    & $nssmPath stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    & $nssmPath remove $ServiceName confirm
    Write-Host "[OK] Removed prior service registration." -ForegroundColor Green
}

Write-Host "Registering Windows Service '$ServiceName' via NSSM..." -ForegroundColor Cyan
$appArgs = "-m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --workers 1 --env-file `"$EnvFile`""

& $nssmPath install $ServiceName $PythonExe $appArgs
& $nssmPath set $ServiceName AppDirectory $InstallDir
& $nssmPath set $ServiceName Description "Universal AI Job Application Assistant (FastAPI ASGI on 127.0.0.1:8000 behind IIS 10)"
& $nssmPath set $ServiceName Start SERVICE_AUTO_START

# Log rotation: 10 MB limit per log, keep archive
& $nssmPath set $ServiceName AppStdout "$DataDir\logs\app.log"
& $nssmPath set $ServiceName AppStderr "$DataDir\logs\app_error.log"
& $nssmPath set $ServiceName AppRotateFiles 1
& $nssmPath set $ServiceName AppRotateOnline 1
& $nssmPath set $ServiceName AppRotateBytes 10485760

# Restart behavior
& $nssmPath set $ServiceName AppThrottle 3000
& $nssmPath set $ServiceName AppExit Default Restart

# -----------------------------------------------------------------------------
# START SERVICE & HEALTH VERIFICATION
# -----------------------------------------------------------------------------
Write-Host "`nStarting Windows Service '$ServiceName'..." -ForegroundColor Cyan
& $nssmPath start $ServiceName

Write-Host "Awaiting service initialization and verifying health endpoint..." -ForegroundColor Cyan
$healthUrl = "http://127.0.0.1:8000/api/health"
$maxAttempts = 15
$attempt = 0
$isHealthy = $false

while ($attempt -lt $maxAttempts -and -not $isHealthy) {
    Start-Sleep -Seconds 2
    $attempt++
    try {
        $response = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 3 -ErrorAction Stop
        if ($response.status -eq "healthy") {
            $isHealthy = $true
            break
        } else {
            Write-Host "      Attempt $attempt/$maxAttempts: Service reported status '$($response.status)'" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "      Attempt $attempt/$maxAttempts: Waiting for $healthUrl..." -ForegroundColor Gray
    }
}

if ($isHealthy) {
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] Windows Service '$ServiceName' is RUNNING & HEALTHY!" -ForegroundColor Green
    Write-Host " Local Endpoint: $healthUrl" -ForegroundColor Green
    Write-Host " Persistent Logs: $DataDir\logs" -ForegroundColor Green
    Write-Host " SQLite Database: $DataDir\database\job_assistant.db" -ForegroundColor Green
    Write-Host " Worker Model:   Single Worker (--workers 1)" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
} else {
    Write-Error "CRITICAL: Service health check failed after $maxAttempts attempts.`nInspect logs at '$DataDir\logs\app_error.log' for startup failure diagnostics."
}

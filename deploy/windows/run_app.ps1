<#
.SYNOPSIS
    Interactive PowerShell Launcher for AI Job Application Assistant.
    Used for local testing or troubleshooting prior to Windows service registration.
.DESCRIPTION
    Strictly validates configuration and launches the FastAPI ASGI server with React SPA,
    enforcing --workers 1, 127.0.0.1 binding, and failing closed on invalid production configuration.
.PARAMETER Port
    HTTP listen port. Default: 8000.
.PARAMETER Address
    Listen IP address. Default: 127.0.0.1 (Localhost only behind IIS).
.PARAMETER EnvFile
    Path to environment configuration file (e.g. C:\Apps\AI_Job_Application_Assistant\.env).
.PARAMETER PythonExe
    Path to Python 3.11 x64 executable. Auto-detected if omitted.
.PARAMETER Dev
    Explicit switch to allow running in local development mode without a production .env file.
#>

[CmdletBinding()]
param(
    [string]$Port = "8000",
    [string]$Address = "127.0.0.1",
    [string]$EnvFile = "",
    [string]$PythonExe = "",
    [switch]$Dev
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path

Set-Location $ProjectRoot
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Starting AI Job Application Assistant from $ProjectRoot" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Resolve Python Executable
if (-not $PythonExe) {
    $detectedPy = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
    if ($detectedPy) {
        $PythonExe = $detectedPy
    } elseif (Test-Path "C:\Program Files\Python311\python.exe") {
        $PythonExe = "C:\Program Files\Python311\python.exe"
    } else {
        Write-Error "CRITICAL: Python executable not found in PATH or standard installation directory."
        exit 1
    }
} else {
    if (-not (Test-Path $PythonExe)) {
        Write-Error "CRITICAL: Specified Python executable '$PythonExe' does not exist."
        exit 1
    }
}

Write-Host "Using Python executable: $PythonExe" -ForegroundColor Gray

# 2. Resolve Environment File
$ResolvedEnvFile = ""
if ($EnvFile) {
    if (-not (Test-Path $EnvFile)) {
        Write-Error "CRITICAL: Explicitly specified environment file '$EnvFile' does not exist."
        exit 1
    }
    $ResolvedEnvFile = (Resolve-Path $EnvFile).Path
} else {
    $defaultEnv = Join-Path $ProjectRoot ".env"
    if (Test-Path $defaultEnv) {
        $ResolvedEnvFile = (Resolve-Path $defaultEnv).Path
    } else {
        if (-not $Dev) {
            Write-Error "CRITICAL: Production launch requires an existing environment file. None found at '$defaultEnv'.`nTo launch in local development mode without a production .env, explicitly pass the -Dev switch."
            exit 1
        }
    }
}

# 3. Strict Preflight Validation (Fail-Closed Enforcement)
$isDev = if ($Dev) { "True" } else { "False" }

if ($ResolvedEnvFile) {
    Write-Host "Validating configuration from: $ResolvedEnvFile..." -ForegroundColor Cyan
    $preflightScript = @"
import os, sys
try:
    from src.config.env_loader import load_production_env, validate_production_configuration
    load_production_env(r'$ResolvedEnvFile')
    app_env = os.environ.get("APP_ENV", "").strip().lower()
    is_dev_mode = $isDev

    if not is_dev_mode:
        if app_env != "production":
            raise ValueError(
                f"Normal launch requires APP_ENV=production. Detected APP_ENV='{app_env}'. "
                "To run in local development mode with a non-production .env, pass the -Dev switch."
            )
        validate_production_configuration(enforce=True)
    else:
        if app_env == "production":
            validate_production_configuration(enforce=True)
    print(f"PREFLIGHT_OK|{app_env}")
except Exception as exc:
    print(f"PREFLIGHT_FAIL|{exc}", file=sys.stderr)
    sys.exit(1)
"@

    $preflightResult = & $PythonExe -c $preflightScript 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CRITICAL: Configuration preflight validation failed! Uvicorn execution is strictly aborted to prevent fail-open state.`n$preflightResult"
        exit 1
    }
    Write-Host "[OK] Configuration validated successfully." -ForegroundColor Green
} else {
    Write-Host "[DEV] Running in explicitly requested local DEVELOPMENT mode without .env file." -ForegroundColor Yellow
}

# 4. Launch Uvicorn with Single Worker
Write-Host "Running Uvicorn with single worker on $Address`:$Port..." -ForegroundColor Green
if ($ResolvedEnvFile) {
    & $PythonExe -m uvicorn backend.api.main:app --host $Address --port $Port --workers 1 --env-file "$ResolvedEnvFile"
} else {
    $env:APP_ENV = "development"
    & $PythonExe -m uvicorn backend.api.main:app --host $Address --port $Port --workers 1
}

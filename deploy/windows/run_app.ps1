<#
.SYNOPSIS
    Interactive PowerShell Launcher for AI Job Application Assistant.
    Used for local testing or troubleshooting prior to Windows service registration.
.DESCRIPTION
    Validates configuration and launches the FastAPI ASGI server with React SPA,
    enforcing --workers 1, 127.0.0.1 binding, and loading .env with validation.
#>

[CmdletBinding()]
param(
    [string]$Port = "8000",
    [string]$Address = "127.0.0.1",
    [string]$EnvFile = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path

Set-Location $ProjectRoot
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Starting AI Job Application Assistant from $ProjectRoot" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Verify Python
$pyCmd = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pyCmd) {
    Write-Error "Python executable not found in PATH."
}

# Resolve .env file
if (-not $EnvFile) {
    $defaultEnv = Join-Path $ProjectRoot ".env"
    if (Test-Path $defaultEnv) {
        $EnvFile = $defaultEnv
    }
}

$envArgs = ""
if ($EnvFile -and (Test-Path $EnvFile)) {
    Write-Host "Validating configuration from $EnvFile..." -ForegroundColor Cyan
    $preflight = & python -c "from src.config.env_loader import load_production_env, validate_production_configuration; load_production_env(r'$EnvFile'); validate_production_configuration(); print('ENV_OK')" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Configuration validation warning / error:`n$preflight"
    } else {
        Write-Host "[OK] Configuration validated." -ForegroundColor Green
    }
    $envArgs = "--env-file `"$EnvFile`""
}

Write-Host "Running Uvicorn with single worker on $Address`:$Port..." -ForegroundColor Green
if ($envArgs) {
    & python -m uvicorn backend.api.main:app --host $Address --port $Port --workers 1 --env-file $EnvFile
} else {
    & python -m uvicorn backend.api.main:app --host $Address --port $Port --workers 1
}

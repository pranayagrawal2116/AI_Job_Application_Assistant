<#
.SYNOPSIS
    Interactive PowerShell Launcher for AI Job Application Assistant.
    Used for local testing or troubleshooting prior to service registration.
#>

[CmdletBinding()]
param(
    [string]$Port = "8000",
    [string]$Address = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Resolve-Path "$ScriptDir\..\.."

Set-Location $ProjectRoot
Write-Host "Starting AI Job Application Assistant from $ProjectRoot..." -ForegroundColor Cyan

# Verify Python
$pyCmd = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pyCmd) {
    Write-Error "Python executable not found in PATH."
}

# Run FastAPI ASGI server (serves REST API and React SPA from frontend/dist)
Write-Host "Running: python -m uvicorn backend.api.main:app --host $Address --port $Port --workers 1" -ForegroundColor Green
& python -m uvicorn backend.api.main:app --host $Address --port $Port --workers 1

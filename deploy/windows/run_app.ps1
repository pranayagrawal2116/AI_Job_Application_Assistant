<#
.SYNOPSIS
    Interactive PowerShell Launcher for AI Job Application Assistant.
    Used for local testing or troubleshooting prior to service registration.
#>

[CmdletBinding()]
param(
    [string]$Port = "8501",
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

# Run Streamlit
Write-Host "Running: python -m streamlit run dashboard\app.py --server.port $Port --server.address $Address" -ForegroundColor Green
& python -m streamlit run dashboard\app.py --server.port $Port --server.address $Address

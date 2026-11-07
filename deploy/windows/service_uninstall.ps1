<#
.SYNOPSIS
    Cleanly stops and removes the AI Job Application Assistant Windows Service.
.PARAMETER ServiceName
    Windows Service identifier. Default: AIJobAssistant
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "AIJobAssistant"
)

$ErrorActionPreference = "Stop"

# Administrator Elevation Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run from an elevated Administrator PowerShell prompt."
}

$nssmCmd = Get-Command nssm.exe -ErrorAction SilentlyContinue
if (-not $nssmCmd) {
    Write-Error "NSSM executable not found in PATH."
}
$nssmPath = $nssmCmd.Source

Write-Host "Stopping and removing Windows Service '$ServiceName'..." -ForegroundColor Yellow
& $nssmPath stop $ServiceName 2>$null
Start-Sleep -Seconds 2
& $nssmPath remove $ServiceName confirm

Write-Host "[SUCCESS] Windows Service '$ServiceName' has been removed." -ForegroundColor Green

<#
.SYNOPSIS
    Automated Windows Service Installer for AI Job Application Assistant using NSSM.
.DESCRIPTION
    Configures and installs the Streamlit dashboard as an automated, resilient Windows Service
    on Windows Server 2016. Creates dedicated production storage directories on D:\ and sets ACL permissions.
.PARAMETER InstallDir
    Application codebase root directory. Default: C:\Apps\AI_Job_Application_Assistant
.PARAMETER DataDir
    Persistent storage root directory (outside IIS web root). Default: D:\AIJobAssistantData
.PARAMETER PythonExe
    Path to 64-bit Python 3.11 executable. Default: C:\Program Files\Python311\python.exe
.PARAMETER ServiceName
    Windows Service identifier. Default: AIJobAssistant
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\service_install.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Apps\AI_Job_Application_Assistant",
    [string]$DataDir = "D:\AIJobAssistantData",
    [string]$PythonExe = "C:\Program Files\Python311\python.exe",
    [string]$ServiceName = "AIJobAssistant"
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " AI Job Application Assistant - Windows Service Setup (NSSM)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Administrator Elevation Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This installer must be run from an elevated Administrator PowerShell prompt."
}

# 2. Path Validations
if (-not (Test-Path $InstallDir)) {
    Write-Error "Installation directory '$InstallDir' not found. Please verify the path."
}
if (-not (Test-Path $PythonExe)) {
    Write-Warning "Python executable not found at standard path: $PythonExe"
    $detectedPy = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
    if ($detectedPy) {
        Write-Host "Found alternative Python: $detectedPy" -ForegroundColor Yellow
        $PythonExe = $detectedPy
    } else {
        Write-Error "Python 3.11 x64 executable not found. Please install Python 3.11 or specify -PythonExe."
    }
}

# 3. NSSM Availability Check
$nssmCmd = Get-Command nssm.exe -ErrorAction SilentlyContinue
if (-not $nssmCmd) {
    $localNssm = Join-Path $InstallDir "tools\nssm.exe"
    if (Test-Path $localNssm) {
        $nssmPath = $localNssm
    } else {
        Write-Error "NSSM (Non-Sucking Service Manager) not found in PATH or '$localNssm'. Download from https://nssm.cc/ and place in PATH."
    }
} else {
    $nssmPath = $nssmCmd.Source
}
Write-Host "[OK] Using NSSM binary: $nssmPath" -ForegroundColor Green

# 4. Create Production Data Directories
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
        Write-Host "[DIR] Created: $d" -ForegroundColor Green
    } else {
        Write-Host "[DIR] Exists:  $d" -ForegroundColor Gray
    }
}

# 5. Configure Permissions (SYSTEM & Local Service Access)
Write-Host "Configuring filesystem ACLs on $DataDir..." -ForegroundColor Yellow
try {
    icacls $DataDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /Q | Out-Null
    icacls $DataDir /grant "NT AUTHORITY\NETWORK SERVICE:(OI)(CI)M" /T /Q | Out-Null
    Write-Host "[OK] ACL permissions configured successfully." -ForegroundColor Green
} catch {
    Write-Warning "Could not configure ACLs automatically: $_"
}

# 6. Stop and Remove Existing Service if present
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Existing service '$ServiceName' found. Stopping and removing..." -ForegroundColor Yellow
    & $nssmPath stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    & $nssmPath remove $ServiceName confirm
    Write-Host "[OK] Removed prior service registration." -ForegroundColor Green
}

# 7. Install Windows Service with NSSM
Write-Host "Installing Windows Service '$ServiceName'..." -ForegroundColor Cyan
$appArgs = "-m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000"

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

# Restart on unexpected exit after 3000ms delay
& $nssmPath set $ServiceName AppThrottle 3000
& $nssmPath set $ServiceName AppExit Default Restart

# 8. Start Service
Write-Host "Starting Windows Service '$ServiceName'..." -ForegroundColor Cyan
& $nssmPath start $ServiceName

Start-Sleep -Seconds 3
$svcStatus = (Get-Service -Name $ServiceName).Status
if ($svcStatus -eq "Running") {
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] Service '$ServiceName' is RUNNING!" -ForegroundColor Green
    Write-Host " Local Endpoint: http://127.0.0.1:8000" -ForegroundColor Green
    Write-Host " Logs Directory: $DataDir\logs" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
} else {
    Write-Warning "Service status is currently: $svcStatus. Check $DataDir\logs\app_error.log for details."
}

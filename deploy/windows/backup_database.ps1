<#
.SYNOPSIS
    Automated SQLite Online Database Backup Script for Windows Task Scheduler.
.DESCRIPTION
    Triggers an atomic, online backup of the SQLite database to the dedicated backups directory.
    Explicitly loads production .env to ensure the target database matches DATABASE_PATH.
    Verifies SQLite database integrity (PRAGMA integrity_check) on the backup file.
    Purges older backup archives ONLY after a verified backup succeeds.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Apps\AI_Job_Application_Assistant",
    [string]$BackupDir = "D:\AIJobAssistantData\backups",
    [string]$EnvFile = "",
    [int]$RetentionDays = 30
)

$ErrorActionPreference = "Stop"
Set-Location $InstallDir

if (-not $EnvFile) {
    $EnvFile = Join-Path $InstallDir ".env"
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = Join-Path $BackupDir "backup_job_assistant_$timestamp.db"

Write-Host "Creating online SQLite backup at: $backupFile..." -ForegroundColor Cyan

# Execute atomic backup via Python DatabaseManager after explicitly loading .env
$code = @"
import os, sys, sqlite3
from pathlib import Path

# Load production environment before importing DatabaseManager
from src.config.env_loader import load_production_env
load_production_env(r'$EnvFile')

from src.database.db_manager import DatabaseManager
db = DatabaseManager()

print(f"SOURCE_DATABASE:{db.db_path}")

# Perform atomic online backup
path = db.backup_database(backup_path=r'$backupFile')

# Verify SQLite integrity on the backup copy
conn = sqlite3.connect(path)
cursor = conn.cursor()
cursor.execute("PRAGMA integrity_check")
status = cursor.fetchone()[0]
conn.close()

if status != "ok":
    print(f"INTEGRITY_CHECK_FAILED:{status}", file=sys.stderr)
    sys.exit(2)

print(f"BACKUP_SUCCESS:{path}")
"@

$result = python -c "$code" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Backup or integrity check failed!`n$result"
}

Write-Host $result -ForegroundColor Green

# Retention cleanup: ONLY executed if backup and integrity check succeeded
Write-Host "Cleaning backups older than $RetentionDays days in $BackupDir..." -ForegroundColor Yellow
$cutoff = (Get-Date).AddDays(-$RetentionDays)
Get-ChildItem -Path $BackupDir -Filter "*.db" | Where-Object { $_.LastWriteTime -lt $cutoff -and $_.FullName -ne $backupFile } | ForEach-Object {
    Write-Host "Purging expired backup: $($_.Name)" -ForegroundColor Gray
    Remove-Item $_.FullName -Force
}

Write-Host "Backup process completed successfully." -ForegroundColor Green

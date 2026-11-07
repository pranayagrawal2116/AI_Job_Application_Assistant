<#
.SYNOPSIS
    Automated SQLite Online Database Backup Script for Windows Task Scheduler.
.DESCRIPTION
    Triggers an atomic, online backup of the SQLite database to the dedicated backups directory.
    Retains the last 30 daily backup archives and purges older ones.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Apps\AI_Job_Application_Assistant",
    [string]$BackupDir = "D:\AIJobAssistantData\backups",
    [int]$RetentionDays = 30
)

$ErrorActionPreference = "Stop"
Set-Location $InstallDir

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = Join-Path $BackupDir "backup_job_assistant_$timestamp.db"

Write-Host "Creating online SQLite backup at: $backupFile..." -ForegroundColor Cyan

# Execute atomic backup via Python DatabaseManager
$code = @"
import os, sys
from pathlib import Path
from src.database.db_manager import DatabaseManager
db = DatabaseManager()
path = db.backup_database(backup_path=r'$backupFile')
print(f'BACKUP_SUCCESS:{path}')
"@

$result = python -c "$code"
Write-Host $result -ForegroundColor Green

# Retention cleanup
Write-Host "Cleaning backups older than $RetentionDays days in $BackupDir..." -ForegroundColor Yellow
$cutoff = (Get-Date).AddDays(-$RetentionDays)
Get-ChildItem -Path $BackupDir -Filter "*.db" | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object {
    Write-Host "Purging expired backup: $($_.Name)" -ForegroundColor Gray
    Remove-Item $_.FullName -Force
}

Write-Host "Backup process completed." -ForegroundColor Green

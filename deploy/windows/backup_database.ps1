<#
.SYNOPSIS
    Automated SQLite Online Database Backup Script for Windows Task Scheduler.
.DESCRIPTION
    Triggers an atomic, online backup of the SQLite database to the dedicated backups directory.
    Strictly verifies the production environment file exists and validates configuration before import.
    Requires APP_ENV=production, validates DATABASE_PATH and BACKUP_DIR, and never falls back to dev DB.
    Verifies SQLite database integrity (PRAGMA integrity_check) on the backup copy independently.
    Purges older backup archives ONLY after a verified backup succeeds.
.PARAMETER InstallDir
    Application root directory. Default: C:\Apps\AI_Job_Application_Assistant.
.PARAMETER EnvFile
    Path to production environment file. Default: $InstallDir\.env.
.PARAMETER BackupDirOverride
    Optional destination override (validated against production configuration if supplied).
.PARAMETER RetentionDays
    Retention period for historical backups in days. Default: 30.
.PARAMETER PythonExe
    Path to Python 3.11 x64 executable. Auto-detected if omitted.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Apps\AI_Job_Application_Assistant",
    [string]$EnvFile = "",
    [string]$BackupDirOverride = "",
    [int]$RetentionDays = 30,
    [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"
Set-Location $InstallDir

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

# 2. Verify Production Environment File Exists
if (-not $EnvFile) {
    $EnvFile = Join-Path $InstallDir ".env"
}

if (-not (Test-Path $EnvFile)) {
    Write-Error "CRITICAL: Production environment file '$EnvFile' not found. Database backup aborted to prevent dev fallback."
    exit 1
}

$ResolvedEnvFile = (Resolve-Path $EnvFile).Path
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " AI Job Application Assistant - Production Database Backup" -ForegroundColor Cyan
Write-Host " Environment File: $ResolvedEnvFile" -ForegroundColor Cyan
Write-Host " Timestamp:        $timestamp" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 3. Execute Validated Atomic Online Backup via Python
$backupScript = @"
import os, sys, sqlite3
from pathlib import Path

# Step 1: Explicitly load production environment
from src.config.env_loader import load_production_env, validate_production_configuration
env_path = r'$ResolvedEnvFile'
load_production_env(env_path)

# Step 2: Require APP_ENV == 'production'
app_env = os.environ.get("APP_ENV", "").strip().lower()
if app_env != "production":
    print(f"CRITICAL: Backup requires APP_ENV=production, got '{app_env}'. Aborting.", file=sys.stderr)
    sys.exit(1)

# Step 3: Run full production configuration preflight validation
try:
    report = validate_production_configuration(enforce=True)
except Exception as exc:
    print(f"CRITICAL: Production configuration validation failed: {exc}", file=sys.stderr)
    sys.exit(1)

# Step 4: Resolve and verify DATABASE_PATH
source_db = os.environ.get("DATABASE_PATH")
if not source_db:
    print("CRITICAL: DATABASE_PATH is not configured in environment.", file=sys.stderr)
    sys.exit(1)

source_path = Path(source_db)
if not source_path.exists():
    print(f"CRITICAL: Source database '{source_db}' does not exist on disk.", file=sys.stderr)
    sys.exit(1)

# Step 5: Resolve effective BACKUP_DIR
env_backup_dir = os.environ.get("BACKUP_DIR")
if not env_backup_dir:
    print("CRITICAL: BACKUP_DIR is not configured in environment.", file=sys.stderr)
    sys.exit(1)

backup_dir_override = r'$BackupDirOverride'.strip()
effective_backup_dir = backup_dir_override if backup_dir_override else env_backup_dir
dest_dir_path = Path(effective_backup_dir)

try:
    dest_dir_path.mkdir(parents=True, exist_ok=True)
except Exception as exc:
    print(f"CRITICAL: Cannot access or create backup directory '{effective_backup_dir}': {exc}", file=sys.stderr)
    sys.exit(1)

# Step 6: Perform atomic online backup using DatabaseManager
from src.database.db_manager import DatabaseManager
db = DatabaseManager(db_path=str(source_path))

if str(db.db_path) != str(source_path):
    print(f"CRITICAL: DatabaseManager resolved '{db.db_path}' which does not match DATABASE_PATH '{source_path}'.", file=sys.stderr)
    sys.exit(1)

target_backup_file = dest_dir_path / f"backup_job_assistant_{'$timestamp'}.db"
backup_path = db.backup_database(backup_path=str(target_backup_file))

# Step 7: Independent SQLite integrity check & verification
if not os.path.exists(backup_path):
    print(f"CRITICAL: Backup file was not created at '{backup_path}'.", file=sys.stderr)
    sys.exit(2)

backup_size = os.path.getsize(backup_path)
if backup_size <= 0:
    print(f"CRITICAL: Backup file '{backup_path}' is empty (0 bytes).", file=sys.stderr)
    sys.exit(2)

conn = sqlite3.connect(backup_path)
cursor = conn.cursor()
cursor.execute("PRAGMA integrity_check")
status = cursor.fetchone()[0]
conn.close()

if status != "ok":
    print(f"CRITICAL: INTEGRITY_CHECK_FAILED: SQLite PRAGMA integrity_check failed on backup copy: {status}", file=sys.stderr)
    sys.exit(2)

print(f"SOURCE_DATABASE:{source_path}")
print(f"EFFECTIVE_BACKUP_DIR:{dest_dir_path}")
print(f"BACKUP_VERIFIED_SUCCESS:{backup_path}")
"@

$result = & $PythonExe -c $backupScript 2>&1
if ($LASTEXITCODE -ne 0 -or $result -notmatch "BACKUP_VERIFIED_SUCCESS:(?<path>.+)") {
    Write-Error "CRITICAL: Database backup or integrity verification failed! Retention cleanup aborted.`n$result"
    exit 1
}

$verifiedBackupPath = $Matches['path'].Trim()
Write-Host $result -ForegroundColor Green

# 4. Resolve Effective Backup Directory for Retention Cleanup
$effectiveDir = ""
if ($result -match "EFFECTIVE_BACKUP_DIR:(?<dir>.+)") {
    $effectiveDir = $Matches['dir'].Trim()
}

# 5. Retention Cleanup: ONLY executed after successful, verified backup
if ($effectiveDir -and (Test-Path $effectiveDir)) {
    Write-Host "Cleaning historical backups older than $RetentionDays days in $effectiveDir..." -ForegroundColor Yellow
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -Path $effectiveDir -Filter "*.db" | Where-Object { 
        $_.LastWriteTime -lt $cutoff -and $_.FullName -ne $verifiedBackupPath 
    } | ForEach-Object {
        Write-Host "Purging expired backup: $($_.Name)" -ForegroundColor Gray
        Remove-Item $_.FullName -Force
    }
}

Write-Host "======================================================================" -ForegroundColor Green
Write-Host " [SUCCESS] Verified production database backup completed!" -ForegroundColor Green
Write-Host " Backup Archive: $verifiedBackupPath" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green

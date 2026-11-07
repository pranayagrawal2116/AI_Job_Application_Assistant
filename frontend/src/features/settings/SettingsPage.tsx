import React, { useState } from 'react';
import { useAuth } from '@/features/auth/AuthContext';
import { api } from '@/lib/api';
import { useNavigate } from 'react-router-dom';
import {
  User,
  Database,
  Download,
  LogOut,
  CheckCircle2,
  HardDrive,
} from 'lucide-react';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';

export const SettingsPage: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [isBackingUp, setIsBackingUp] = useState(false);
  const [backupMsg, setBackupMsg] = useState<string | null>(null);

  const [isExporting, setIsExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  const handleBackup = async () => {
    setIsBackingUp(true);
    setBackupMsg(null);
    try {
      const res = await api.createBackup();
      setBackupMsg(`Live backup snapshot created at: ${res.backup_path}`);
    } catch (e: any) {
      setBackupMsg(`Backup failed: ${e.message}`);
    } finally {
      setIsBackingUp(false);
    }
  };

  const handleExportCsv = async () => {
    setIsExporting(true);
    setExportMsg(null);
    try {
      const blob = await api.exportCsv();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `opportunities_export_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setExportMsg('Export file downloaded successfully.');
    } catch (e: any) {
      setExportMsg(`Export failed: ${e.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-fade-in">
      <div>
        <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Account & System Settings</h1>
        <p className="text-xs text-slate-500 mt-1">
          Manage your candidate credentials, data storage backups, and active session.
        </p>
      </div>

      {/* 1. Account Profile */}
      <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-brand-50 text-brand-600 flex items-center justify-center">
            <User size={20} />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">Candidate Identity</h3>
            <p className="text-xs text-slate-500">Your authenticated account information</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
          <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Full Legal Name
            </span>
            <span className="text-xs font-bold text-slate-800 mt-1 block">
              {user?.full_name || 'Candidate'}
            </span>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Registered Email
            </span>
            <span className="text-xs font-bold text-slate-800 mt-1 block">{user?.email}</span>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              User ID #
            </span>
            <span className="text-xs font-bold text-slate-800 mt-1 block">{user?.id}</span>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Security Boundary
            </span>
            <span className="text-xs font-bold text-emerald-700 mt-1 block">
              Argon2id + HMAC Verified
            </span>
          </div>
        </div>
      </div>

      {/* 2. Database & Data Storage */}
      <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center">
            <Database size={20} />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">Data Storage & Audit Exports</h3>
            <p className="text-xs text-slate-500">Atomic live backup and CSV data export</p>
          </div>
        </div>

        {backupMsg && (
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 flex items-center gap-2">
            <CheckCircle2 size={15} className="text-emerald-600 shrink-0" />
            <span className="truncate">{backupMsg}</span>
          </div>
        )}

        {exportMsg && (
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 flex items-center gap-2">
            <CheckCircle2 size={15} className="text-emerald-600 shrink-0" />
            <span className="truncate">{exportMsg}</span>
          </div>
        )}

        <div className="flex flex-col sm:flex-row gap-3 pt-2">
          <button
            onClick={handleBackup}
            disabled={isBackingUp}
            className="flex-1 py-3 px-4 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
          >
            {isBackingUp ? (
              <LoadingSpinner size={14} />
            ) : (
              <HardDrive size={15} className="text-slate-600" />
            )}
            <span>Create Atomic SQLite Backup</span>
          </button>

          <button
            onClick={handleExportCsv}
            disabled={isExporting}
            className="flex-1 py-3 px-4 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
          >
            {isExporting ? (
              <LoadingSpinner size={14} />
            ) : (
              <Download size={15} className="text-slate-600" />
            )}
            <span>Export Catalog to CSV</span>
          </button>
        </div>
      </div>

      {/* 3. Session & Sign Out */}
      <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-slate-900">Active Candidate Session</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Revoke all active action tickets and sign out on this browser.
          </p>
        </div>
        <button
          onClick={handleLogout}
          className="px-5 py-2.5 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 font-semibold text-xs border border-rose-200 flex items-center gap-2 transition-colors"
        >
          <LogOut size={15} />
          <span>Sign Out</span>
        </button>
      </div>
    </div>
  );
};

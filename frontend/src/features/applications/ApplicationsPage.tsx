import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '@/lib/api';
import { ApplicationItem, FollowUpItem } from '@/types';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Modal } from '@/components/common/Modal';
import { getStatusBadgeColor } from '@/lib/utils';
import {
  Kanban,
  List as ListIcon,
  Search,
  Building2,
  ArrowRight,
  Plus,
  Bell,
  MapPin,
  CheckCircle2,
} from 'lucide-react';

export const ApplicationsPage: React.FC = () => {
  const [viewMode, setViewMode] = useState<'kanban' | 'list'>('kanban');
  const [applications, setApplications] = useState<ApplicationItem[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Follow-up modal state
  const [activeAppForFollowUp, setActiveAppForFollowUp] = useState<ApplicationItem | null>(null);
  const [followUps, setFollowUps] = useState<FollowUpItem[]>([]);
  const [newFuType, setNewFuType] = useState('STATUS_INQUIRY');
  const [newFuDate, setNewFuDate] = useState('');
  const [newFuNotes, setNewFuNotes] = useState('');
  const [isCreatingFu, setIsCreatingFu] = useState(false);

  const fetchApps = async () => {
    setIsLoading(true);
    try {
      const data = await api.getApplications();
      setApplications(data);
    } catch (e) {
      console.error('Failed to fetch applications:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const openFollowUpModal = async (app: ApplicationItem) => {
    setActiveAppForFollowUp(app);
    try {
      const fus = await api.getFollowUps(app.id);
      setFollowUps(fus);
    } catch (e) {
      console.error('Failed to get follow-ups:', e);
    }
  };

  const handleCreateFollowUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeAppForFollowUp || !newFuDate) return;
    setIsCreatingFu(true);
    try {
      await api.createFollowUp(activeAppForFollowUp.id, {
        follow_up_type: newFuType,
        scheduled_date: newFuDate,
        notes: newFuNotes,
      });
      const fus = await api.getFollowUps(activeAppForFollowUp.id);
      setFollowUps(fus);
      setNewFuNotes('');
      setNewFuDate('');
    } catch (e) {
      console.error('Failed to create follow-up:', e);
    } finally {
      setIsCreatingFu(false);
    }
  };

  const filteredApps = applications.filter((app) => {
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    return (
      app.company_name.toLowerCase().includes(q) ||
      app.job_title.toLowerCase().includes(q) ||
      (app.location && app.location.toLowerCase().includes(q))
    );
  });

  const columns = [
    { title: 'Draft / Saved', statuses: ['DRAFT', 'Saved', 'Discovered'] },
    { title: 'Preparing', statuses: ['PREPARING', 'Preparing', 'Under Review'] },
    { title: 'Ready for Review', statuses: ['READY_FOR_REVIEW', 'Ready for Review', 'Application Prepared'] },
    { title: 'Approved', statuses: ['APPROVED', 'Approved', 'Awaiting Approval'] },
    { title: 'Submitted', statuses: ['SUBMITTED', 'Applied', 'In Progress', 'IN_PROGRESS'] },
    { title: 'Interview / Offer', statuses: ['INTERVIEW', 'Interview', 'ASSESSMENT', 'OFFER'] },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
            Application Tracker
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Manage your opportunities, prepare tailored application packets, and confirm portal submissions.
          </p>
        </div>

        {/* View Switcher & Action */}
        <div className="flex items-center gap-3">
          <div className="flex items-center p-1 rounded-2xl bg-slate-200/60">
            <button
              onClick={() => setViewMode('kanban')}
              className={`p-1.5 rounded-xl transition-all ${
                viewMode === 'kanban' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500'
              }`}
              title="Kanban Board View"
            >
              <Kanban size={16} />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-1.5 rounded-xl transition-all ${
                viewMode === 'list' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500'
              }`}
              title="Table List View"
            >
              <ListIcon size={16} />
            </button>
          </div>

          <Link
            to="/jobs"
            className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all"
          >
            <Plus size={15} />
            <span>New Application</span>
          </Link>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative max-w-md">
        <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter applications by company or title..."
          className="w-full pl-9 pr-4 py-2 rounded-xl border border-slate-200 bg-white text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
        />
      </div>

      {isLoading ? (
        <div className="py-20 flex justify-center">
          <LoadingSpinner size={32} />
        </div>
      ) : filteredApps.length === 0 ? (
        <div className="py-16 text-center text-slate-400 bg-white rounded-3xl border border-slate-200">
          <Building2 size={36} className="mx-auto mb-2 text-slate-300" />
          <p className="text-sm font-bold text-slate-700">No applications found</p>
          <p className="text-xs text-slate-400 mt-1">
            Explore jobs and click "Start Application" to begin tracking.
          </p>
        </div>
      ) : viewMode === 'kanban' ? (
        /* KANBAN VIEW */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 items-start overflow-x-auto pb-4">
          {columns.map((col) => {
            const appsInCol = filteredApps.filter((a) =>
              col.statuses.some((s) => s.toLowerCase() === a.status.toLowerCase())
            );
            return (
              <div
                key={col.title}
                className="bg-slate-100/70 rounded-2xl p-3 border border-slate-200/60 flex flex-col min-w-[220px]"
              >
                <div className="flex items-center justify-between mb-3 px-1">
                  <span className="text-xs font-bold text-slate-700">{col.title}</span>
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-white text-slate-600 shadow-2xs">
                    {appsInCol.length}
                  </span>
                </div>

                <div className="space-y-2.5">
                  {appsInCol.map((app) => (
                    <div
                      key={app.id}
                      className="bg-white rounded-xl p-3.5 border border-slate-200/80 shadow-2xs hover:shadow-sm transition-all space-y-2"
                    >
                      <div>
                        <h4 className="text-xs font-bold text-slate-900 line-clamp-1">
                          {app.job_title}
                        </h4>
                        <p className="text-[11px] font-medium text-slate-500 mt-0.5 flex items-center gap-1">
                          <Building2 size={11} className="text-slate-400" />
                          <span>{app.company_name}</span>
                        </p>
                      </div>

                      {app.location && (
                        <div className="flex items-center gap-1 text-[10px] text-slate-400">
                          <MapPin size={10} />
                          <span>{app.location}</span>
                        </div>
                      )}

                      <div className="pt-2 border-t border-slate-100 flex items-center justify-between gap-1">
                        <button
                          onClick={() => openFollowUpModal(app)}
                          className="p-1 rounded-lg text-slate-400 hover:text-brand-600 hover:bg-brand-50 transition-colors"
                          title="Follow-up Reminders"
                        >
                          <Bell size={13} />
                        </button>
                        <Link
                          to={`/applications/${app.id}/prepare`}
                          className="px-2.5 py-1 rounded-lg bg-brand-50 hover:bg-brand-100 text-brand-700 font-bold text-[10px] border border-brand-200 flex items-center gap-1 transition-colors"
                        >
                          <span>Prepare</span>
                          <ArrowRight size={10} />
                        </Link>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* TABLE LIST VIEW */
        <div className="bg-white rounded-3xl border border-slate-200/80 shadow-sm overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-medium">
              <tr>
                <th className="py-3 px-4 font-semibold">Company & Role</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold">Location</th>
                <th className="py-3 px-4 font-semibold">Created</th>
                <th className="py-3 px-4 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredApps.map((app) => (
                <tr key={app.id} className="hover:bg-slate-50/60 transition-colors">
                  <td className="py-3.5 px-4">
                    <p className="font-bold text-slate-900">{app.job_title}</p>
                    <p className="text-[11px] text-slate-500">{app.company_name}</p>
                  </td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${getStatusBadgeColor(
                        app.status
                      )}`}
                    >
                      {app.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-500">{app.location || 'Remote'}</td>
                  <td className="py-3.5 px-4 text-slate-400">
                    {app.created_at ? new Date(app.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td className="py-3.5 px-4 text-right space-x-2">
                    <button
                      onClick={() => openFollowUpModal(app)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors inline-flex align-middle"
                      title="Follow-up Reminders"
                    >
                      <Bell size={14} />
                    </button>
                    <Link
                      to={`/applications/${app.id}/prepare`}
                      className="px-3 py-1.5 rounded-xl bg-brand-50 hover:bg-brand-100 text-brand-700 font-semibold text-xs border border-brand-200 transition-colors inline-flex align-middle"
                    >
                      Prepare
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* FOLLOW-UP REMINDERS MODAL */}
      {activeAppForFollowUp && (
        <Modal
          isOpen={!!activeAppForFollowUp}
          onClose={() => setActiveAppForFollowUp(null)}
          title="Candidate Follow-up Reminders"
          description={`Scheduled check-ins for ${activeAppForFollowUp.job_title} at ${activeAppForFollowUp.company_name}`}
        >
          <div className="space-y-4">
            {/* New reminder form */}
            <form onSubmit={handleCreateFollowUp} className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-3">
              <h4 className="text-xs font-bold text-slate-900">Schedule Reminder</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                    Follow-up Action
                  </label>
                  <select
                    value={newFuType}
                    onChange={(e) => setNewFuType(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs bg-white focus:outline-none"
                  >
                    <option value="STATUS_INQUIRY">Status Inquiry</option>
                    <option value="THANK_YOU_NOTE">Thank You Note</option>
                    <option value="RECRUITER_CHECKIN">Recruiter Check-in</option>
                    <option value="PORTFOLIO_UPDATE">Portfolio Update</option>
                    <option value="PHONE_CALL">Phone Call</option>
                    <option value="OTHER">Other</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                    Target Date
                  </label>
                  <input
                    type="date"
                    required
                    value={newFuDate}
                    onChange={(e) => setNewFuDate(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs bg-white focus:outline-none"
                  />
                </div>
              </div>
              <div>
                <input
                  type="text"
                  placeholder="Notes or questions for recruiter..."
                  value={newFuNotes}
                  onChange={(e) => setNewFuNotes(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs bg-white focus:outline-none"
                />
              </div>
              <button
                type="submit"
                disabled={isCreatingFu}
                className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Plus size={13} />
                <span>{isCreatingFu ? 'Scheduling...' : 'Add Reminder'}</span>
              </button>
            </form>

            {/* Existing follow-ups */}
            <div>
              <h4 className="text-xs font-bold text-slate-900 mb-2">Scheduled Reminders ({followUps.length})</h4>
              {followUps.length === 0 ? (
                <p className="text-xs text-slate-400 py-2">No follow-ups scheduled yet.</p>
              ) : (
                <div className="space-y-2">
                  {followUps.map((fu) => (
                    <div
                      key={fu.id}
                      className="p-3 rounded-xl bg-white border border-slate-200 flex items-center justify-between text-xs"
                    >
                      <div>
                        <span className="font-bold text-slate-800">{fu.follow_up_type}</span>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Scheduled: {fu.scheduled_date} {fu.outcome_notes && `• ${fu.outcome_notes}`}
                        </p>
                      </div>
                      {fu.is_completed ? (
                        <span className="text-[11px] font-semibold text-emerald-700 flex items-center gap-1">
                          <CheckCircle2 size={12} />
                          Done
                        </span>
                      ) : (
                        <span className="text-[11px] font-semibold text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-200">
                          Pending
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

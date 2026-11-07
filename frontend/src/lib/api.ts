import {
  AuthResponse,
  CandidateProfile,
  DashboardSummary,
  DiscoveryStatus,
  InferredRole,
  JobItem,
  JobMatchExplanation,
  ResumeItem,
  ApplicationItem,
  FollowUpItem,
  User,
} from '@/types';

function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
  return match ? decodeURIComponent(match[3]) : null;
}

class ApiClient {
  private baseUrl: string = '/api';

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers || {});
    const method = (options.method || 'GET').toUpperCase();

    // Attach CSRF protection token on mutating requests
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrfToken = getCookie('csrf_token');
      if (csrfToken) {
        headers.set('X-CSRF-Token', csrfToken);
      }
    }

    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const config: RequestInit = {
      ...options,
      headers,
      credentials: 'include', // Automatically send and receive HttpOnly session cookies
    };

    const response = await fetch(`${this.baseUrl}${endpoint}`, config);

    if (!response.ok) {
      let errorMsg = `Error ${response.status}: ${response.statusText}`;
      try {
        const errorJson = await response.json();
        errorMsg = errorJson.detail || errorJson.message || errorMsg;
      } catch (e) {
        // Ignored
      }
      throw new Error(errorMsg);
    }

    return response.json() as Promise<T>;
  }

  // Auth endpoints
  async register(data: { email: string; password: string; full_name: string; profession_industry?: string }): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async login(data: { email: string; password: string }): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async logout(): Promise<void> {
    await this.request('/auth/logout', { method: 'POST' });
  }

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Dashboard
  async getDashboardSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>('/dashboard/summary');
  }

  // Profile
  async getProfile(): Promise<{ user_id: number; profile_data: CandidateProfile; version: number }> {
    return this.request('/profile');
  }

  async updateProfile(profile_data: CandidateProfile): Promise<any> {
    return this.request('/profile', {
      method: 'PUT',
      body: JSON.stringify({ profile_data }),
    });
  }

  async getResumes(): Promise<ResumeItem[]> {
    return this.request<ResumeItem[]>('/profile/resumes');
  }

  async uploadResume(file: File): Promise<ResumeItem> {
    const formData = new FormData();
    formData.append('file', file);
    return this.request<ResumeItem>('/profile/resumes', {
      method: 'POST',
      body: formData,
    });
  }

  async setPrimaryResume(resumeId: number): Promise<any> {
    return this.request(`/profile/resumes/${resumeId}/primary`, { method: 'POST' });
  }

  async deleteResume(resumeId: number): Promise<any> {
    return this.request(`/profile/resumes/${resumeId}`, { method: 'DELETE' });
  }

  async syncProfileWithResume(resumeId: number): Promise<any> {
    return this.request(`/profile/resumes/${resumeId}/sync`, { method: 'POST' });
  }

  // Jobs
  async getJobs(params?: {
    search?: string;
    arrangement?: string;
    platform?: string;
    min_score?: number;
    only_eligible?: boolean;
    saved_only?: boolean;
    recommended_only?: boolean;
  }): Promise<JobItem[]> {
    const q = new URLSearchParams();
    if (params?.search) q.set('search', params.search);
    if (params?.arrangement) q.set('arrangement', params.arrangement);
    if (params?.platform) q.set('platform', params.platform);
    if (params?.min_score !== undefined) q.set('min_score', params.min_score.toString());
    if (params?.only_eligible !== undefined) q.set('only_eligible', params.only_eligible.toString());
    if (params?.saved_only) q.set('saved_only', 'true');
    if (params?.recommended_only) q.set('recommended_only', 'true');

    const queryStr = q.toString() ? `?${q.toString()}` : '';
    return this.request<JobItem[]>(`/jobs${queryStr}`);
  }

  async getJob(id: number): Promise<JobItem> {
    return this.request<JobItem>(`/jobs/${id}`);
  }

  async getJobMatchExplanation(jobId: number): Promise<JobMatchExplanation> {
    return this.request<JobMatchExplanation>(`/jobs/${jobId}/match-explanation`);
  }

  async toggleShortlist(jobId: number): Promise<{ status: string; is_shortlisted: boolean; message: string }> {
    return this.request(`/jobs/${jobId}/shortlist`, { method: 'POST' });
  }

  // Candidate Discovery & Recommendations
  async triggerDiscovery(roles?: string[], locations?: string[]): Promise<{ status: string; message: string; run_id?: number }> {
    return this.request('/discovery/trigger', {
      method: 'POST',
      body: JSON.stringify({ roles, locations }),
    });
  }

  async getDiscoveryStatus(): Promise<DiscoveryStatus> {
    return this.request<DiscoveryStatus>('/discovery/status');
  }

  async getSuggestedRoles(): Promise<{ suggested_roles: InferredRole[]; suggested_locations: string[] }> {
    return this.request('/discovery/suggested-roles');
  }

  async updateSearchPreferences(prefs: {
    target_roles: string[];
    target_locations: string[];
    auto_discover_enabled?: boolean;
  }): Promise<{ message: string; preferences: any }> {
    return this.request('/discovery/preferences', {
      method: 'POST',
      body: JSON.stringify(prefs),
    });
  }

  async ingestJobText(data: { raw_text: string; hint_title?: string; hint_company?: string; hint_location?: string }): Promise<any> {
    return this.request('/jobs/ingest/text', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async ingestJobFile(file: File, hintTitle?: string, hintCompany?: string): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    if (hintTitle) formData.append('hint_title', hintTitle);
    if (hintCompany) formData.append('hint_company', hintCompany);
    return this.request('/jobs/ingest/file', {
      method: 'POST',
      body: formData,
    });
  }

  async ingestJobUrl(url: string): Promise<any> {
    return this.request('/jobs/ingest/url', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  // Applications
  async getApplications(statusFilter?: string): Promise<ApplicationItem[]> {
    const q = statusFilter ? `?status_filter=${encodeURIComponent(statusFilter)}` : '';
    return this.request<ApplicationItem[]>(`/applications${q}`);
  }

  async createApplication(data: { company_name?: string; job_title?: string; job_id?: number; job_description_id?: number; resume_id?: number }): Promise<ApplicationItem> {
    return this.request<ApplicationItem>('/applications', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getApplication(id: number): Promise<ApplicationItem> {
    return this.request<ApplicationItem>(`/applications/${id}`);
  }

  async updateApplicationStatus(id: number, status: string, notes?: string): Promise<ApplicationItem> {
    return this.request<ApplicationItem>(`/applications/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
  }

  async getPreparationState(id: number): Promise<any> {
    return this.request(`/applications/${id}/preparation-state`);
  }

  async tailorResume(
    id: number,
    dataOrInstructions?: string | { resume_id?: number; custom_instructions?: string; template?: string },
    resumeId?: number
  ): Promise<any> {
    let body: any = {};
    if (typeof dataOrInstructions === 'string') {
      body = { custom_instructions: dataOrInstructions, resume_id: resumeId };
    } else if (dataOrInstructions) {
      body = dataOrInstructions;
    }
    return this.request(`/applications/${id}/tailor-resume`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async generateCoverLetter(
    id: number,
    dataOrTone?: string | { tone?: string; custom_instructions?: string; resume_id?: number },
    resumeId?: number
  ): Promise<any> {
    let body: any = {};
    if (typeof dataOrTone === 'string') {
      body = { tone: dataOrTone, resume_id: resumeId };
    } else if (dataOrTone) {
      body = dataOrTone;
    }
    return this.request(`/applications/${id}/cover-letter`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async answerScreeningQuestions(
    id: number,
    data?: { questions?: any[]; resume_id?: number }
  ): Promise<any> {
    return this.request(`/applications/${id}/screening-qa`, {
      method: 'POST',
      body: JSON.stringify(data || {}),
    });
  }

  async getLatestPacket(id: number): Promise<any> {
    return this.request(`/applications/${id}/packets/latest`);
  }

  async issueApprovalTicket(id: number): Promise<{ ticket: string; packet_hash: string }> {
    return this.request(`/applications/${id}/tickets/approval`, { method: 'POST' });
  }

  async approvePacket(id: number, data: { approver_name: string; action_ticket: string; candidate_confirmed: boolean }): Promise<any> {
    return this.request(`/applications/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async issueSubmissionTicket(id: number): Promise<{ ticket: string; packet_hash: string }> {
    return this.request(`/applications/${id}/tickets/submission`, { method: 'POST' });
  }

  async confirmSubmission(id: number, data: {
    submission_ticket: string;
    candidate_confirmed: boolean;
    submission_channel?: string;
    confirmation_reference?: string;
    candidate_notes?: string;
  }): Promise<any> {
    return this.request(`/applications/${id}/confirm-submission`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getTimeline(id: number): Promise<any> {
    return this.request(`/applications/${id}/timeline`);
  }

  async getFollowUps(id: number): Promise<FollowUpItem[]> {
    return this.request<FollowUpItem[]>(`/applications/${id}/followups`);
  }

  async createFollowUp(id: number, data: { follow_up_type: string; scheduled_date: string; notes?: string }): Promise<FollowUpItem> {
    return this.request<FollowUpItem>(`/applications/${id}/followups`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Matching
  async evaluateMatch(data: {
    resume_id: number;
    job_id?: number;
    job_description_id?: number;
    scoring_profile?: string;
  }): Promise<any> {
    return this.request('/matching/evaluate', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getScoringProfiles(): Promise<{ profiles: Record<string, string> }> {
    return this.request('/matching/profiles');
  }

  async getMatchHistory(jobId?: number, jobDescriptionId?: number): Promise<any[]> {
    const params = new URLSearchParams();
    if (jobId) params.set('job_id', String(jobId));
    if (jobDescriptionId) params.set('job_description_id', String(jobDescriptionId));
    return this.request(`/matching/history?${params.toString()}`);
  }

  // Application Preparation & Documents
  async prepareApplicationPacket(id: number): Promise<any> {
    return this.request(`/applications/${id}/prepare-packet`, {
      method: 'POST',
    });
  }

  async downloadDocument(appId: number, docType: string, docFormat: string): Promise<Blob> {
    const response = await fetch(`${this.baseUrl}/applications/${appId}/documents/${docType}/${docFormat}`, {
      method: 'GET',
      credentials: 'include',
    });
    if (!response.ok) {
      let msg = `Download failed: ${response.statusText}`;
      try {
        const err = await response.json();
        msg = err.detail || msg;
      } catch (e) {}
      throw new Error(msg);
    }
    return response.blob();
  }

  // Settings
  async createBackup(): Promise<any> {
    return this.request('/settings/backup', { method: 'POST' });
  }

  async exportCsv(): Promise<Blob> {
    const response = await fetch(`${this.baseUrl}/settings/export/csv`, {
      method: 'GET',
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(`Export failed: ${response.statusText}`);
    }
    return response.blob();
  }
}

export const api = new ApiClient();

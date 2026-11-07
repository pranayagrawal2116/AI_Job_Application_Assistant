import {
  AuthResponse,
  CandidateProfile,
  DashboardSummary,
  JobItem,
  ResumeItem,
  ApplicationItem,
  FollowUpItem,
  User,
} from '@/types';

class ApiClient {
  private baseUrl: string = '/api';

  private getToken(): string | null {
    return localStorage.getItem('auth_token');
  }

  public setToken(token: string | null) {
    if (token) {
      localStorage.setItem('auth_token', token);
    } else {
      localStorage.removeItem('auth_token');
    }
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers = new Headers(options.headers || {});

    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const config: RequestInit = {
      ...options,
      headers,
      credentials: 'include', // Send cookies for HttpOnly session
    };

    const response = await fetch(`${this.baseUrl}${endpoint}`, config);

    if (response.status === 401) {
      this.setToken(null);
      // Let caller handle or redirect to login
    }

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
    const res = await this.request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (res.session_id) {
      this.setToken(res.session_id);
    }
    return res;
  }

  async login(data: { email: string; password: string }): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (res.session_id) {
      this.setToken(res.session_id);
    }
    return res;
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.setToken(null);
    }
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
  }): Promise<JobItem[]> {
    const q = new URLSearchParams();
    if (params?.search) q.set('search', params.search);
    if (params?.arrangement) q.set('arrangement', params.arrangement);
    if (params?.platform) q.set('platform', params.platform);
    if (params?.min_score !== undefined) q.set('min_score', params.min_score.toString());
    if (params?.only_eligible !== undefined) q.set('only_eligible', params.only_eligible.toString());
    if (params?.saved_only) q.set('saved_only', 'true');

    const queryStr = q.toString() ? `?${q.toString()}` : '';
    return this.request<JobItem[]>(`/jobs${queryStr}`);
  }

  async getJob(id: number): Promise<JobItem> {
    return this.request<JobItem>(`/jobs/${id}`);
  }

  async toggleShortlist(jobId: number): Promise<{ status: string; is_shortlisted: boolean; message: string }> {
    return this.request(`/jobs/${jobId}/shortlist`, { method: 'POST' });
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

  async tailorResume(id: number, customInstructions?: string, resumeId?: number): Promise<any> {
    return this.request(`/applications/${id}/tailor-resume`, {
      method: 'POST',
      body: JSON.stringify({ custom_instructions: customInstructions, resume_id: resumeId }),
    });
  }

  async generateCoverLetter(id: number, tone?: string): Promise<any> {
    return this.request(`/applications/${id}/cover-letter`, {
      method: 'POST',
      body: JSON.stringify({ tone }),
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

  // Settings
  async createBackup(): Promise<any> {
    return this.request('/settings/backup', { method: 'POST' });
  }

  async exportCsv(): Promise<any> {
    return this.request('/settings/export/csv');
  }
}

export const api = new ApiClient();

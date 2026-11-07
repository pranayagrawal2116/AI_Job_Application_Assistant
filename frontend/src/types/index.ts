export interface User {
  id: number;
  email: string;
  full_name: string;
  profession_industry?: string;
  created_at?: string;
}

export interface AuthResponse {
  user: User;
  session_id: string;
  token?: string;
  message?: string;
}

export interface DashboardSummary {
  profile_completeness: number;
  resume_count: number;
  total_opportunities: number;
  eligible_opportunities: number;
  saved_count: number;
  preparing_count: number;
  review_count: number;
  submitted_count: number;
  interview_count: number;
  pending_follow_ups: number;
  recommended_action: {
    title: string;
    description: string;
    cta_label: string;
    cta_url: string;
  };
}

export interface JobItem {
  id: number;
  company_name: string;
  job_title: string;
  job_description: string;
  job_url: string;
  location: string;
  stipend: string;
  required_skills: string[];
  eligibility_criteria?: string;
  application_deadline?: string;
  match_score: number;
  match_classification: string;
  is_eligible: boolean;
  platform: string;
  work_arrangement: string;
  internship_duration: string;
  is_shortlisted: boolean;
  source: string;
  matching_skills?: string[];
  missing_skills?: string[];
  match_explanation?: string;
  score_breakdown?: Record<string, any>;
}

export interface ResumeItem {
  id: number;
  user_id: number;
  original_filename: string;
  file_format: string;
  file_size_bytes: number;
  file_hash: string;
  is_primary: boolean;
  upload_date?: string;
  created_at?: string;
  sync_status?: string;
  sync_error?: string;
}

export interface CandidateProfile {
  personal_info?: {
    full_name?: string;
    email?: string;
    phone?: string;
    location?: string;
    linkedin?: string;
    github?: string;
    portfolio?: string;
    summary?: string;
  };
  personal?: {
    full_name?: string;
    email?: string;
    phone?: string;
    location?: string;
    linkedin?: string;
    github?: string;
    portfolio?: string;
    summary?: string;
  };
  education?: Array<{
    institution: string;
    degree: string;
    field_of_study?: string;
    major?: string;
    graduation_year?: number | string;
    expected_graduation_year?: number | string;
    cgpa?: number | string;
    current_cgpa?: number | string;
    percentage?: number | string;
    provenance?: string;
  }>;
  work_experience?: Array<{
    employer: string;
    job_title: string;
    start_date?: string;
    end_date?: string;
    is_current?: boolean;
    duration?: string;
    responsibilities?: string[];
    provenance?: string;
  }>;
  per_experience?: Array<{
    employer?: string;
    job_title?: string;
    role_name?: string;
    start_date?: string;
    end_date?: string;
    is_current?: boolean;
    duration?: string;
    responsibilities?: string[];
    supervisory_context?: string;
    provenance?: string;
  }>;
  technical_skills?: string[] | Record<string, string[]>;
  professional_skills?: string[];
  tools_and_software?: string[];
  languages?: string[];
  certifications?: Array<{
    name: string;
    issuer?: string;
    issue_date?: string;
    membership?: string;
    provenance?: string;
  }>;
  professional_qualifications?: Array<{
    name: string;
    issuer?: string;
    membership?: string;
    provenance?: string;
  }>;
  projects?: Array<{
    title?: string;
    name?: string;
    description?: string;
    technologies?: string[];
    deliverables?: string[];
    provenance?: string;
  }>;
  search_preferences?: {
    target_roles?: string[];
    target_locations?: string[];
    auto_discover_enabled?: boolean;
    suggested_roles?: InferredRole[];
  };
  preferences?: {
    target_roles?: string[];
    target_locations?: string[];
    auto_discover_enabled?: boolean;
  };
}

export interface InferredRole {
  role_title: string;
  evidence_sources: string[];
  supporting_skills: string[];
  confidence: number;
  is_candidate_selected?: boolean;
}

export interface DiscoveryRun {
  id: number;
  user_id: number;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PARTIAL';
  triggered_by?: string;
  target_roles?: string[];
  target_locations?: string[];
  jobs_discovered?: number;
  jobs_evaluated?: number;
  jobs_found?: number;
  jobs_saved?: number;
  duplicates_skipped?: number;
  errors_count?: number;
  error_message?: string;
  log_summary?: string;
  created_at: string;
  completed_at?: string;
}

export interface DiscoveryStatus {
  is_running: boolean;
  active_run?: DiscoveryRun | null;
  latest_run?: DiscoveryRun | null;
  suggested_roles: InferredRole[];
  target_roles: string[];
  target_locations: string[];
  auto_discover_enabled: boolean;
}

export interface JobMatchExplanation {
  job_id: number;
  company_name: string;
  job_title: string;
  is_evaluated?: boolean;
  match_score?: number | null;
  match_classification?: string;
  is_eligible?: boolean | null;
  eligibility_status?: string;
  score_breakdown?: Record<string, any>;
  matching_skills?: string[];
  missing_skills?: string[];
  explanation: string;
  disqualification_reasons?: string[];
}

export interface ApplicationItem {
  id: number;
  user_id: number;
  company_name: string;
  job_title: string;
  status: string;
  job_id?: number;
  job_description_id?: number;
  resume_id?: number;
  external_application_url?: string;
  target_role?: string;
  location?: string;
  application_deadline?: string;
  date_prepared?: string;
  date_submitted?: string;
  notes?: string;
  created_at?: string;
  updated_at?: string;
  is_archived?: boolean;
}

export interface FollowUpItem {
  id: number;
  application_id: number;
  user_id: number;
  follow_up_type: string;
  scheduled_date: string;
  is_completed: boolean;
  completed_at?: string;
  outcome_notes?: string;
}

export interface TimelineEvent {
  event_type: string;
  timestamp: string;
  details?: Record<string, any>;
  actor_type?: string;
  previous_event_hash?: string;
  event_hash?: string;
}

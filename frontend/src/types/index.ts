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
  };
  education?: Array<{
    institution: string;
    degree: string;
    field_of_study?: string;
    graduation_year?: number | string;
    cgpa?: number | string;
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
  technical_skills?: string[] | Record<string, string[]>;
  professional_skills?: string[];
  certifications?: Array<{
    name: string;
    issuer?: string;
    issue_date?: string;
    provenance?: string;
  }>;
  projects?: Array<{
    name: string;
    description?: string;
    technologies?: string[];
  }>;
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

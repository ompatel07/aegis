// TypeScript types mirroring the Go API response shapes exactly.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Pillar = "quality" | "security" | "deployment";
export type Engine = "semgrep" | "trivy" | "gitleaks" | "quality" | "deployment";
export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type Grade = "A" | "B" | "C" | "D" | "F";

// ── API envelopes ────────────────────────────────────────────────────────────
export interface ApiSuccess<T> {
  data: T;
  meta: { timestamp: string };
}

export interface Paginated<T> {
  data: T[];
  meta: { page: number; per_page: number; total: number; timestamp: string };
}

export interface ApiError {
  error: { code: string; message: string; details?: unknown };
}

// ── Domain models ────────────────────────────────────────────────────────────
export interface User {
  id: string;
  email: string;
  name: string;
  role: "user" | "admin";
  plan: "free" | "pro" | "enterprise";
  created_at: string;
  updated_at: string;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

export interface AuthResponse {
  user: User;
  tokens: TokenPair;
}

export interface Project {
  id: string;
  user_id: string;
  name: string;
  slug: string;
  description?: string;
  repo_url?: string;
  repo_type?: "github" | "gitlab" | "bitbucket" | "upload";
  default_branch: string;
  language?: string;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  trigger: "manual" | "webhook" | "scheduled";
  status: ScanStatus;
  branch?: string;
  commit_sha?: string;
  quality_score?: number;
  security_score?: number;
  deployment_score?: number;
  overall_score?: number;
  overall_grade?: Grade;
  quality_issues_total: number;
  security_issues_total: number;
  secrets_found: number;
  vulnerabilities_found: number;
  queued_at: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  error_message?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  pillar: Pillar;
  engine: Engine;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  title: string;
  description?: string;
  file_path: string;
  line_start?: number;
  line_end?: number;
  column_start?: number;
  column_end?: number;
  cwe_id?: string;
  cve_id?: string;
  owasp_category?: string;
  is_false_positive: boolean;
  is_suppressed: boolean;
  fix_suggestion?: string;
  metadata?: Record<string, unknown>;
  // Context-rich enrichment (Phase 2B).
  title_human?: string;
  impact?: string;
  risk_level?: "informational" | "low" | "medium" | "high" | "critical";
  remediation_action?: string;
  remediation_details?: string;
  estimated_effort?: "trivial" | "quick" | "moderate" | "significant";
  context_metadata?: Record<string, unknown>;
  false_positive_probability?: number;
  created_at: string;
}

export interface SeverityCount {
  pillar: Pillar;
  severity: Severity;
  count: number;
}

export interface ScanReport {
  scan: Scan;
  breakdown: SeverityCount[];
}

// ── Request payloads ─────────────────────────────────────────────────────────
export interface CreateProjectInput {
  name: string;
  description?: string;
  repo_url?: string;
  repo_type?: Project["repo_type"];
  default_branch?: string;
  language?: string;
}

export interface FindingFilters {
  pillar?: Pillar;
  severity?: Severity;
  engine?: Engine;
  page?: number;
  per_page?: number;
  include_suppressed?: boolean;
}

// ── GitHub integration ───────────────────────────────────────────────────────
export interface GithubIntegration {
  id: string;
  user_id: string;
  project_id: string;
  installation_id?: string;
  created_at: string;
}

export interface ConnectGitHubResult {
  integration: GithubIntegration;
  webhook_url: string;
  // Shown exactly once, at creation time.
  webhook_secret: string;
}

// ── Intelligence ─────────────────────────────────────────────────────────────
export interface SyncStatus {
  source: string;
  last_started_at?: string;
  last_completed_at?: string;
  last_status?: string;
  records_added: number;
  records_updated: number;
  next_sync?: string;
}

export interface IntelligenceStatus {
  sources: SyncStatus[];
  cve_counts: Record<string, number>;
  total_cves: number;
}

export interface Notification {
  id: string;
  project_id?: string;
  kind: string;
  title: string;
  body?: string;
  is_read: boolean;
  created_at: string;
}

// ── Custom rules ─────────────────────────────────────────────────────────────
export interface ProjectRule {
  id: string;
  project_id: string;
  name: string;
  rule_yaml: string;
  created_at: string;
}

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

// ── Notifications (Phase 2C TASK 7) ──────────────────────────────────────────
export interface NotificationSettings {
  email_enabled: boolean;
  email_scan_complete: boolean;
  email_new_critical: boolean;
  digest_frequency: "daily" | "weekly" | "never";
  severity_threshold: "critical" | "high" | "medium" | "all";
}

// ── GitHub App (Phase 2C TASK 1) ─────────────────────────────────────────────
export interface GHAppRepo {
  id: string;
  installation_id: number;
  full_name: string;
  default_branch?: string;
  enabled: boolean;
}

export interface GHAppInstallation {
  installation_id: number;
  account_login: string;
  account_type: string;
  repos: GHAppRepo[];
}

// ── Policies (Phase 2C TASK 8) ───────────────────────────────────────────────
export interface PolicyConfig {
  max_severity?: Severity;
  block_new_findings?: boolean;
  block_new_severity?: Severity;
  min_security_score?: number;
  min_quality_score?: number;
  min_ai_safety_score?: number;
  max_ai_generated_pct?: number;
}

export interface Policy {
  id: string;
  project_id: string;
  name: string;
  template?: string;
  config: PolicyConfig;
  is_active: boolean;
}

export interface PolicyCheck {
  rule: string;
  passed: boolean;
  detail: string;
}

export interface PolicyResult {
  passed: boolean;
  has_policy: boolean;
  policy_name?: string;
  checks: PolicyCheck[];
}

export type OrgRole = "owner" | "admin" | "member" | "viewer";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  billing_email?: string;
  plan: string;
  is_personal: boolean;
  created_at: string;
  updated_at: string;
}

export interface OrgMembership extends Organization {
  role: OrgRole;
}

export interface OrgMember {
  user_id: string;
  email: string;
  name?: string;
  role: OrgRole;
  joined_at: string;
}

export interface OrgInvitation {
  id: string;
  org_id: string;
  email: string;
  role: OrgRole;
  token: string;
  expires_at: string;
  accepted_at?: string;
  created_at: string;
}

export interface Project {
  id: string;
  user_id: string;
  organization_id?: string;
  name: string;
  slug: string;
  description?: string;
  repo_url?: string;
  repo_type?: "github" | "gitlab" | "bitbucket" | "upload";
  default_branch: string;
  language?: string;
  ai_fix_enabled: boolean;
  grandfather_mode: boolean;
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
  // Phase 2C: AI-generated-code analysis.
  ai_generated_pct?: number;
  ai_code_safety_score?: number;
  ai_code_report?: AICodeReport;
  created_at: string;
}

export interface AICodeIssue {
  rule_id: string;
  title: string;
  count: number;
}

export interface AICodeReport {
  files_scored: number;
  ai_file_count: number;
  ai_generated_pct: number;
  threshold: number;
  model_available: boolean;
  findings_in_ai_code: number;
  findings_in_human_code: number;
  ai_failure_mode_findings: number;
  safety_score: number;
  top_ai_issues: AICodeIssue[];
  top_signals: string[];
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
  // Phase 2C: AI-generated-code tagging.
  in_ai_generated_code?: boolean;
  ai_generated_probability?: number;
  // Phase 2C: deviates from the project baseline.
  is_new?: boolean;
  created_at: string;
}

// ── Project memory (Phase 2C TASK 4) ─────────────────────────────────────────
export interface BaselineRule {
  rule_id: string;
  engine?: string;
  avg_count_per_scan: number;
  typical_severity?: Severity;
  times_seen: number;
  is_grandfathered: boolean;
}

export interface RuleStat {
  rule_id: string;
  total_feedback: number;
  fp_count: number;
  confirmed_count: number;
  fp_rate: number;
}

export interface BaselineData {
  established: boolean;
  scan_count: number;
  grandfather_mode: boolean;
  profile?: { total_findings?: number; distinct_rules?: number; severity_breakdown?: Record<string, number> };
  rules: BaselineRule[];
  team_learning: RuleStat[];
}

export interface AICodePoint {
  date: string;
  pct: number;
  safety: number;
}

export interface AICodeMemory {
  scans_analyzed: number;
  first_seen?: string;
  current_pct: number;
  trend: "growing" | "shrinking" | "stable" | "none";
  avg_safety: number;
  series: AICodePoint[];
  persistent_files: string[];
  note: string;
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
  ai_fix_enabled?: boolean;
  grandfather_mode?: boolean;
  organization_id?: string;
}

export interface AISuggestion {
  suggestion: string;
  model: string;
  provider: string;
}

export interface ExecRiskItem {
  title: string;
  severity: Severity;
  impact?: string;
  file: string;
}

export interface ExecTrend {
  previous_grade: string;
  current_grade: string;
  overall_delta: number;
  security_delta: number;
  note: string;
}

export interface ExecAICode {
  ai_generated_pct: number;
  safety_score: number;
  findings_in_ai_code: number;
  top_issue?: string;
  note: string;
}

export interface ExecReport {
  project: string;
  scan: Scan;
  summary: string;
  top_risks: ExecRiskItem[];
  trend?: ExecTrend;
  priorities: string[];
  ai_code?: ExecAICode;
  generated_by: string;
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

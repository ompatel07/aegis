// Typed API client for the Aegis Go API. `createApi(token)` returns an object of
// typed methods; the access token is injected as a Bearer header.
import axios, { AxiosError, type AxiosInstance } from "axios";
import type {
  AISuggestion,
  AICodeMemory,
  ApiSuccess,
  BaselineData,
  ConnectGitHubResult,
  ExecReport,
  CreateProjectInput,
  Finding,
  FindingFilters,
  GithubIntegration,
  IntelligenceStatus,
  Notification,
  GHAppInstallation,
  NotificationSettings,
  Organization,
  OrgInvitation,
  OrgMember,
  OrgMembership,
  Paginated,
  Policy,
  PolicyConfig,
  PolicyResult,
  ProjectRule,
  Project,
  Scan,
  ScanReport,
} from "./types";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api/v1";

/** Normalize Axios errors into a plain Error carrying the API message. */
function normalizeError(err: unknown): never {
  const ax = err as AxiosError<{ error?: { message?: string; code?: string } }>;
  const message =
    ax.response?.data?.error?.message ||
    ax.message ||
    "Unexpected error contacting the API";
  throw new Error(message);
}

export function createApi(token?: string) {
  const http: AxiosInstance = axios.create({
    baseURL: BASE_URL,
    timeout: 20_000,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  return {
    // ── Projects ─────────────────────────────────────────────────────────────
    listProjects: (page = 1, perPage = 20) =>
      http
        .get<Paginated<Project>>("/projects", { params: { page, per_page: perPage } })
        .then((r) => r.data)
        .catch(normalizeError),

    createProject: (input: CreateProjectInput) =>
      http
        .post<ApiSuccess<Project>>("/projects", input)
        .then((r) => r.data.data)
        .catch(normalizeError),

    getProject: (id: string) =>
      http
        .get<ApiSuccess<Project>>(`/projects/${id}`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    updateProject: (id: string, input: CreateProjectInput) =>
      http
        .put<ApiSuccess<Project>>(`/projects/${id}`, input)
        .then((r) => r.data.data)
        .catch(normalizeError),

    deleteProject: (id: string) =>
      http.delete(`/projects/${id}`).then(() => undefined).catch(normalizeError),

    // ── Organizations (Phase 2C) ─────────────────────────────────────────────
    listOrgs: () =>
      http.get<ApiSuccess<OrgMembership[]>>("/organizations").then((r) => r.data.data).catch(normalizeError),

    createOrg: (body: { name: string; billing_email?: string }) =>
      http.post<ApiSuccess<Organization>>("/organizations", body).then((r) => r.data.data).catch(normalizeError),

    getOrg: (orgId: string) =>
      http.get<ApiSuccess<Organization>>(`/organizations/${orgId}`).then((r) => r.data.data).catch(normalizeError),

    updateOrg: (orgId: string, body: { name: string; billing_email?: string }) =>
      http.put<ApiSuccess<Organization>>(`/organizations/${orgId}`, body).then((r) => r.data.data).catch(normalizeError),

    listMembers: (orgId: string) =>
      http.get<ApiSuccess<OrgMember[]>>(`/organizations/${orgId}/members`).then((r) => r.data.data).catch(normalizeError),

    setMemberRole: (orgId: string, userId: string, role: string) =>
      http.put(`/organizations/${orgId}/members/${userId}`, { role }).then(() => undefined).catch(normalizeError),

    removeMember: (orgId: string, userId: string) =>
      http.delete(`/organizations/${orgId}/members/${userId}`).then(() => undefined).catch(normalizeError),

    listInvitations: (orgId: string) =>
      http.get<ApiSuccess<OrgInvitation[]>>(`/organizations/${orgId}/invitations`).then((r) => r.data.data).catch(normalizeError),

    inviteMember: (orgId: string, body: { email: string; role: string }) =>
      http.post<ApiSuccess<OrgInvitation | { added: boolean }>>(`/organizations/${orgId}/invitations`, body).then((r) => r.data.data).catch(normalizeError),

    revokeInvitation: (orgId: string, invId: string) =>
      http.delete(`/organizations/${orgId}/invitations/${invId}`).then(() => undefined).catch(normalizeError),

    acceptInvitation: (token: string) =>
      http.post<ApiSuccess<Organization>>("/invitations/accept", { token }).then((r) => r.data.data).catch(normalizeError),

    // ── Notifications (Phase 2C) ─────────────────────────────────────────────
    getNotificationSettings: () =>
      http.get<ApiSuccess<NotificationSettings>>("/notifications/settings").then((r) => r.data.data).catch(normalizeError),

    updateNotificationSettings: (body: NotificationSettings) =>
      http.put<ApiSuccess<NotificationSettings>>("/notifications/settings", body).then((r) => r.data.data).catch(normalizeError),

    // ── GitHub App (Phase 2C) ────────────────────────────────────────────────
    getGithubAppInstallUrl: () =>
      http.get<ApiSuccess<{ enabled: boolean; install_url: string }>>("/integrations/github/install-url").then((r) => r.data.data).catch(normalizeError),

    listGithubAppInstallations: () =>
      http.get<ApiSuccess<GHAppInstallation[]>>("/integrations/github/installations").then((r) => r.data.data).catch(normalizeError),

    toggleGithubAppRepo: (repoId: string, enabled: boolean) =>
      http.patch(`/integrations/github/repos/${repoId}`, { enabled }).then(() => undefined).catch(normalizeError),

    // ── Policies (Phase 2C) ──────────────────────────────────────────────────
    getPolicyTemplates: () =>
      http.get<ApiSuccess<Record<string, PolicyConfig>>>("/policies/templates").then((r) => r.data.data).catch(normalizeError),

    getPolicy: (projectId: string) =>
      http.get<ApiSuccess<Policy | null>>(`/projects/${projectId}/policy`).then((r) => r.data.data).catch(normalizeError),

    setPolicy: (projectId: string, body: { name?: string; template?: string; config?: PolicyConfig }) =>
      http.put<ApiSuccess<Policy>>(`/projects/${projectId}/policy`, body).then((r) => r.data.data).catch(normalizeError),

    evaluatePolicy: (scanId: string) =>
      http.get<ApiSuccess<PolicyResult>>(`/scans/${scanId}/policy`).then((r) => r.data.data).catch(normalizeError),

    // ── Project memory (Phase 2C) ────────────────────────────────────────────
    getBaseline: (projectId: string) =>
      http
        .get<ApiSuccess<BaselineData>>(`/projects/${projectId}/baseline`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    getAICodeMemory: (projectId: string) =>
      http
        .get<ApiSuccess<AICodeMemory>>(`/projects/${projectId}/ai-code-memory`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    // ── Support + feedback widgets (Interim Polish) ──────────────────────────
    submitSupportTicket: (body: { subject: string; message: string }) =>
      http.post("/support/tickets", body).then(() => undefined).catch(normalizeError),

    submitScanFeedback: (scanId: string, body: { rating: "up" | "down"; comment?: string }) =>
      http.post(`/scans/${scanId}/feedback-rating`, body).then(() => undefined).catch(normalizeError),

    // ── Scans ────────────────────────────────────────────────────────────────
    listScans: (projectId: string, page = 1, perPage = 20) =>
      http
        .get<Paginated<Scan>>(`/projects/${projectId}/scans`, {
          params: { page, per_page: perPage },
        })
        .then((r) => r.data)
        .catch(normalizeError),

    triggerScan: (
      projectId: string,
      body?: {
        branch?: string;
        commit_sha?: string;
        deep_scan_enabled?: boolean;
        deep_scan_engine?: "joern" | "codeql";
      },
    ) =>
      http
        .post<ApiSuccess<Scan>>(`/projects/${projectId}/scans`, body ?? {})
        .then((r) => r.data.data)
        .catch(normalizeError),

    // ── AI fix suggestions ─────────────────────────────────────────────────────
    getAiStatus: () =>
      http
        .get<ApiSuccess<{ enabled: boolean; provider: string }>>("/ai/status")
        .then((r) => r.data.data)
        .catch(normalizeError),

    suggestFix: (findingId: string) =>
      http
        .post<ApiSuccess<AISuggestion>>(`/findings/${findingId}/suggest-fix`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    // ── Custom rules ─────────────────────────────────────────────────────────
    listRules: (projectId: string) =>
      http
        .get<ApiSuccess<ProjectRule[]>>(`/projects/${projectId}/rules`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    createRule: (projectId: string, body: { name: string; rule_yaml: string }) =>
      http
        .post<ApiSuccess<ProjectRule>>(`/projects/${projectId}/rules`, body)
        .then((r) => r.data.data)
        .catch(normalizeError),

    deleteRule: (ruleId: string) =>
      http
        .delete(`/rules/${ruleId}`)
        .then(() => undefined)
        .catch(normalizeError),

    // ── Intelligence ─────────────────────────────────────────────────────────
    getIntelligenceStatus: () =>
      http
        .get<ApiSuccess<IntelligenceStatus>>("/intelligence/status")
        .then((r) => r.data.data)
        .catch(normalizeError),

    listNotifications: () =>
      http
        .get<ApiSuccess<{ notifications: Notification[]; unread_count: number }>>("/notifications")
        .then((r) => r.data.data)
        .catch(normalizeError),

    markNotificationRead: (id: string) =>
      http
        .patch(`/notifications/${id}/read`)
        .then(() => undefined)
        .catch(normalizeError),

    // ── GitHub integration ───────────────────────────────────────────────────
    listIntegrations: (projectId: string) =>
      http
        .get<ApiSuccess<GithubIntegration[]>>(`/projects/${projectId}/integrations`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    connectGitHub: (projectId: string, body?: { installation_id?: string; access_token?: string }) =>
      http
        .post<ApiSuccess<ConnectGitHubResult>>(`/projects/${projectId}/integrations/github`, body ?? {})
        .then((r) => r.data.data)
        .catch(normalizeError),

    deleteIntegration: (integrationId: string) =>
      http
        .delete(`/integrations/${integrationId}`)
        .then(() => undefined)
        .catch(normalizeError),

    // Downloads the scan's findings as a SARIF 2.1.0 file (browser download).
    exportSarif: async (scanId: string) => {
      const r = await http
        .get(`/scans/${scanId}/export/sarif`, { responseType: "blob" })
        .catch(normalizeError);
      const url = URL.createObjectURL(r.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aegis-${scanId}.sarif`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },

    getScan: (scanId: string) =>
      http
        .get<ApiSuccess<ScanReport>>(`/scans/${scanId}`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    getReport: (scanId: string) =>
      http
        .get<ApiSuccess<ScanReport>>(`/scans/${scanId}/report`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    getExecutiveReport: (scanId: string) =>
      http
        .get<ApiSuccess<ExecReport>>(`/scans/${scanId}/report/executive`)
        .then((r) => r.data.data)
        .catch(normalizeError),

    listFindings: (scanId: string, filters: FindingFilters = {}) =>
      http
        .get<Paginated<Finding>>(`/scans/${scanId}/findings`, { params: filters })
        .then((r) => r.data)
        .catch(normalizeError),

    sendFeedback: (
      findingId: string,
      action: "marked_fp" | "confirmed" | "fixed" | "suppressed" | "ignored",
      reason?: string,
    ) =>
      http
        .post(`/findings/${findingId}/feedback`, { action, reason })
        .then(() => undefined)
        .catch(normalizeError),

    patchFinding: (
      findingId: string,
      body: { is_false_positive?: boolean; is_suppressed?: boolean },
    ) =>
      http
        .patch<ApiSuccess<Finding>>(`/findings/${findingId}`, body)
        .then((r) => r.data.data)
        .catch(normalizeError),
  };
}

export type Api = ReturnType<typeof createApi>;

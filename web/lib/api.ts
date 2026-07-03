// Typed API client for the Aegis Go API. `createApi(token)` returns an object of
// typed methods; the access token is injected as a Bearer header.
import axios, { AxiosError, type AxiosInstance } from "axios";
import type {
  AISuggestion,
  ApiSuccess,
  ConnectGitHubResult,
  CreateProjectInput,
  Finding,
  FindingFilters,
  GithubIntegration,
  IntelligenceStatus,
  Notification,
  Paginated,
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

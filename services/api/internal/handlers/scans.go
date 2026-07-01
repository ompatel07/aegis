package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// ScanHandler serves the /scans and nested /projects/{id}/scans routes.
type ScanHandler struct {
	scans *services.ScanService
	log   zerolog.Logger
}

func NewScanHandler(scans *services.ScanService, log zerolog.Logger) *ScanHandler {
	return &ScanHandler{scans: scans, log: log}
}

type triggerRequest struct {
	Branch          string `json:"branch" validate:"omitempty,max=255"`
	CommitSHA       string `json:"commit_sha" validate:"omitempty,max=64"`
	DeepScanEnabled bool   `json:"deep_scan_enabled"`
	DeepScanEngine  string `json:"deep_scan_engine" validate:"omitempty,oneof=joern codeql"`
}

type patchFindingRequest struct {
	IsFalsePositive *bool `json:"is_false_positive"`
	IsSuppressed    *bool `json:"is_suppressed"`
}

// ListForProject handles GET /api/v1/projects/{id}/scans.
func (h *ScanHandler) ListForProject(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")
	page := httpx.QueryInt(r, "page", 1, 1, 1_000_000)
	perPage := httpx.QueryInt(r, "per_page", 20, 1, 100)

	scans, total, err := h.scans.List(r.Context(), projectID, userID, perPage, (page-1)*perPage)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WritePaginated(w, scans, page, perPage, total)
}

// Trigger handles POST /api/v1/projects/{id}/scans.
func (h *ScanHandler) Trigger(w http.ResponseWriter, r *http.Request) {
	// Body is optional; tolerate an empty body by treating EOF as no overrides.
	var req triggerRequest
	if r.ContentLength != 0 {
		if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
			httpx.WriteError(w, apiErr)
			return
		}
	}
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")

	scan, err := h.scans.Trigger(r.Context(), projectID, userID, services.TriggerInput{
		Branch: req.Branch, CommitSHA: req.CommitSHA,
		DeepScan: req.DeepScanEnabled, DeepScanEngine: req.DeepScanEngine,
	})
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusAccepted, scan)
}

// Get handles GET /api/v1/scans/{scanId} — scan detail with finding breakdown.
func (h *ScanHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")

	report, err := h.scans.BuildReport(r.Context(), scanID, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, report)
}

// ListFindings handles GET /api/v1/scans/{scanId}/findings with filters.
func (h *ScanHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")
	page := httpx.QueryInt(r, "page", 1, 1, 1_000_000)
	perPage := httpx.QueryInt(r, "per_page", 20, 1, 200)

	filter := repository.FindingFilter{
		Pillar:            r.URL.Query().Get("pillar"),
		Severity:          r.URL.Query().Get("severity"),
		Engine:            r.URL.Query().Get("engine"),
		IncludeSuppressed: r.URL.Query().Get("include_suppressed") == "true",
	}

	findings, total, err := h.scans.ListFindings(r.Context(), scanID, userID, filter, perPage, (page-1)*perPage)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WritePaginated(w, findings, page, perPage, total)
}

// PatchFinding handles PATCH /api/v1/findings/{findingId}.
func (h *ScanHandler) PatchFinding(w http.ResponseWriter, r *http.Request) {
	var req patchFindingRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	if req.IsFalsePositive == nil && req.IsSuppressed == nil {
		httpx.WriteError(w, httpx.ErrBadRequest("provide is_false_positive and/or is_suppressed"))
		return
	}
	userID := middleware.UserID(r.Context())
	findingID := chi.URLParam(r, "findingId")

	finding, err := h.scans.UpdateFindingTriage(r.Context(), findingID, userID, req.IsFalsePositive, req.IsSuppressed)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, finding)
}

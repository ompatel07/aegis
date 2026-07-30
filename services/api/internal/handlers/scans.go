package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// maxUploadBytes caps the compressed archive size accepted by the upload endpoint.
// Decompression-bomb protection (uncompressed caps) is enforced during extraction
// in the orchestrator.
const maxUploadBytes = 100 << 20 // 100 MiB

// uploadDir is the shared workspace path where the API stages uploaded archives
// for the orchestrator to extract. Both mount the `workspaces` volume.
const uploadDir = "/workspaces/uploads"

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

type feedbackRequest struct {
	Action string `json:"action" validate:"required,oneof=marked_fp fixed suppressed ignored confirmed"`
	Reason string `json:"reason" validate:"omitempty,max=2000"`
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

// ExportSARIF handles GET /api/v1/scans/{scanId}/export/sarif — a SARIF 2.1.0
// document of the scan's findings, suitable for GitHub code scanning upload.
func (h *ScanHandler) ExportSARIF(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")

	log, err := h.scans.ExportSARIF(r.Context(), scanID, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aegis-%s.sarif"`, scanID))
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(log); err != nil {
		h.log.Error().Err(err).Str("scan_id", scanID).Msg("failed to encode SARIF")
	}
}

// ExportSBOM handles GET /api/v1/scans/{scanId}/export/sbom?format=cyclonedx|spdx
// — a downloadable Software Bill of Materials (components, versions, CVEs, and
// licenses where the ecosystem provides them).
func (h *ScanHandler) ExportSBOM(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "cyclonedx"
	}
	content, err := h.scans.ExportSBOM(r.Context(), scanID, userID, format)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	ext := map[string]string{"cyclonedx": "cdx.json", "spdx": "spdx.json"}[format]
	if ext == "" {
		ext = "json"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aegis-%s.%s"`, scanID, ext))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

// UploadScan handles POST /api/v1/projects/{id}/scans/upload — a multipart
// upload of a .zip/.tar.gz code archive (Method B). The archive is staged to the
// shared workspace and scanned in an isolated per-scan sandbox; no git host or
// credential is involved.
func (h *ScanHandler) UploadScan(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("upload too large or malformed (max 100 MiB)"))
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("missing multipart field 'file'"))
		return
	}
	defer file.Close()

	name := strings.ToLower(hdr.Filename)
	var ext string
	switch {
	case strings.HasSuffix(name, ".zip"):
		ext = ".zip"
	case strings.HasSuffix(name, ".tar.gz"):
		ext = ".tar.gz"
	case strings.HasSuffix(name, ".tgz"):
		ext = ".tgz"
	default:
		httpx.WriteError(w, httpx.ErrBadRequest("only .zip or .tar.gz archives are accepted"))
		return
	}

	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		h.log.Error().Err(err).Msg("create upload dir")
		httpx.WriteError(w, httpx.ErrInternal())
		return
	}
	dest := filepath.Join(uploadDir, uuid.NewString()+ext)
	// 0644 so the orchestrator (which may run as a different uid on the shared
	// volume) can read the staged archive; it is deleted right after extraction.
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		h.log.Error().Err(err).Msg("create upload file")
		httpx.WriteError(w, httpx.ErrInternal())
		return
	}
	// Cap the copy defensively even though MaxBytesReader already bounds the body.
	if _, err := io.Copy(out, io.LimitReader(file, maxUploadBytes+1)); err != nil {
		out.Close()
		_ = os.Remove(dest)
		httpx.WriteError(w, httpx.ErrBadRequest("failed to read upload"))
		return
	}
	out.Close()

	scan, err := h.scans.TriggerUpload(r.Context(), projectID, userID, dest)
	if err != nil {
		_ = os.Remove(dest) // don't leave an orphaned archive if the trigger failed
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, scan)
}

// Feedback handles POST /api/v1/findings/{findingId}/feedback — records a user's
// action on a finding (feeds the local false-positive classifier).
func (h *ScanHandler) Feedback(w http.ResponseWriter, r *http.Request) {
	var req feedbackRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	userID := middleware.UserID(r.Context())
	findingID := chi.URLParam(r, "findingId")
	if err := h.scans.RecordFeedback(r.Context(), findingID, userID, req.Action, req.Reason); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

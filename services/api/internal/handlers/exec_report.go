package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/services"
)

// ExecReportHandler serves the executive (CISO) report.
type ExecReportHandler struct {
	reports *services.ReportService
	log     zerolog.Logger
}

func NewExecReportHandler(reports *services.ReportService, log zerolog.Logger) *ExecReportHandler {
	return &ExecReportHandler{reports: reports, log: log}
}

// Executive handles GET /api/v1/scans/{scanId}/report/executive — a metadata-only
// executive summary (exec paragraph, top risks, trend vs previous scan,
// remediation priorities). The dashboard renders it and exports to PDF via print.
func (h *ExecReportHandler) Executive(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")

	report, err := h.reports.Executive(r.Context(), scanID, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, report)
}

// Compliance handles GET /api/v1/scans/{scanId}/report/compliance?framework=soc2 —
// an audit-evidence compliance report (findings mapped to a framework's controls).
// Org-scoped via the scan; returns the rendered HTML + score summary so the UI can
// preview and download it.
func (h *ExecReportHandler) Compliance(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")
	framework := r.URL.Query().Get("framework")
	if framework == "" {
		framework = "soc2"
	}

	report, err := h.reports.Compliance(r.Context(), scanID, userID, framework)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	// download=1 → serve the raw HTML as an attachment (a real downloadable file).
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"aegis-"+framework+"-"+scanID+".html\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.HTML))
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, report)
}

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

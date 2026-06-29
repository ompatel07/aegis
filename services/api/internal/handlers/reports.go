package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/services"
)

// ReportHandler serves the formatted scan report endpoint.
type ReportHandler struct {
	scans *services.ScanService
	log   zerolog.Logger
}

func NewReportHandler(scans *services.ScanService, log zerolog.Logger) *ReportHandler {
	return &ReportHandler{scans: scans, log: log}
}

// Get handles GET /api/v1/scans/{scanId}/report — the formatted report JSON
// (scan scores/metadata plus the pillar × severity finding breakdown).
func (h *ReportHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	scanID := chi.URLParam(r, "scanId")

	report, err := h.scans.BuildReport(r.Context(), scanID, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, report)
}

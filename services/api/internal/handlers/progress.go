package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/repository"
)

// progressChannelPrefix mirrors the orchestrator's progress.ChannelPrefix; the
// two services are separate Go modules so the literal is duplicated here.
const progressChannelPrefix = "scan:progress:"

// ProgressHandler streams live scan-stage updates over Server-Sent Events. SSE
// (not WebSocket) is used deliberately: scan progress is one-directional
// server→client, SSE needs no extra dependency, and it degrades gracefully. The
// browser's EventSource cannot set an Authorization header, so the access token
// is passed as a `?token=` query parameter and validated here.
type ProgressHandler struct {
	rdb    *redis.Client
	tokens *auth.TokenManager
	scans  *repository.ScanRepository
	log    zerolog.Logger
}

func NewProgressHandler(rdb *redis.Client, tokens *auth.TokenManager, scans *repository.ScanRepository, log zerolog.Logger) *ProgressHandler {
	return &ProgressHandler{rdb: rdb, tokens: tokens, scans: scans, log: log}
}

// Stream: GET /scans/{scanId}/progress?token=... (text/event-stream).
func (h *ProgressHandler) Stream(w http.ResponseWriter, r *http.Request) {
	claims, err := h.tokens.ParseAccess(r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	scanID := chi.URLParam(r, "scanId")

	// Ownership + current stage.
	scan, err := h.scans.GetByIDForUser(r.Context(), scanID, claims.Subject)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)

	send := func(stage string) {
		fmt.Fprintf(w, "event: stage\ndata: {\"scan_id\":%q,\"stage\":%q}\n\n", scanID, stage)
		flusher.Flush()
	}

	// Emit the current stage immediately (covers reloads + late joiners).
	cur := scan.Status
	if scan.Stage != nil && *scan.Stage != "" {
		cur = *scan.Stage
	}
	send(cur)
	if scan.Status == "completed" || scan.Status == "failed" {
		return // nothing more to stream
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	pubsub := h.rdb.Subscribe(ctx, progressChannelPrefix+scanID)
	defer pubsub.Close()
	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			// The published payload already contains the stage; forward it and
			// close on a terminal stage.
			var u struct {
				Stage string `json:"stage"`
			}
			_ = json.Unmarshal([]byte(msg.Payload), &u)
			if u.Stage != "" {
				send(u.Stage)
				if u.Stage == "completed" || u.Stage == "failed" {
					return
				}
			}
		}
	}
}

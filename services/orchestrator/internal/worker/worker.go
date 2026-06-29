// Package worker wires the Asynq server to the scan job processor.
package worker

import (
	"context"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/orchestrator/internal/queue"
)

// Server bundles the Asynq server with its routing mux.
type Server struct {
	srv *asynq.Server
	mux *asynq.ServeMux
	log zerolog.Logger
}

// NewServer builds the Asynq worker server.
func NewServer(redisAddr, redisPassword string, redisDB, concurrency int, processor *ScanProcessor, log zerolog.Logger) *Server {
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr, Password: redisPassword, DB: redisDB},
		asynq.Config{
			Concurrency: concurrency,
			// Single dedicated queue for scans (room to add priorities later).
			Queues: map[string]int{"scans": 1},
			Logger: newAsynqLogger(log),
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				retried, _ := asynq.GetRetryCount(ctx)
				maxRetry, _ := asynq.GetMaxRetry(ctx)
				log.Error().
					Err(err).
					Str("type", task.Type()).
					Int("retry", retried).
					Int("max_retry", maxRetry).
					Msg("scan task error")
			}),
		},
	)

	mux := asynq.NewServeMux()
	mux.HandleFunc(queue.TypeScanRun, processor.ProcessTask)

	return &Server{srv: srv, mux: mux, log: log}
}

// Run starts the server (blocking until Shutdown is called).
func (s *Server) Run() error {
	return s.srv.Run(s.mux)
}

// Shutdown stops the server gracefully, letting in-flight tasks finish.
func (s *Server) Shutdown() {
	s.srv.Shutdown()
}

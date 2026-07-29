// Command orchestrator consumes scan jobs from Redis (Asynq), runs the 3-pillar
// pipeline against each repository, scores the results, and persists them.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"

	"github.com/aegis-platform/orchestrator/internal/adapters"
	"github.com/aegis-platform/orchestrator/internal/config"
	"github.com/aegis-platform/orchestrator/internal/intelligence"
	"github.com/aegis-platform/orchestrator/internal/logger"
	"github.com/aegis-platform/orchestrator/internal/pipeline"
	"github.com/aegis-platform/orchestrator/internal/progress"
	"github.com/aegis-platform/orchestrator/internal/store"
	"github.com/aegis-platform/orchestrator/internal/worker"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(cfg.LogLevel, cfg.LogPretty, "orchestrator")
	log.Info().
		Str("env", cfg.Environment).
		Int("concurrency", cfg.WorkerConcurrency).
		Str("scanner", cfg.ScannerBaseURL).
		Msg("starting orchestrator")

	// ── Dependencies ─────────────────────────────────────────────────────────
	st, err := store.Connect(context.Background(), cfg.DatabaseURL, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer st.Close()
	log.Info().Msg("database connected")

	gitClient := adapters.NewGitClient(cfg.WorkspaceDir, cfg.GitCloneDepth)
	scannerClient := adapters.NewScannerClient(cfg.ScannerBaseURL, cfg.ScannerTimeout)
	deepClient := adapters.NewScannerClient(cfg.ScannerDeepURL, cfg.ScannerTimeout)
	pipe := pipeline.New(scannerClient, deepClient, log)

	// Redis pub/sub publisher for live scan-stage updates (streamed by the API).
	progressRDB := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB})
	defer progressRDB.Close()
	progressPub := progress.NewPublisher(progressRDB)

	processor := worker.NewScanProcessor(st, gitClient, pipe, progressPub, cfg.MaxRepoSizeMB, cfg.DeepScanEnabled, log)

	// ── Live vulnerability intelligence (background sync + retroactive rescore) ─
	if cfg.IntelligenceEnabled {
		intelCtx, intelCancel := context.WithCancel(context.Background())
		defer intelCancel()
		intelStore := intelligence.NewStore(st.DB())
		intelligence.NewScheduler(intelStore, log,
			&intelligence.NVDSource{APIKey: cfg.NVDAPIKey},
			&intelligence.OSVSource{Store: intelStore},
			&intelligence.GHSASource{Token: cfg.GitHubToken},
			&intelligence.SemgrepSource{Store: intelStore, ScannerURL: cfg.ScannerBaseURL},
		).Start(intelCtx)
	}

	// ── Worker server (Asynq traps SIGINT/SIGTERM and shuts down gracefully) ──
	server := worker.NewServer(
		cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, cfg.WorkerConcurrency, processor, log,
	)

	log.Info().Msg("worker listening for scan jobs")
	if err := server.Run(); err != nil {
		return fmt.Errorf("worker server: %w", err)
	}
	log.Info().Msg("worker stopped cleanly")
	return nil
}

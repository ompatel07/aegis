// Command api is the Aegis public API gateway: auth, projects, scans, findings,
// reports, and GitHub webhooks. It enqueues scan jobs for the orchestrator.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/redis/go-redis/v9"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/config"
	"github.com/aegis-platform/api/internal/database"
	"github.com/aegis-platform/api/internal/handlers"
	"github.com/aegis-platform/api/internal/logger"
	mw "github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/queue"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
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
	log := logger.New(cfg.LogLevel, cfg.LogPretty, "api")
	log.Info().Str("env", cfg.Environment).Int("port", cfg.HTTPPort).Msg("starting api")

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Dependencies ─────────────────────────────────────────────────────────
	db, err := database.Connect(rootCtx, cfg)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()
	log.Info().Msg("database connected")

	rdb := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB,
	})
	defer rdb.Close()
	if err := rdb.Ping(rootCtx).Err(); err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	log.Info().Msg("redis connected")

	publisher := queue.NewPublisher(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	defer publisher.Close()

	// ── Auth primitives ──────────────────────────────────────────────────────
	tokens := auth.NewTokenManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, cfg.JWTAccessTTL, cfg.JWTRefreshTTL)
	sessions := auth.NewSessionStore(rdb)

	// ── Repositories ─────────────────────────────────────────────────────────
	userRepo := repository.NewUserRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	scanRepo := repository.NewScanRepository(db)
	findingRepo := repository.NewFindingRepository(db)
	integrationRepo := repository.NewGithubIntegrationRepository(db)

	// ── Services ─────────────────────────────────────────────────────────────
	authSvc := services.NewAuthService(userRepo, tokens, sessions)
	projectSvc := services.NewProjectService(projectRepo)
	scanSvc := services.NewScanService(projectRepo, scanRepo, findingRepo, publisher)

	// ── Handlers ─────────────────────────────────────────────────────────────
	authH := handlers.NewAuthHandler(authSvc, log)
	projectH := handlers.NewProjectHandler(projectSvc, log)
	scanH := handlers.NewScanHandler(scanSvc, log)
	reportH := handlers.NewReportHandler(scanSvc, log)
	webhookH := handlers.NewWebhookHandler(integrationRepo, scanSvc, log)
	healthH := handlers.NewHealthHandler(db, rdb)

	rateLimiter := mw.NewRateLimiter(rdb, cfg.RateLimitRPM, log)

	// ── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(mw.Recoverer(log))
	r.Use(mw.RequestLogger(log))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Requested-With"},
		ExposedHeaders:   []string{"X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(rateLimiter.Handler)

	r.Get("/health", healthH.Get)

	r.Route("/api/v1", func(r chi.Router) {
		// Public auth + webhook routes.
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authH.Register)
			r.Post("/login", authH.Login)
			r.Post("/refresh", authH.Refresh)
			r.Post("/logout", authH.Logout)
		})
		r.Post("/webhooks/github", webhookH.GitHub)

		// Authenticated routes.
		r.Group(func(r chi.Router) {
			r.Use(mw.Authenticator(tokens))

			r.Route("/projects", func(r chi.Router) {
				r.Get("/", projectH.List)
				r.Post("/", projectH.Create)
				r.Get("/{id}", projectH.Get)
				r.Put("/{id}", projectH.Update)
				r.Delete("/{id}", projectH.Delete)
				r.Get("/{id}/scans", scanH.ListForProject)
				r.Post("/{id}/scans", scanH.Trigger)
			})

			r.Route("/scans", func(r chi.Router) {
				r.Get("/{scanId}", scanH.Get)
				r.Get("/{scanId}/findings", scanH.ListFindings)
				r.Get("/{scanId}/report", reportH.Get)
			})

			r.Patch("/findings/{findingId}", scanH.PatchFinding)
		})
	})

	// ── HTTP server with graceful shutdown ───────────────────────────────────
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info().Str("addr", srv.Addr).Msg("http server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case <-rootCtx.Done():
		log.Info().Msg("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	log.Info().Msg("server stopped cleanly")
	return nil
}

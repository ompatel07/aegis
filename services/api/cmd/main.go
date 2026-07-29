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

	"github.com/aegis-platform/api/internal/ai"
	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/config"
	"github.com/aegis-platform/api/internal/database"
	"github.com/aegis-platform/api/internal/githubapp"
	"github.com/aegis-platform/api/internal/handlers"
	"github.com/aegis-platform/api/internal/notify"
	"github.com/aegis-platform/api/internal/vcs"
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
	encryptor, err := auth.NewEncryptor(cfg.TokenEncryptionKey)
	if err != nil {
		return fmt.Errorf("init encryptor: %w", err)
	}

	// ── Repositories ─────────────────────────────────────────────────────────
	userRepo := repository.NewUserRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	scanRepo := repository.NewScanRepository(db)
	findingRepo := repository.NewFindingRepository(db)
	integrationRepo := repository.NewGithubIntegrationRepository(db)
	intelligenceRepo := repository.NewIntelligenceRepository(db)
	projectRuleRepo := repository.NewProjectRuleRepository(db)
	aiAuditRepo := repository.NewAIAuditRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	adminRepo := repository.NewAdminRepository(db)
	policyRepo := repository.NewPolicyRepository(db)
	githubAppRepo := repository.NewGitHubAppRepository(db)
	ssoRepo := repository.NewSSORepository(db)

	// ── Services ─────────────────────────────────────────────────────────────
	authSvc := services.NewAuthService(userRepo, orgRepo, tokens, sessions)
	projectSvc := services.NewProjectService(projectRepo, orgRepo)
	orgSvc := services.NewOrganizationService(orgRepo, userRepo)
	policySvc := services.NewPolicyService(policyRepo, projectRepo, scanRepo, findingRepo)
	scanSvc := services.NewScanService(projectRepo, scanRepo, findingRepo, projectRuleRepo, publisher)
	integrationSvc := services.NewIntegrationService(projectRepo, integrationRepo, encryptor)

	githubApp, err := githubapp.New(githubapp.Config{
		AppID: cfg.GitHubAppID, PrivateKeyPEM: cfg.GitHubAppPrivateKey, WebhookSecret: cfg.GitHubAppWebhookKey,
		ClientID: cfg.GitHubAppClientID, ClientSecret: cfg.GitHubAppClientSecret, Slug: cfg.GitHubAppSlug,
	}, nil)
	if err != nil {
		return fmt.Errorf("init github app: %w", err)
	}
	dashURL := cfg.DashboardURL
	if dashURL == "" {
		dashURL = "http://localhost"
	}
	githubAppSvc := services.NewGitHubAppService(githubApp, githubAppRepo, projectRepo, scanSvc, scanRepo, findingRepo, policySvc, dashURL, log)
	log.Info().Bool("github_app_enabled", githubApp.Enabled()).Msg("github app")

	// GitLab + Bitbucket providers (opt-in, disabled without a token).
	gitlabProvider := vcs.NewGitLab(vcs.GitLabConfig{BaseURL: cfg.GitLabBaseURL, Token: cfg.GitLabToken, WebhookSecret: cfg.GitLabWebhookSecret}, nil)
	bitbucketProvider := vcs.NewBitbucket(vcs.BitbucketConfig{Token: cfg.BitbucketToken, WebhookSecret: cfg.BitbucketWebhookSecret}, nil)
	vcsRepo := repository.NewVCSRepository(db)
	vcsSvc := services.NewVCSService(
		map[string]vcs.VCSProvider{"gitlab": gitlabProvider, "bitbucket": bitbucketProvider},
		vcsRepo, projectRepo, scanSvc, scanRepo, findingRepo, policySvc, dashURL, log)
	log.Info().Bool("gitlab_enabled", gitlabProvider.Enabled()).Bool("bitbucket_enabled", bitbucketProvider.Enabled()).Msg("vcs providers")

	// Notifications: email (log provider by default) + Slack incoming webhooks.
	emailSender := notify.NewSender(notify.Config{
		Provider: cfg.EmailProvider, APIKey: cfg.EmailAPIKey, From: cfg.EmailFrom,
		SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort, SMTPUser: cfg.SMTPUser, SMTPPass: cfg.SMTPPass,
	}, nil, log)
	notifyRepo := repository.NewNotifyRepository(db)
	notifySvc := services.NewNotificationService(emailSender, notify.NewSlack(nil), notifyRepo, scanRepo, findingRepo, projectRepo, dashURL, log)
	orgSvc.SetInviter(notifySvc) // deliver org invitations by email
	log.Info().Str("email_provider", emailSender.Name()).Msg("notifications")
	ruleSvc := services.NewRuleService(projectRepo, projectRuleRepo, cfg.ScannerBaseURL)
	aiBackend := ai.New(ai.Config{Provider: cfg.AIProvider, Model: cfg.AIModel, APIKey: cfg.AIAPIKey, BaseURL: cfg.AIBaseURL})
	aiSvc := services.NewAIService(aiBackend, findingRepo, aiAuditRepo)
	reportSvc := services.NewReportService(scanRepo, findingRepo, projectRepo, aiBackend, aiAuditRepo)
	log.Info().Str("provider", aiSvc.Provider()).Bool("enabled", aiSvc.Enabled()).Msg("AI layer")

	// ── Handlers ─────────────────────────────────────────────────────────────
	authH := handlers.NewAuthHandler(authSvc, log)
	projectH := handlers.NewProjectHandler(projectSvc, log)
	scanH := handlers.NewScanHandler(scanSvc, log)
	reportH := handlers.NewReportHandler(scanSvc, log)
	integrationH := handlers.NewIntegrationHandler(integrationSvc, log)
	intelligenceH := handlers.NewIntelligenceHandler(intelligenceRepo, log)
	ruleH := handlers.NewRuleHandler(ruleSvc, log)
	aiH := handlers.NewAIHandler(aiSvc, log)
	execReportH := handlers.NewExecReportHandler(reportSvc, log)
	orgH := handlers.NewOrganizationHandler(orgSvc, log)
	adminH := handlers.NewAdminHandler(adminRepo, userRepo, tokens, log)
	policyH := handlers.NewPolicyHandler(policySvc, log)
	githubAppH := handlers.NewGitHubAppHandler(githubAppSvc, githubAppRepo, log)
	vcsH := handlers.NewVCSHandler(vcsSvc, log)
	notifyH := handlers.NewNotifyHandler(notifySvc, log)
	ssoSvc := services.NewSSOService(ssoRepo, userRepo, orgRepo, authSvc, encryptor, rdb, dashURL)
	ssoH := handlers.NewSSOHandler(ssoSvc, ssoRepo, orgRepo, encryptor, dashURL, log)
	scimH := handlers.NewSCIMHandler(ssoRepo, userRepo, orgRepo, authSvc, log)
	webhookH := handlers.NewWebhookHandler(integrationRepo, scanSvc, log)
	progressH := handlers.NewProgressHandler(rdb, tokens, scanRepo, log)
	healthH := handlers.NewHealthHandler(db, rdb)

	rateLimiter := mw.NewRateLimiter(rdb, cfg.RateLimitRPM, log)

	// ── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(mw.Recoverer(log))
	r.Use(mw.RequestLogger(log))
	r.Use(mw.SecureHeaders)
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

	// Strict per-IP limiter for credential endpoints (brute-force defense),
	// on its own counter namespace so it doesn't share the global budget.
	authLimiter := mw.NewNamedRateLimiter(rdb, cfg.AuthRateLimitRPM, "auth", log)

	r.Route("/api/v1", func(r chi.Router) {
		// Public auth + webhook routes.
		r.Route("/auth", func(r chi.Router) {
			r.Use(authLimiter.Handler)
			r.Post("/register", authH.Register)
			r.Post("/login", authH.Login)
			r.Post("/refresh", authH.Refresh)
			r.Post("/logout", authH.Logout)
			// Enterprise SSO login flow (public — the IdP redirects the browser here).
			r.Route("/sso", func(r chi.Router) {
				r.Get("/discover", ssoH.Discover)
				r.Get("/oidc/callback", ssoH.OIDCCallback)
				r.Post("/saml/acs", ssoH.SAMLACS)
				r.Get("/{connID}/login", ssoH.Login)
				r.Get("/{connID}/saml/metadata", ssoH.SAMLMetadata)
			})
		})
		r.Post("/webhooks/github", webhookH.GitHub)
		r.Post("/webhooks/github/app", githubAppH.Webhook)
		r.Post("/webhooks/gitlab", vcsH.GitLab)
		r.Post("/webhooks/bitbucket", vcsH.Bitbucket)
		// SSE live scan progress — auth via ?token= (EventSource can't set headers).
		r.Get("/scans/{scanId}/progress", progressH.Stream)

		// Authenticated routes.
		r.Group(func(r chi.Router) {
			r.Use(mw.Authenticator(tokens))

			r.Route("/organizations", func(r chi.Router) {
				r.Get("/", orgH.List)
				r.Post("/", orgH.Create)
				r.Get("/{orgId}", orgH.Get)
				r.Put("/{orgId}", orgH.Update)
				r.Get("/{orgId}/members", orgH.Members)
				r.Put("/{orgId}/members/{userId}", orgH.SetRole)
				r.Delete("/{orgId}/members/{userId}", orgH.RemoveMember)
				r.Get("/{orgId}/invitations", orgH.ListInvitations)
				r.Post("/{orgId}/invitations", orgH.Invite)
				r.Delete("/{orgId}/invitations/{invId}", orgH.RevokeInvitation)
			})
			r.Post("/invitations/accept", orgH.Accept)

			r.Route("/projects", func(r chi.Router) {
				r.Get("/", projectH.List)
				r.Post("/", projectH.Create)
				r.Get("/{id}", projectH.Get)
				r.Put("/{id}", projectH.Update)
				r.Delete("/{id}", projectH.Delete)
				r.Get("/{id}/scans", scanH.ListForProject)
				r.Post("/{id}/scans", scanH.Trigger)
				r.Get("/{id}/integrations", integrationH.ListForProject)
				r.Post("/{id}/integrations/github", integrationH.Connect)
				r.Get("/{id}/rules", ruleH.List)
				r.Post("/{id}/rules", ruleH.Create)
				r.Get("/{id}/baseline", projectH.Baseline)
				r.Get("/{id}/policy", policyH.Get)
				r.Put("/{id}/policy", policyH.Set)
				r.Get("/{id}/slack", notifyH.GetProjectSlack)
				r.Put("/{id}/slack", notifyH.SetProjectSlack)
			})
			r.Get("/policies/templates", policyH.Templates)
			r.Get("/notifications/settings", notifyH.GetSettings)
			r.Put("/notifications/settings", notifyH.UpdateSettings)

			r.Route("/integrations/github", func(r chi.Router) {
				r.Get("/install-url", githubAppH.InstallURL)
				r.Get("/installations", githubAppH.Installations)
				r.Patch("/repos/{id}", githubAppH.ToggleRepo)
			})

			r.Route("/scans", func(r chi.Router) {
				r.Get("/{scanId}", scanH.Get)
				r.Get("/{scanId}/findings", scanH.ListFindings)
				r.Get("/{scanId}/report", reportH.Get)
				r.Get("/{scanId}/report/executive", execReportH.Executive)
				r.Get("/{scanId}/policy", policyH.Evaluate)
				r.Get("/{scanId}/export/sarif", scanH.ExportSARIF)
				r.Get("/{scanId}/export/sbom", scanH.ExportSBOM)
			})

			r.Patch("/findings/{findingId}", scanH.PatchFinding)
			r.Post("/findings/{findingId}/feedback", scanH.Feedback)
			r.Post("/findings/{findingId}/suggest-fix", aiH.SuggestFix)
			r.Get("/ai/status", aiH.Status)
			r.Get("/ai/audit", aiH.Audit)
			r.Delete("/integrations/{integrationId}", integrationH.Delete)
			r.Delete("/rules/{ruleId}", ruleH.Delete)

			r.Get("/intelligence/status", intelligenceH.Status)
			r.Get("/notifications", intelligenceH.ListNotifications)
			r.Patch("/notifications/{id}/read", intelligenceH.MarkNotificationRead)

			// In-app widgets (any signed-in user).
			r.Post("/support/tickets", adminH.SubmitTicket)
			r.Post("/scans/{scanId}/feedback-rating", adminH.SubmitScanRating)

			// ── Platform super-admin panel ───────────────────────────────────
			r.Route("/admin", func(r chi.Router) {
				r.Use(mw.RequireSuperAdmin(adminRepo.IsSuperAdmin))
				r.Get("/overview", adminH.Overview)
				r.Get("/health", adminH.Health)
				r.Get("/organizations", adminH.ListOrgs)
				r.Post("/organizations/{orgId}/suspend", adminH.SuspendOrg)
				r.Put("/organizations/{orgId}/plan", adminH.SetOrgPlan)
				r.Get("/users", adminH.ListUsers)
				r.Post("/users/{userId}/super-admin", adminH.SetSuperAdmin)
				r.Post("/users/{userId}/suspend", adminH.SuspendUser)
				r.Post("/users/{userId}/impersonate", adminH.Impersonate)
				r.Get("/scans", adminH.ListScans)
				r.Get("/audit", adminH.ListAudit)
				r.Get("/features", adminH.ListFlags)
				r.Post("/features", adminH.CreateFlag)
				r.Put("/features/{flagId}", adminH.UpdateFlag)
				r.Delete("/features/{flagId}", adminH.DeleteFlag)
				r.Get("/beta", adminH.ListBeta)
				r.Post("/beta", adminH.CreateBeta)
				r.Post("/beta/{betaId}/revoke", adminH.RevokeBeta)
				r.Get("/support", adminH.ListTickets)
				r.Post("/support/{ticketId}/reply", adminH.ReplyTicket)
			})

			// Org-scoped SSO/IdP administration (owner-gated in the handler).
			r.Route("/sso", func(r chi.Router) {
				r.Post("/connections", ssoH.CreateConnection)
				r.Get("/connections", ssoH.ListConnections)
				r.Put("/connections/{id}", ssoH.UpdateConnection)
				r.Delete("/connections/{id}", ssoH.DeleteConnection)
				r.Post("/scim-tokens", ssoH.CreateSCIMToken)
				r.Get("/scim-tokens", ssoH.ListSCIMTokens)
				r.Delete("/scim-tokens/{id}", ssoH.RevokeSCIMToken)
			})
		})
	})

	// SCIM 2.0 provisioning — its own bearer-token auth (not the user JWT).
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(scimH.Authenticate)
		r.Post("/Users", scimH.CreateUser)
		r.Get("/Users", scimH.ListUsers)
		r.Get("/Users/{id}", scimH.GetUser)
		r.Patch("/Users/{id}", scimH.PatchUser)
		r.Put("/Users/{id}", scimH.PatchUser)
		r.Delete("/Users/{id}", scimH.DeleteUser)
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

	// Reconciler: finalize PR/MR checks + comments once scans complete, across
	// every configured provider.
	if githubApp.Enabled() || gitlabProvider.Enabled() || bitbucketProvider.Enabled() {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-rootCtx.Done():
					return
				case <-ticker.C:
					githubAppSvc.Reconcile(rootCtx)
					vcsSvc.Reconcile(rootCtx)
				}
			}
		}()
	}

	// Notification dispatcher: email/Slack for completed scans (every 15s).
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-ticker.C:
				notifySvc.Dispatch(rootCtx)
			}
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

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/orchestrator/internal/adapters"
	"github.com/aegis-platform/orchestrator/internal/pipeline"
	"github.com/aegis-platform/orchestrator/internal/queue"
	"github.com/aegis-platform/orchestrator/internal/store"
)

// ScanProcessor executes the end-to-end scan pipeline for one job.
type ScanProcessor struct {
	store         *store.Store
	git           *adapters.GitClient
	pipe          *pipeline.Pipeline
	maxRepoSizeMB int
	log           zerolog.Logger
}

func NewScanProcessor(
	st *store.Store, git *adapters.GitClient, pipe *pipeline.Pipeline, maxRepoSizeMB int, log zerolog.Logger,
) *ScanProcessor {
	return &ScanProcessor{store: st, git: git, pipe: pipe, maxRepoSizeMB: maxRepoSizeMB, log: log}
}

// ProcessTask is the Asynq handler for TypeScanRun.
//
// Stages (each updates scan state so the dashboard can show progress):
//
//	queued → running → (clone → detect → scan → aggregate → persist) → completed | failed
func (p *ScanProcessor) ProcessTask(ctx context.Context, task *asynq.Task) error {
	var payload queue.ScanPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		// A malformed payload can never succeed — do not retry (SkipRetry).
		p.log.Error().Err(err).Msg("invalid scan payload")
		return fmt.Errorf("unmarshal payload: %w: %w", err, asynq.SkipRetry)
	}

	log := p.log.With().Str("scan_id", payload.ScanID).Str("project_id", payload.ProjectID).Logger()
	start := time.Now()
	log.Info().Str("repo", payload.RepoURL).Str("branch", payload.Branch).Msg("scan started")

	if err := p.store.MarkRunning(ctx, payload.ScanID); err != nil {
		return fmt.Errorf("mark running: %w", err) // transient DB error → retry
	}

	// ── Clone ────────────────────────────────────────────────────────────────
	checkout, err := p.git.Clone(ctx, payload.ScanID, payload.RepoURL, payload.Branch)
	if err != nil {
		return p.fail(ctx, payload.ScanID, task, fmt.Sprintf("clone failed: %v", err), log)
	}
	defer checkout.Cleanup()

	// ── Size guard ───────────────────────────────────────────────────────────
	if sizeMB, serr := adapters.DirSizeMB(checkout.Dir); serr == nil && sizeMB > p.maxRepoSizeMB {
		msg := fmt.Sprintf("repository too large: %dMB exceeds limit of %dMB", sizeMB, p.maxRepoSizeMB)
		// Permanent condition — mark failed and skip retry.
		_ = p.store.MarkFailed(ctx, payload.ScanID, msg)
		log.Warn().Msg(msg)
		return fmt.Errorf("%s: %w", msg, asynq.SkipRetry)
	}

	// ── Detect ───────────────────────────────────────────────────────────────
	det := pipeline.Detect(checkout.Dir)
	if payload.Language != "" && det.PrimaryLanguage == "" {
		det.PrimaryLanguage = payload.Language
		det.Languages = append(det.Languages, payload.Language)
	}
	log.Info().
		Str("primary_language", det.PrimaryLanguage).
		Strs("languages", det.Languages).
		Strs("project_types", det.ProjectTypes).
		Msg("project detected")

	// ── Scan (parallel fan-out) ──────────────────────────────────────────────
	results := p.pipe.Run(ctx, checkout.Dir, payload.ScanID, det, payload.CustomRules)

	// ── Deep scan (opt-in) ───────────────────────────────────────────────────
	// Runs after the fast fan-out; merged + deduped so the same vuln is not
	// double-reported. A skipped/failed deep scan never fails the overall scan.
	if payload.DeepScanEnabled {
		deep := p.pipe.Deep(ctx, checkout.Dir, payload.ScanID, payload.DeepScanEngine)
		results = pipeline.MergeDeep(results, deep)
	}

	// ── Aggregate + score ────────────────────────────────────────────────────
	agg := pipeline.Aggregate(results)

	// ── AI-generated-code analysis (Phase 2C) ────────────────────────────────
	// Score files for AI-generation, tag findings that sit in AI code, and build
	// the scan's AI-code report. A degraded pass leaves findings untagged.
	aiRes := p.pipe.AICode(ctx, checkout.Dir, payload.ScanID)
	aiReport := pipeline.TagAICode(agg.Findings, aiRes)
	if aiRes != nil {
		if b, err := json.Marshal(aiReport); err == nil {
			agg.AICodeReport = b
		}
		pct, safety := aiReport.AIGeneratedPct, aiReport.SafetyScore
		agg.AIGeneratedPct = &pct
		agg.AICodeSafetyScore = &safety
		log.Info().Float64("ai_pct", pct).Int("ai_safety", safety).
			Int("findings_in_ai", aiReport.FindingsInAICode).
			Msg("ai-code analysis complete")
	}

	// ── Persist ──────────────────────────────────────────────────────────────
	if err := p.store.SaveResults(ctx, payload.ScanID, payload.ProjectID, agg); err != nil {
		return p.fail(ctx, payload.ScanID, task, fmt.Sprintf("persist results: %v", err), log)
	}

	log.Info().
		Int("overall", agg.OverallScore).
		Str("grade", agg.OverallGrade).
		Int("security", agg.SecurityScore).
		Int("quality", agg.QualityScore).
		Int("deployment", agg.DeploymentScore).
		Int("findings", len(agg.Findings)).
		Dur("duration", time.Since(start)).
		Msg("scan completed")
	return nil
}

// fail records a failure, marking the scan failed only on the final attempt so
// transient errors still get Asynq's retry budget.
func (p *ScanProcessor) fail(ctx context.Context, scanID string, task *asynq.Task, msg string, log zerolog.Logger) error {
	retried, _ := asynq.GetRetryCount(ctx)
	maxRetry, _ := asynq.GetMaxRetry(ctx)
	if retried >= maxRetry {
		if err := p.store.MarkFailed(ctx, scanID, msg); err != nil {
			log.Error().Err(err).Msg("failed to mark scan failed")
		}
		log.Error().Str("reason", msg).Msg("scan failed (final attempt)")
	} else {
		log.Warn().Str("reason", msg).Int("retry", retried).Msg("scan attempt failed, will retry")
	}
	return fmt.Errorf("%s", msg)
}

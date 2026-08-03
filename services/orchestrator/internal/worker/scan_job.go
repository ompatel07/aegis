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
	"github.com/aegis-platform/orchestrator/internal/progress"
	"github.com/aegis-platform/orchestrator/internal/queue"
	"github.com/aegis-platform/orchestrator/internal/store"
)

// ScanProcessor executes the end-to-end scan pipeline for one job.
type ScanProcessor struct {
	store           *store.Store
	git             *adapters.GitClient
	pipe            *pipeline.Pipeline
	progress        *progress.Publisher
	maxRepoSizeMB   int
	deepScanEnabled bool // experimental Joern deep scan; OFF by default (Track 2f)
	log             zerolog.Logger
}

func NewScanProcessor(
	st *store.Store, git *adapters.GitClient, pipe *pipeline.Pipeline, prog *progress.Publisher,
	maxRepoSizeMB int, deepScanEnabled bool, log zerolog.Logger,
) *ScanProcessor {
	return &ScanProcessor{store: st, git: git, pipe: pipe, progress: prog, maxRepoSizeMB: maxRepoSizeMB, deepScanEnabled: deepScanEnabled, log: log}
}

// stage records + broadcasts the scan's current pipeline stage.
func (p *ScanProcessor) stage(ctx context.Context, scanID, stage string) {
	_ = p.store.SetStage(ctx, scanID, stage)
	p.progress.Publish(ctx, scanID, stage)
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
	p.stage(ctx, payload.ScanID, progress.StageCloning)
	var checkout *adapters.Checkout
	if payload.UploadPath != "" {
		// Method B: extract the uploaded archive into a per-scan sandbox. A bad,
		// oversized, or decompression-bomb archive is a PERMANENT failure — do not
		// retry (the archive is consumed on the first attempt), and record the real
		// extraction error rather than a misleading "file gone" on a retry.
		c, err := p.git.ExtractUpload(payload.ScanID, payload.UploadPath)
		if err != nil {
			return p.failNoRetry(ctx, payload.ScanID, fmt.Sprintf("upload extraction failed: %v", err), log)
		}
		checkout = c
	} else {
		c, err := p.git.Clone(ctx, payload.ScanID, payload.RepoURL, payload.Branch, payload.CloneToken)
		if err != nil {
			return p.fail(ctx, payload.ScanID, task, fmt.Sprintf("clone failed: %v", err), log)
		}
		checkout = c
	}
	defer checkout.Cleanup()

	// ── Size guard ───────────────────────────────────────────────────────────
	if sizeMB, serr := adapters.DirSizeMB(checkout.Dir); serr == nil && sizeMB > p.maxRepoSizeMB {
		msg := fmt.Sprintf("Repository is too large to scan (%d MB, current limit %d MB). "+
			"Scope the scan to specific directories, or contact us about a plan for large monorepos.",
			sizeMB, p.maxRepoSizeMB)
		// Permanent condition — mark failed and skip retry.
		_ = p.store.MarkFailed(ctx, payload.ScanID, msg)
		log.Warn().Msg(msg)
		return fmt.Errorf("%s: %w", msg, asynq.SkipRetry)
	}

	// ── Detect ───────────────────────────────────────────────────────────────
	p.stage(ctx, payload.ScanID, progress.StageDetecting)
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
	p.stage(ctx, payload.ScanID, progress.StageScanning)
	results := p.pipe.Run(ctx, checkout.Dir, payload.ScanID, det, payload.CustomRules)

	// ── Deep scan (opt-in) ───────────────────────────────────────────────────
	// Runs after the fast fan-out; merged + deduped so the same vuln is not
	// double-reported. A skipped/failed deep scan never fails the overall scan.
	// The experimental Joern deep scan is globally gated OFF by default (Track 2f:
	// 0 net-new vulns on real repos). A per-scan request runs it only when the
	// operator has explicitly enabled the engine via DEEP_SCAN_ENABLED.
	if payload.DeepScanEnabled && p.deepScanEnabled {
		p.stage(ctx, payload.ScanID, progress.StageDeepScan)
		deep := p.pipe.Deep(ctx, checkout.Dir, payload.ScanID, payload.DeepScanEngine)
		results = pipeline.MergeDeep(results, deep)
	} else if payload.DeepScanEnabled {
		p.log.Info().Str("scan_id", payload.ScanID).
			Msg("deep scan requested but the engine is disabled (experimental, DEEP_SCAN_ENABLED=false); skipping")
	}

	// ── Aggregate + score ────────────────────────────────────────────────────
	agg := pipeline.Aggregate(results)

	// ── Persist ──────────────────────────────────────────────────────────────
	p.stage(ctx, payload.ScanID, progress.StageFinalizing)
	if err := p.store.SaveResults(ctx, payload.ScanID, payload.ProjectID, agg); err != nil {
		return p.fail(ctx, payload.ScanID, task, fmt.Sprintf("persist results: %v", err), log)
	}

	// SBOM (CycloneDX + SPDX) from the checkout — best-effort, never fails the scan.
	cdx := p.pipe.GenerateSBOM(ctx, checkout.Dir, payload.ScanID, "cyclonedx")
	spdx := p.pipe.GenerateSBOM(ctx, checkout.Dir, payload.ScanID, "spdx")
	if cdx != "" || spdx != "" {
		if err := p.store.SaveSBOMs(ctx, payload.ScanID, cdx, spdx); err != nil {
			log.Warn().Err(err).Msg("persist sbom failed (non-fatal)")
		}
	}

	p.stage(ctx, payload.ScanID, progress.StageCompleted)

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
// failNoRetry marks a scan failed immediately with no Asynq retry — for permanent
// failures (e.g. a malformed or decompression-bomb upload) where retrying cannot
// succeed and would only record a misleading follow-up error.
func (p *ScanProcessor) failNoRetry(ctx context.Context, scanID, msg string, log zerolog.Logger) error {
	if err := p.store.MarkFailed(ctx, scanID, msg); err != nil {
		log.Error().Err(err).Msg("failed to mark scan failed")
	}
	p.stage(ctx, scanID, progress.StageFailed)
	log.Error().Str("reason", msg).Msg("scan failed (no retry)")
	return fmt.Errorf("%s: %w", msg, asynq.SkipRetry)
}

func (p *ScanProcessor) fail(ctx context.Context, scanID string, task *asynq.Task, msg string, log zerolog.Logger) error {
	retried, _ := asynq.GetRetryCount(ctx)
	maxRetry, _ := asynq.GetMaxRetry(ctx)
	if retried >= maxRetry {
		if err := p.store.MarkFailed(ctx, scanID, msg); err != nil {
			log.Error().Err(err).Msg("failed to mark scan failed")
		}
		p.stage(ctx, scanID, progress.StageFailed)
		log.Error().Str("reason", msg).Msg("scan failed (final attempt)")
	} else {
		log.Warn().Str("reason", msg).Int("retry", retried).Msg("scan attempt failed, will retry")
	}
	return fmt.Errorf("%s", msg)
}

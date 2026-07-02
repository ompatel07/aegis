// Package pipeline orchestrates a single scan: detection, parallel scanner
// fan-out, aggregation, and scoring.
package pipeline

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/orchestrator/internal/adapters"
	"github.com/aegis-platform/orchestrator/internal/types"
)

// Pipeline runs the scanner engines for a checked-out repository.
type Pipeline struct {
	scanner *adapters.ScannerClient
	deep    *adapters.ScannerClient // deep-scan sidecar (may equal scanner)
	log     zerolog.Logger
}

func New(scanner, deep *adapters.ScannerClient, log zerolog.Logger) *Pipeline {
	if deep == nil {
		deep = scanner
	}
	return &Pipeline{scanner: scanner, deep: deep, log: log}
}

// engineCall describes one scanner invocation and the pillar it belongs to (so a
// transport failure can be synthesized into a degraded EngineResult).
type engineCall struct {
	engine string
	pillar string
	run    func(ctx context.Context) (*types.EngineResult, error)
}

// Run invokes all five scanner endpoints in parallel. A failure in one engine
// is captured as a degraded result (Error set, no findings) rather than failing
// the whole scan — partial intelligence is better than none.
func (p *Pipeline) Run(ctx context.Context, dir, scanID string, det Detection, customRules []string) []*types.EngineResult {
	langs := det.Languages
	ptypes := det.ProjectTypes

	calls := []engineCall{
		{"semgrep", types.PillarSecurity, func(c context.Context) (*types.EngineResult, error) {
			return p.scanner.SAST(c, dir, scanID, langs, ptypes, customRules)
		}},
		{"trivy", types.PillarSecurity, func(c context.Context) (*types.EngineResult, error) {
			return p.scanner.SCA(c, dir, scanID, langs, ptypes)
		}},
		{"gitleaks", types.PillarSecurity, func(c context.Context) (*types.EngineResult, error) {
			return p.scanner.Secrets(c, dir, scanID, langs, ptypes)
		}},
		{"quality", types.PillarQuality, func(c context.Context) (*types.EngineResult, error) {
			return p.scanner.Quality(c, dir, scanID, langs, ptypes)
		}},
		{"deployment", types.PillarDeployment, func(c context.Context) (*types.EngineResult, error) {
			return p.scanner.Deployment(c, dir, scanID, langs, ptypes)
		}},
	}

	results := make([]*types.EngineResult, len(calls))
	var wg sync.WaitGroup
	wg.Add(len(calls))

	for i, call := range calls {
		go func(idx int, ec engineCall) {
			defer wg.Done()
			res, err := ec.run(ctx)
			if err != nil {
				p.log.Error().Err(err).Str("engine", ec.engine).Str("scan_id", scanID).
					Msg("scanner engine failed (degraded)")
				results[idx] = &types.EngineResult{
					Engine: ec.engine, Pillar: ec.pillar, Status: "failed", Error: err.Error(),
				}
				return
			}
			p.log.Info().
				Str("engine", ec.engine).Str("scan_id", scanID).
				Int("findings", len(res.Findings)).
				Float64("duration_s", res.DurationSeconds).
				Msg("scanner engine completed")
			results[idx] = res
		}(i, call)
	}

	wg.Wait()
	return results
}

// Deep runs the opt-in interprocedural taint scan after the fast fan-out. A
// transport failure is captured as a degraded result (never fails the scan); an
// absent backend tool surfaces from the scanner as status="skipped".
func (p *Pipeline) Deep(ctx context.Context, dir, scanID, engine string) *types.EngineResult {
	if engine == "" {
		engine = "joern"
	}
	res, err := p.deep.Deep(ctx, dir, scanID, engine)
	if err != nil {
		p.log.Error().Err(err).Str("engine", engine).Str("scan_id", scanID).
			Msg("deep scan failed (degraded)")
		return &types.EngineResult{
			Engine: engine, Pillar: types.PillarSecurity, Status: "failed", Error: err.Error(),
		}
	}
	p.log.Info().
		Str("engine", engine).Str("scan_id", scanID).
		Str("status", res.Status).Int("findings", len(res.Findings)).
		Float64("duration_s", res.DurationSeconds).
		Msg("deep scan completed")
	return res
}

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

// GenerateSBOM produces a Software Bill of Materials (cyclonedx | spdx) from the
// checkout. Best-effort: a failure never fails the scan (returns empty + logs).
func (p *Pipeline) GenerateSBOM(ctx context.Context, dir, scanID, format string) string {
	content, components, err := p.scanner.SBOM(ctx, dir, scanID, format)
	if err != nil {
		p.log.Warn().Err(err).Str("scan_id", scanID).Str("format", format).Msg("sbom generation failed")
		return ""
	}
	p.log.Info().Str("scan_id", scanID).Str("format", format).Int("components", components).Msg("sbom generated")
	return content
}

// engineCall describes one scanner invocation and the pillar it belongs to (so a
// transport failure can be synthesized into a degraded EngineResult).
type engineCall struct {
	engine string
	pillar string
	run    func(ctx context.Context) (*types.EngineResult, error)
}

// engineCalls is the single place the engine set is chosen. The deployment engine —
// the ONLY engine that could run a build/install subprocess on customer code — is
// appended ONLY in CI mode. A web/API scan (ciMode=false) therefore has no path to
// it. This is the guarded boundary asserted by TestWebScanNeverInvokesDeployment;
// keep the deployment append gated here and nowhere else.
func (p *Pipeline) engineCalls(dir, scanID string, langs, ptypes, customRules []string, ciMode bool) []engineCall {
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
	}
	if ciMode {
		calls = append(calls, engineCall{"deployment", types.PillarDeployment, func(c context.Context) (*types.EngineResult, error) {
			return p.scanner.Deployment(c, dir, scanID, langs, ptypes)
		}})
	}
	return calls
}

// Run invokes the scanner engines in parallel. A failure in one engine is captured
// as a degraded result (Error set, no findings) rather than failing the whole scan
// — partial intelligence is better than none.
//
// Aegis is a TWO-PILLAR product — Security and Code Quality. The deployment pillar
// is NOT part of the default (web/API) scan: verifying a build means running the
// customer's build (npm ci / mvn package / …) on untrusted code, which breaks the
// no-execute boundary. It is offered ONLY in CI mode (ciMode=true), where the
// customer's own pipeline already built the workspace inside their trust boundary
// and Aegis merely inspects the artifacts — it never builds. A web/API scan
// (ciMode=false) is structurally unable to reach the deployment engine: the call is
// not in its `calls` list at all. This is the guarded boundary from
// TestWebScanNeverInvokesDeployment; do not add the deployment call unconditionally.
func (p *Pipeline) Run(ctx context.Context, dir, scanID string, det Detection, customRules []string, ciMode bool) []*types.EngineResult {
	calls := p.engineCalls(dir, scanID, det.Languages, det.ProjectTypes, customRules, ciMode)

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

package intelligence

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// Syncer runs a single source: fetch → upsert deltas → retroactively flag
// affected scans for newly-published CVEs → record the sync log.
type Syncer struct {
	store *Store
	log   zerolog.Logger
}

func NewSyncer(store *Store, log zerolog.Logger) *Syncer {
	return &Syncer{store: store, log: log}
}

func (sy *Syncer) RunOnce(ctx context.Context, src Source) SyncResult {
	logID, err := sy.store.StartSync(ctx, src.Name())
	if err != nil {
		sy.log.Error().Err(err).Str("source", src.Name()).Msg("intelligence: start sync failed")
		return SyncResult{Source: src.Name()}
	}

	cves, res, err := src.Fetch(ctx)
	if err != nil {
		sy.log.Warn().Err(err).Str("source", src.Name()).Msg("intelligence: fetch failed")
		_ = sy.store.FinishSync(ctx, logID, 0, 0, "failed", truncate(err.Error(), 500))
		return res
	}
	if res.Skipped {
		sy.log.Info().Str("source", src.Name()).Str("note", res.Note).Msg("intelligence: sync skipped")
		_ = sy.store.FinishSync(ctx, logID, 0, 0, "success", res.Note)
		return res
	}

	added, updated, flagged := 0, 0, 0
	for _, c := range cves {
		if c.CVEID == "" {
			continue
		}
		isNew, err := sy.store.UpsertCVE(ctx, c)
		if err != nil {
			continue
		}
		if isNew {
			added++
			if n, err := sy.store.FlagAffectedScans(ctx, c); err == nil {
				flagged += n
			}
		} else {
			updated++
		}
	}
	_ = sy.store.FinishSync(ctx, logID, added, updated, "success", "")
	sy.log.Info().
		Str("source", src.Name()).Int("added", added).Int("updated", updated).
		Int("scans_flagged", flagged).Msg("intelligence: sync complete")
	res.Added, res.Updated = added, updated
	return res
}

// Scheduler runs every source on its own interval, with a staggered first run.
type Scheduler struct {
	syncer  *Syncer
	sources []Source
	log     zerolog.Logger
}

func NewScheduler(store *Store, log zerolog.Logger, sources ...Source) *Scheduler {
	return &Scheduler{syncer: NewSyncer(store, log), sources: sources, log: log}
}

// Start launches a goroutine per source; they stop when ctx is cancelled.
func (sc *Scheduler) Start(ctx context.Context) {
	for i, src := range sc.sources {
		go sc.loop(ctx, i, src)
	}
	sc.log.Info().Int("sources", len(sc.sources)).Msg("intelligence: scheduler started")
}

func (sc *Scheduler) loop(ctx context.Context, idx int, src Source) {
	// Stagger initial runs so we don't hammer every feed at once on boot.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(idx) * 20 * time.Second):
	}
	sc.syncer.RunOnce(ctx, src)

	ticker := time.NewTicker(src.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.syncer.RunOnce(ctx, src)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

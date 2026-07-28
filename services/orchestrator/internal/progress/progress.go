// Package progress publishes live scan-stage updates to Redis pub/sub so the API
// can stream them to the dashboard (SSE) during onboarding and scans.
package progress

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// ChannelPrefix + scanID is the pub/sub channel for one scan's progress.
const ChannelPrefix = "scan:progress:"

// Pipeline stages, in order. Emitted as a scan advances.
const (
	StageCloning    = "cloning"
	StageDetecting  = "detecting"
	StageScanning   = "scanning"
	StageDeepScan   = "deep_scan"
	StageFinalizing = "finalizing"
	StageCompleted  = "completed"
	StageFailed     = "failed"
)

// Update is the payload streamed to clients.
type Update struct {
	ScanID string `json:"scan_id"`
	Stage  string `json:"stage"`
	TS     int64  `json:"ts"`
}

// Publisher fans stage updates out over Redis pub/sub. A nil Publisher is a no-op.
type Publisher struct {
	rdb *redis.Client
}

func NewPublisher(rdb *redis.Client) *Publisher { return &Publisher{rdb: rdb} }

func (p *Publisher) Publish(ctx context.Context, scanID, stage string) {
	if p == nil || p.rdb == nil {
		return
	}
	msg, _ := json.Marshal(Update{ScanID: scanID, Stage: stage, TS: time.Now().Unix()})
	_ = p.rdb.Publish(ctx, ChannelPrefix+scanID, msg).Err()
}

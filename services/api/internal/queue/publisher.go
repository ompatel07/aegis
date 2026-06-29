package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

// Publisher enqueues scan jobs onto the Redis-backed Asynq queue.
type Publisher struct {
	client *asynq.Client
}

// NewPublisher builds a Publisher from Redis connection options.
func NewPublisher(redisAddr, password string, db int) *Publisher {
	client := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     redisAddr,
		Password: password,
		DB:       db,
	})
	return &Publisher{client: client}
}

// EnqueueScan publishes a scan job. Retries and a generous timeout are set so a
// transient scanner failure is retried with Asynq's built-in exponential backoff.
func (p *Publisher) EnqueueScan(ctx context.Context, payload ScanPayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal scan payload: %w", err)
	}

	task := asynq.NewTask(TypeScanRun, body)
	info, err := p.client.EnqueueContext(ctx, task,
		asynq.Queue("scans"),
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Minute),
		asynq.Retention(24*time.Hour),
		// Deduplicate concurrent enqueues for the same scan id.
		asynq.TaskID(payload.ScanID),
	)
	if err != nil {
		// A duplicate task id means the job is already queued — treat as success.
		if err == asynq.ErrTaskIDConflict {
			return payload.ScanID, nil
		}
		return "", fmt.Errorf("enqueue scan: %w", err)
	}
	return info.ID, nil
}

// Close releases the underlying client.
func (p *Publisher) Close() error { return p.client.Close() }

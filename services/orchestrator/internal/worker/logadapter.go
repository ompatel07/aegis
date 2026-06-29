package worker

import (
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
)

// zerologAdapter routes Asynq's internal logs through zerolog so the worker
// emits a single, consistent structured log stream.
type zerologAdapter struct {
	log zerolog.Logger
}

func newAsynqLogger(log zerolog.Logger) asynq.Logger {
	return &zerologAdapter{log: log.With().Str("component", "asynq").Logger()}
}

func (a *zerologAdapter) Debug(args ...any) { a.log.Debug().Msg(fmt.Sprint(args...)) }
func (a *zerologAdapter) Info(args ...any)  { a.log.Info().Msg(fmt.Sprint(args...)) }
func (a *zerologAdapter) Warn(args ...any)  { a.log.Warn().Msg(fmt.Sprint(args...)) }
func (a *zerologAdapter) Error(args ...any) { a.log.Error().Msg(fmt.Sprint(args...)) }
func (a *zerologAdapter) Fatal(args ...any) { a.log.Fatal().Msg(fmt.Sprint(args...)) }

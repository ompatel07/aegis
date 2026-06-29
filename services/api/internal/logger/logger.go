// Package logger configures the process-wide zerolog logger.
package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// New builds a zerolog.Logger. In development it renders human-friendly console
// output; otherwise it emits structured JSON (one object per line).
func New(level string, pretty bool, service string) zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano

	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	var lw zerolog.Logger
	if pretty {
		lw = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).Level(lvl)
	} else {
		lw = zerolog.New(os.Stdout).Level(lvl)
	}

	return lw.With().
		Timestamp().
		Str("service", service).
		Logger()
}

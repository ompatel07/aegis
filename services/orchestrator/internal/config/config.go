// Package config loads and validates orchestrator configuration.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Environment string
	LogLevel    string
	LogPretty   bool

	DatabaseURL       string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	WorkerConcurrency int

	ScannerBaseURL string
	ScannerDeepURL string // deep-scan sidecar (Joern); falls back to ScannerBaseURL
	ScannerTimeout time.Duration

	// DeepScanEnabled globally gates the experimental Joern interprocedural
	// deep-scan engine. OFF by default: Track 2f measured 0 genuine net-new
	// vulnerabilities on 10 real repos (see DEEP_SCAN_VALUE.md). Even when a scan
	// requests deep_scan_enabled, it is skipped unless this operator flag is set.
	DeepScanEnabled bool

	WorkspaceDir  string
	MaxRepoSizeMB int
	GitCloneDepth int

	// Intelligence feed. Both optional: NVD works without a key (lower rate
	// limit); GHSA sync is skipped unless a GitHub token is provided.
	IntelligenceEnabled bool
	NVDAPIKey           string
	GitHubToken         string
}

func Load() (*Config, error) {
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.SetDefault("ENVIRONMENT", "development")
	v.SetDefault("LOG_LEVEL", "info")
	v.SetDefault("LOG_PRETTY", true)
	v.SetDefault("DB_MAX_OPEN_CONNS", 15)
	v.SetDefault("DB_MAX_IDLE_CONNS", 5)
	v.SetDefault("DB_CONN_MAX_LIFETIME_MINUTES", 30)
	v.SetDefault("REDIS_ADDR", "localhost:6379")
	v.SetDefault("REDIS_PASSWORD", "")
	v.SetDefault("REDIS_DB", 0)
	v.SetDefault("WORKER_CONCURRENCY", 5)
	v.SetDefault("SCANNER_BASE_URL", "http://localhost:8000")
	v.SetDefault("SCANNER_DEEP_URL", "")
	v.SetDefault("DEEP_SCAN_ENABLED", false) // experimental; shelved for launch (Track 2f)
	v.SetDefault("SCANNER_TIMEOUT_SECONDS", 900)
	v.SetDefault("WORKSPACE_DIR", "/tmp/aegis-workspaces")
	v.SetDefault("MAX_REPO_SIZE_MB", 512)
	v.SetDefault("GIT_CLONE_DEPTH", 1)
	v.SetDefault("INTELLIGENCE_ENABLED", true)
	v.SetDefault("NVD_API_KEY", "")
	v.SetDefault("GITHUB_TOKEN", "")

	cfg := &Config{
		Environment:       v.GetString("ENVIRONMENT"),
		LogLevel:          v.GetString("LOG_LEVEL"),
		LogPretty:         v.GetBool("LOG_PRETTY"),
		DatabaseURL:       v.GetString("DATABASE_URL"),
		DBMaxOpenConns:    v.GetInt("DB_MAX_OPEN_CONNS"),
		DBMaxIdleConns:    v.GetInt("DB_MAX_IDLE_CONNS"),
		DBConnMaxLifetime: time.Duration(v.GetInt("DB_CONN_MAX_LIFETIME_MINUTES")) * time.Minute,
		RedisAddr:         v.GetString("REDIS_ADDR"),
		RedisPassword:     v.GetString("REDIS_PASSWORD"),
		RedisDB:           v.GetInt("REDIS_DB"),
		WorkerConcurrency: v.GetInt("WORKER_CONCURRENCY"),
		ScannerBaseURL:    v.GetString("SCANNER_BASE_URL"),
		ScannerDeepURL:    v.GetString("SCANNER_DEEP_URL"),
		DeepScanEnabled:   v.GetBool("DEEP_SCAN_ENABLED"),
		ScannerTimeout:    time.Duration(v.GetInt("SCANNER_TIMEOUT_SECONDS")) * time.Second,
		WorkspaceDir:      v.GetString("WORKSPACE_DIR"),
		MaxRepoSizeMB:     v.GetInt("MAX_REPO_SIZE_MB"),
		GitCloneDepth:     v.GetInt("GIT_CLONE_DEPTH"),

		IntelligenceEnabled: v.GetBool("INTELLIGENCE_ENABLED"),
		NVDAPIKey:           v.GetString("NVD_API_KEY"),
		GitHubToken:         v.GetString("GITHUB_TOKEN"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.ScannerBaseURL == "" {
		return nil, fmt.Errorf("SCANNER_BASE_URL is required")
	}
	// Deep scans go to a dedicated sidecar (it bundles the heavy Joern CLI). When
	// unset, deep scans fall back to the main scanner (which returns skipped
	// unless it happens to have Joern installed).
	if cfg.ScannerDeepURL == "" {
		cfg.ScannerDeepURL = cfg.ScannerBaseURL
	}
	return cfg, nil
}

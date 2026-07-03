// Package config loads and validates service configuration from the environment.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration for the API service.
type Config struct {
	Environment string
	LogLevel    string
	LogPretty   bool

	HTTPPort        int
	CORSOrigins     []string
	ShutdownTimeout time.Duration

	DatabaseURL       string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	JWTAccessSecret  string
	JWTRefreshSecret string
	JWTAccessTTL     time.Duration
	JWTRefreshTTL    time.Duration

	TokenEncryptionKey string

	RateLimitRPM int

	// Scanner service — used to validate uploaded custom rules with semgrep.
	ScannerBaseURL string

	// AI layer (opt-in, off by default). Provider is a single switch:
	//   disabled | mock | claude | openai   (openai covers Azure/Bedrock/
	//   self-hosted OpenAI-compatible endpoints via AIBaseURL). Changing it does
	//   not touch any other subsystem.
	AIProvider string
	AIModel    string
	AIAPIKey   string
	AIBaseURL  string
}

// Load reads configuration from environment variables (and an optional .env via
// the host), applies defaults, and validates required secrets.
func Load() (*Config, error) {
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults.
	v.SetDefault("ENVIRONMENT", "development")
	v.SetDefault("LOG_LEVEL", "info")
	v.SetDefault("LOG_PRETTY", true)
	v.SetDefault("API_PORT", 8080)
	v.SetDefault("CORS_ALLOWED_ORIGINS", "http://localhost,http://localhost:3000")
	v.SetDefault("SHUTDOWN_TIMEOUT_SECONDS", 15)
	v.SetDefault("DB_MAX_OPEN_CONNS", 25)
	v.SetDefault("DB_MAX_IDLE_CONNS", 10)
	v.SetDefault("DB_CONN_MAX_LIFETIME_MINUTES", 30)
	v.SetDefault("REDIS_ADDR", "localhost:6379")
	v.SetDefault("REDIS_PASSWORD", "")
	v.SetDefault("REDIS_DB", 0)
	v.SetDefault("JWT_ACCESS_TTL_MINUTES", 15)
	v.SetDefault("JWT_REFRESH_TTL_HOURS", 168)
	v.SetDefault("RATE_LIMIT_RPM", 120)
	v.SetDefault("SCANNER_BASE_URL", "http://scanner:8000")
	v.SetDefault("AI_PROVIDER", "disabled")
	v.SetDefault("AI_MODEL", "")
	v.SetDefault("AI_API_KEY", "")
	v.SetDefault("AI_BASE_URL", "")

	cfg := &Config{
		Environment:        v.GetString("ENVIRONMENT"),
		LogLevel:           v.GetString("LOG_LEVEL"),
		LogPretty:          v.GetBool("LOG_PRETTY"),
		HTTPPort:           v.GetInt("API_PORT"),
		ScannerBaseURL:     v.GetString("SCANNER_BASE_URL"),
		AIProvider:         v.GetString("AI_PROVIDER"),
		AIModel:            v.GetString("AI_MODEL"),
		AIAPIKey:           v.GetString("AI_API_KEY"),
		AIBaseURL:          v.GetString("AI_BASE_URL"),
		CORSOrigins:        splitAndTrim(v.GetString("CORS_ALLOWED_ORIGINS")),
		ShutdownTimeout:    time.Duration(v.GetInt("SHUTDOWN_TIMEOUT_SECONDS")) * time.Second,
		DatabaseURL:        v.GetString("DATABASE_URL"),
		DBMaxOpenConns:     v.GetInt("DB_MAX_OPEN_CONNS"),
		DBMaxIdleConns:     v.GetInt("DB_MAX_IDLE_CONNS"),
		DBConnMaxLifetime:  time.Duration(v.GetInt("DB_CONN_MAX_LIFETIME_MINUTES")) * time.Minute,
		RedisAddr:          v.GetString("REDIS_ADDR"),
		RedisPassword:      v.GetString("REDIS_PASSWORD"),
		RedisDB:            v.GetInt("REDIS_DB"),
		JWTAccessSecret:    v.GetString("JWT_ACCESS_SECRET"),
		JWTRefreshSecret:   v.GetString("JWT_REFRESH_SECRET"),
		JWTAccessTTL:       time.Duration(v.GetInt("JWT_ACCESS_TTL_MINUTES")) * time.Minute,
		JWTRefreshTTL:      time.Duration(v.GetInt("JWT_REFRESH_TTL_HOURS")) * time.Hour,
		TokenEncryptionKey: v.GetString("TOKEN_ENCRYPTION_KEY"),
		RateLimitRPM:       v.GetInt("RATE_LIMIT_RPM"),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.JWTAccessSecret == "" || c.JWTRefreshSecret == "" {
		return fmt.Errorf("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required")
	}
	if len(c.TokenEncryptionKey) != 64 {
		return fmt.Errorf("TOKEN_ENCRYPTION_KEY must be 64 hex chars (32 bytes), got %d", len(c.TokenEncryptionKey))
	}
	return nil
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

"""Structured JSON logging via structlog.

Every log line is a single JSON object so the orchestrator / log aggregator can
parse fields directly. In development we render colorized console output instead.
"""
from __future__ import annotations

import logging
import sys

import structlog


def _live_secret_values() -> list[str]:
    try:
        from enrichment import secret_registry

        return sorted((v for v in secret_registry.all_values() if v), key=len, reverse=True)
    except Exception:  # noqa: BLE001 — logging must never fail
        return []


def _scrub_log_secrets(logger, method_name, event_dict):
    """structlog processor — a DELIBERATE second chokepoint on the log path. The
    EngineResult serializer does not cover log lines or tracebacks, so every log
    record is value-scrubbed against the live secret values (exact string, so
    over-scrubbing is harmless). Placed after format_exc_info so it also scrubs the
    rendered traceback."""
    try:
        vals = _live_secret_values()
        if vals:
            from enrichment import egress

            for k, v in list(event_dict.items()):
                if isinstance(v, str):
                    event_dict[k] = egress._value_scrub(v, vals)
    except Exception:  # noqa: BLE001
        pass
    return event_dict


class _SecretLogFilter(logging.Filter):
    """The same value-scrub for stdlib records (uvicorn / semgrep libs bridged
    through logging.basicConfig, which structlog's processor does not see)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            vals = _live_secret_values()
            if vals:
                from enrichment import egress

                if isinstance(record.msg, str):
                    record.msg = egress._value_scrub(record.msg, vals)
                if record.args:
                    record.args = tuple(
                        egress._value_scrub(a, vals) if isinstance(a, str) else a
                        for a in record.args
                    )
        except Exception:  # noqa: BLE001
            pass
        return True


def configure_logging(level: str = "INFO", environment: str = "development") -> None:
    """Configure structlog + the stdlib logging bridge.

    Call once at startup before any logger is used.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        timestamper,
    ]

    if environment == "development":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors
        + [structlog.processors.format_exc_info, _scrub_log_secrets, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (uvicorn, semgrep libs) through to the same stream.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    # Second chokepoint on the stdlib log path.
    _secret_filter = _SecretLogFilter()
    root = logging.getLogger()
    root.addFilter(_secret_filter)
    for _h in root.handlers:
        _h.addFilter(_secret_filter)
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)

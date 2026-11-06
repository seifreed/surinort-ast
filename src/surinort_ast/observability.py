"""Opt-in, dependency-free logging configuration for the package and CLI."""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TextIO

TRACE = 5
logging.addLevelName(TRACE, "TRACE")

_LOGGER_NAME = "surinort_ast"
_CONTEXT_FIELDS = frozenset({"operation", "request_id", "correlation_id", "trace_id", "span_id"})
_EVENT_FIELDS = (
    "event_name",
    "operation",
    "request_id",
    "correlation_id",
    "trace_id",
    "span_id",
    "duration_ms",
    "returncode",
    "status",
    "outcome",
    "error_type",
    "error_code",
    "dialect",
    "conflict_count",
    "error_count",
    "item_count",
    "plugin_name",
    "plugin_type",
    "rule_count",
)
_context: ContextVar[dict[str, str] | None] = ContextVar("surinort_log_context", default=None)
_secret_assignment = re.compile(
    r"(?i)([\"']?[\w.-]*(?:password|passwd|token|jwt|session[_-]?id|access[_-]?key|"
    r"api[_-]?key|secret|authorization|cookie|set-cookie|private[_-]?key)[\w.-]*"
    r"[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
)
_credential = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_url_password = re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@")
_private_key = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----",
    re.DOTALL | re.IGNORECASE,
)


def _safe_text(value: str) -> str:
    value = _private_key.sub("[REDACTED PRIVATE KEY]", value)
    value = _credential.sub("[REDACTED CREDENTIAL]", value)
    value = _url_password.sub(r"\1[REDACTED]@", value)
    value = _secret_assignment.sub(r"\1[REDACTED]", value)
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in value)


class _SafeFormatter(logging.Formatter):
    def _prepare(self, original: logging.LogRecord) -> logging.LogRecord:
        record = copy.copy(original)
        record.msg = _safe_text(record.getMessage())
        record.args = ()
        if record.exc_info:
            if not hasattr(record, "error_type"):
                record.error_type = type(record.exc_info[1]).__name__
            record.exc_text = _safe_text(self.formatException(record.exc_info))
            record.exc_info = None
        return record


class _TextFormatter(_SafeFormatter):
    def format(self, record: logging.LogRecord) -> str:
        record = self._prepare(record)
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        payload: dict[str, str | int | float | bool] = {
            "service": "surinort-ast",
            "component": record.name.removeprefix(f"{_LOGGER_NAME}."),
        }
        environment = os.getenv("SURINORT_ENVIRONMENT")
        if environment:
            payload["environment"] = _safe_text(environment)
        for field in _EVENT_FIELDS:
            value = getattr(record, field, None)
            if isinstance(value, str):
                payload[field] = _safe_text(value)
            elif isinstance(value, (int, float, bool)):
                payload[field] = value
        result = f"{timestamp} {record.levelname} {record.name}: {record.getMessage()}" + (
            " " + " ".join(f"{key}={json.dumps(value)}" for key, value in payload.items())
            if payload
            else ""
        )
        return f"{result}\n{record.exc_text}" if record.exc_text else result


class _JsonFormatter(_SafeFormatter):
    def format(self, original: logging.LogRecord) -> str:
        record = self._prepare(original)
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        payload: dict[str, str | int | float | bool] = {
            "timestamp": timestamp.replace("+00:00", "Z"),
            "level": record.levelname,
            "message": record.getMessage(),
            "service": "surinort-ast",
            "component": record.name.removeprefix(f"{_LOGGER_NAME}."),
        }
        environment = os.getenv("SURINORT_ENVIRONMENT")
        if environment:
            payload["environment"] = _safe_text(environment)
        for field in _EVENT_FIELDS:
            value = getattr(record, field, None)
            if isinstance(value, str):
                payload[field] = _safe_text(value)
            elif isinstance(value, (int, float, bool)):
                payload[field] = value
        if record.exc_text:
            payload["stack_trace"] = record.exc_text
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for field, value in (_context.get() or {}).items():
            if not hasattr(record, field):
                setattr(record, field, value)
        return True


@contextmanager
def log_context(**fields: str) -> Iterator[None]:
    """Bind safe correlation fields for logs emitted in the current context."""
    unknown = fields.keys() - _CONTEXT_FIELDS
    if unknown:
        raise ValueError(f"Unsupported log context fields: {', '.join(sorted(unknown))}")
    token = _context.set({**(_context.get() or {}), **fields})
    try:
        yield
    finally:
        _context.reset(token)


def configure_logging(
    level: str | int | None = None,
    log_format: str | None = None,
    stream: TextIO | None = None,
) -> None:
    """Configure package logs on stderr by default; imports never configure logging."""
    selected_level = level if level is not None else os.getenv("SURINORT_LOG_LEVEL", "WARNING")
    if isinstance(selected_level, str):
        selected_level = (
            TRACE
            if selected_level.upper() == "TRACE"
            else logging.getLevelName(selected_level.upper())
        )
    if not isinstance(selected_level, int) or selected_level < 0:
        raise ValueError(
            "Log level must be TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL, or an integer"
        )

    format_value = (
        log_format if log_format is not None else os.getenv("SURINORT_LOG_FORMAT") or "text"
    )
    selected_format = format_value.lower()
    if selected_format not in {"text", "json"}:
        raise ValueError("Log format must be 'text' or 'json'")

    package_logger = logging.getLogger(_LOGGER_NAME)
    package_logger.setLevel(selected_level)
    package_logger.propagate = False
    for handler in package_logger.handlers[:]:
        if getattr(handler, "_surinort_owned", False):
            package_logger.removeHandler(handler)
            handler.close()

    handler = _PackageStreamHandler(stream if stream is not None else sys.stderr)
    handler.addFilter(_ContextFilter())
    handler.setFormatter(_JsonFormatter() if selected_format == "json" else _TextFormatter())
    package_logger.addHandler(handler)


def add_logging_handler(handler: logging.Handler, log_format: str = "json") -> None:
    """Attach an application-owned handler with the package's safe formatter."""
    selected_format = log_format.lower()
    if selected_format not in {"text", "json"}:
        raise ValueError("Log format must be 'text' or 'json'")

    package_logger = logging.getLogger(_LOGGER_NAME)
    package_logger.propagate = False
    if not any(isinstance(item, _ContextFilter) for item in handler.filters):
        handler.addFilter(_ContextFilter())
    handler.setFormatter(_JsonFormatter() if selected_format == "json" else _TextFormatter())
    if handler not in package_logger.handlers:
        package_logger.addHandler(handler)


class _PackageStreamHandler(logging.StreamHandler[TextIO]):
    """Identify the one handler this explicit configuration owns."""

    _surinort_owned = True

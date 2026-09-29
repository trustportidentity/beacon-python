"""TrustPort Beacon APM SDK for Python (ASGI/FastAPI, WSGI/Django, Flask)."""

from __future__ import annotations

import contextvars
import json
import random
import re
import secrets
import threading
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional, Tuple
from urllib import request as urllib_request
from urllib.error import URLError

__version__ = "1.0.0"

_ALWAYS_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "token",
    "secret",
    "password",
}

_CARD_NUMBER_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def sanitize_headers(headers: dict) -> dict:
    sanitized = {}
    for k, v in headers.items():
        lower_k = str(k).lower()
        if (
            lower_k in _ALWAYS_SENSITIVE_HEADERS
            or "token" in lower_k
            or "secret" in lower_k
            or ("key" in lower_k and lower_k != "key")
        ):
            sanitized[k] = "[Filtered]"
        else:
            sanitized[k] = v
    return sanitized


def sanitize_string(value: str) -> str:
    return _CARD_NUMBER_RE.sub("[redacted-card]", value)


def generate_trace_id() -> str:
    return secrets.token_hex(16)


def generate_span_id() -> str:
    return secrets.token_hex(8)


def parse_traceparent(header: Optional[str]) -> Optional[Tuple[str, str, bool]]:
    if not header or not isinstance(header, str):
        return None
    trimmed = header.strip()
    if len(trimmed) != 55:
        return None
    parts = trimmed.split("-")
    if len(parts) != 4:
        return None
    if len(parts[0]) != 2 or len(parts[1]) != 32 or len(parts[2]) != 16 or len(parts[3]) != 2:
        return None
    try:
        int(parts[1], 16)
        int(parts[2], 16)
    except ValueError:
        return None
    if parts[1] == "0" * 32 or parts[2] == "0" * 16:
        return None
    return parts[1].lower(), parts[2].lower(), parts[3] == "01"


@dataclass
class _Span:
    trace: "_ActiveTrace"
    span_type: str
    name: str
    metadata: Optional[dict] = None
    span_id: str = field(default_factory=generate_span_id)
    parent_span_id: Optional[str] = None
    started_at: float = field(default_factory=time.monotonic)
    tags: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.parent_span_id is None:
            self.parent_span_id = self.trace.span_id

    def set_tag(self, key: str, value: Any) -> "_Span":
        self.tags[key] = str(value)
        return self

    def end(self) -> None:
        duration_ms = (time.monotonic() - self.started_at) * 1000
        start_ms = max(0.0, (self.started_at - self.trace.started_at) * 1000)
        self.trace.spans.append(
            {
                "span_id": self.span_id,
                "parent_span_id": self.parent_span_id,
                "type": self.span_type,
                "name": self.name,
                "start_ms": round(start_ms, 2),
                "duration_ms": round(duration_ms, 2),
                "metadata": self.metadata,
                "tags": self.tags or None,
            }
        )

    def __enter__(self) -> "_Span":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.end()


class _ActiveTrace:
    def __init__(self, header_or_trace_id: Optional[str] = None):
        parsed = parse_traceparent(header_or_trace_id)
        if parsed:
            self.trace_id = parsed[0]
            self.parent_span_id: Optional[str] = parsed[1]
        elif header_or_trace_id and header_or_trace_id.strip():
            self.trace_id = header_or_trace_id.strip()
            self.parent_span_id = None
        else:
            self.trace_id = generate_trace_id()
            self.parent_span_id = None

        self.span_id = generate_span_id()
        self.started_at = time.monotonic()
        self.spans: list = []
        self.breadcrumbs: list = []
        self.user: Optional[dict] = None

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-01"

    def identify(self, **user: Any) -> None:
        self.user = user

    def add_breadcrumb(
        self,
        category: str,
        message: str,
        level: str = "info",
        data: Optional[dict] = None,
    ) -> None:
        self.breadcrumbs.append(
            {
                "category": category,
                "message": message,
                "level": level,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": data,
            }
        )
        if len(self.breadcrumbs) > 100:
            self.breadcrumbs.pop(0)

    def start_span(self, name: str, span_type: str = "custom", metadata: Optional[dict] = None) -> _Span:
        return _Span(self, span_type, name, metadata)

    def start_job_span(
        self,
        job_name: str,
        queue: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> _Span:
        meta = dict(metadata or {})
        if queue:
            meta["queue"] = queue
        span = _Span(self, "job", f"JOB {job_name}", meta)
        span.set_tag("job", job_name)
        if queue:
            span.set_tag("queue", queue)
        return span


_current_trace: contextvars.ContextVar[Optional[_ActiveTrace]] = contextvars.ContextVar(
    "beacon_current_trace", default=None
)


def current_trace() -> Optional[_ActiveTrace]:
    return _current_trace.get()


def identify(**user: Any) -> None:
    """Attach a user identity to the request currently being handled."""
    trace = _current_trace.get()
    if trace is not None:
        trace.identify(**user)


def add_breadcrumb(
    category: str,
    message: str,
    level: str = "info",
    data: Optional[dict] = None,
) -> None:
    """Record a breadcrumb (log, database query, HTTP call) into the active trace."""
    trace = _current_trace.get()
    if trace is not None:
        trace.add_breadcrumb(category, message, level, data)


def inject_traceparent(headers: dict, trace: Optional[_ActiveTrace] = None) -> dict:
    """Injects W3C traceparent header into outgoing HTTP headers dict."""
    active = trace or current_trace()
    if active:
        headers["traceparent"] = active.traceparent
    return headers


@contextmanager
def beacon_span(name: str, span_type: str = "custom", **metadata: Any) -> Iterator[_Span]:
    """Context manager for a child span on the request currently being handled."""
    trace = _current_trace.get()
    if trace is None:
        trace = _ActiveTrace()
    span = trace.start_span(name, span_type, metadata or None)
    try:
        yield span
    finally:
        span.end()


def start_job_span(
    job_name: str,
    queue: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> Optional[_Span]:
    """Start a background job or queue execution span in the active trace."""
    trace = _current_trace.get()
    return trace.start_job_span(job_name, queue, metadata) if trace is not None else None


@contextmanager
def beacon_job_span(job_name: str, queue: Optional[str] = None, **metadata: Any) -> Iterator[_Span]:
    """Context manager for tracing background job / queue worker execution."""
    trace = _current_trace.get()
    if trace is None:
        trace = _ActiveTrace()
    span = trace.start_job_span(job_name, queue, metadata or None)
    try:
        yield span
    finally:
        span.end()


class _Client:
    def __init__(
        self,
        ingest_url: str,
        api_key: str,
        service_name: str,
        environment: str = "production",
        batch_size: int = 50,
        flush_interval: float = 1.0,
        sanitize_pii: bool = False,
        sample_rate: float = 1.0,
    ):
        self.ingest_url = ingest_url.rstrip("/")
        self.api_key = api_key
        self.service_name = service_name
        self.environment = environment
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.sanitize_pii = sanitize_pii
        self.sample_rate = sample_rate if 0 < sample_rate <= 1 else 1.0
        self._queue: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _should_sample(self, has_exception: bool) -> bool:
        """Exceptions are always sent regardless of sample_rate - sampling controls ingest
        volume for routine traffic, never error visibility."""
        if has_exception or self.sample_rate >= 1:
            return True
        return random.random() < self.sample_rate

    def report(self, trace: _ActiveTrace, request: dict, duration_ms: float, exception: Optional[dict] = None) -> None:
        if not self._should_sample(exception is not None):
            return
        
        headers = sanitize_headers(request.get("headers") or {})
        request = {**request, "headers": headers}
        if self.sanitize_pii and request.get("url"):
            request = {**request, "url": sanitize_string(request["url"])}

        event = {
            "id": trace.trace_id,
            "project_key": self.api_key,
            "service_name": self.service_name,
            "environment": self.environment,
            "runtime": "python",
            "trace_id": trace.trace_id,
            "parent_span": trace.parent_span_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_ms": round(duration_ms, 2),
            "user": trace.user,
            "request": request,
            "spans": trace.spans,
            "breadcrumbs": trace.breadcrumbs,
            "has_exception": exception is not None,
            "exception": exception,
        }
        with self._lock:
            self._queue.append(event)
            should_flush = len(self._queue) >= self.batch_size
        if should_flush:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._queue:
                return
            batch = self._queue
            self._queue = []
        try:
            body = json.dumps(batch).encode("utf-8")
            req = urllib_request.Request(
                f"{self.ingest_url}/v1/batch",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Beacon-Key": self.api_key,
                    # Some edge proxies (e.g. Cloudflare) block urllib's default
                    # "Python-urllib/x.y" user agent as a bot; without this, every
                    # batch silently 403s and no telemetry ever arrives.
                    "User-Agent": f"trustportidentity-beacon-python/{__version__}",
                },
            )
            urllib_request.urlopen(req, timeout=3)
        except (URLError, OSError):
            pass  # Non-blocking telemetry failure

    def _run(self) -> None:
        while not self._stop.wait(self.flush_interval):
            self.flush()

    def close(self) -> None:
        self._stop.set()
        self.flush()


_client: Optional[_Client] = None


def init(
    ingest_url: str = "http://localhost:8443",
    api_key: str = "",
    service_name: str = "python-service",
    environment: str = "production",
    batch_size: int = 50,
    flush_interval: float = 1.0,
    sanitize_pii: bool = False,
    sample_rate: float = 1.0,
) -> _Client:
    global _client
    _client = _Client(ingest_url, api_key, service_name, environment, batch_size, flush_interval, sanitize_pii, sample_rate)
    return _client


def close() -> None:
    if _client is not None:
        _client.close()


class BeaconMiddleware:
    """ASGI middleware for FastAPI/Starlette. Add via app.add_middleware(BeaconMiddleware, ...)."""

    def __init__(
        self,
        app: Callable,
        ingest_url: str = "http://localhost:8443",
        api_key: str = "",
        service_name: str = "python-service",
        environment: str = "production",
        batch_size: int = 50,
        flush_interval: float = 1.0,
        sanitize_pii: bool = False,
        sample_rate: float = 1.0,
    ):
        self.app = app
        global _client
        if _client is None:
            _client = _Client(ingest_url, api_key, service_name, environment, batch_size, flush_interval, sanitize_pii, sample_rate)
        self.client = _client

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        trace = _ActiveTrace(headers.get("traceparent"))
        token = _current_trace.set(trace)
        start = time.monotonic()
        status_holder = {"code": 200}

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
                resp_headers = list(message.get("headers", []))
                resp_headers.append((b"traceparent", trace.traceparent.encode("ascii")))
                message["headers"] = resp_headers
            await send(message)

        exception_info = None
        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:  # noqa: BLE001 - report then re-raise
            exception_info = {
                "type": type(exc).__name__,
                "message": str(exc),
                "handled": False,
                "stacktrace": [
                    {"file": frame.filename, "line": frame.lineno, "function": frame.name}
                    for frame in traceback.extract_tb(exc.__traceback__)
                ],
            }
            status_holder["code"] = 500
            raise
        finally:
            duration_ms = (time.monotonic() - start) * 1000
            client_ip = None
            if scope.get("client"):
                client_ip = scope["client"][0]
            self.client.report(
                trace,
                {
                    "method": scope.get("method", ""),
                    "route": scope.get("path", ""),
                    "url": scope.get("path", "") + (("?" + scope["query_string"].decode()) if scope.get("query_string") else ""),
                    "status_code": status_holder["code"],
                    "headers": headers,
                    "client_ip": client_ip,
                },
                duration_ms,
                exception_info,
            )
            _current_trace.reset(token)

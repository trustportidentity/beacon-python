"""TrustPort Beacon APM SDK for Python (ASGI/FastAPI, WSGI/Django, Flask)."""

from __future__ import annotations

import contextvars
import json
import random
import re
import threading
import time
import traceback
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional
from urllib import request as urllib_request
from urllib.error import URLError

__version__ = "1.0.0"

_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}
_CARD_NUMBER_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _sanitize_headers(headers: dict) -> dict:
    return {
        k: ("[redacted]" if k.lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def _sanitize_string(value: str) -> str:
    return _CARD_NUMBER_RE.sub("[redacted-card]", value)


@dataclass
class _Span:
    trace: "_ActiveTrace"
    span_type: str
    name: str
    metadata: Optional[dict] = None
    started_at: float = field(default_factory=time.monotonic)
    tags: dict = field(default_factory=dict)

    def set_tag(self, key: str, value: Any) -> "_Span":
        self.tags[key] = str(value)
        return self

    def end(self) -> None:
        duration_ms = (time.monotonic() - self.started_at) * 1000
        start_ms = max(0.0, (self.started_at - self.trace.started_at) * 1000)
        self.trace.spans.append(
            {
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
    def __init__(self, trace_id: Optional[str] = None):
        self.trace_id = trace_id or str(uuid.uuid4())
        self.started_at = time.monotonic()
        self.spans: list = []
        self.user: Optional[dict] = None

    def identify(self, **user: Any) -> None:
        self.user = user

    def start_span(self, name: str, span_type: str = "custom", metadata: Optional[dict] = None) -> _Span:
        return _Span(self, span_type, name, metadata)


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
        if self.sanitize_pii:
            if request.get("headers"):
                request = {**request, "headers": _sanitize_headers(request["headers"])}
            if request.get("url"):
                request = {**request, "url": _sanitize_string(request["url"])}

        event = {
            "id": trace.trace_id,
            "project_key": self.api_key,
            "service_name": self.service_name,
            "environment": self.environment,
            "runtime": "python",
            "trace_id": trace.trace_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_ms": round(duration_ms, 2),
            "user": trace.user,
            "request": request,
            "spans": trace.spans,
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

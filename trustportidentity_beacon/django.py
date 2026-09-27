"""Django WSGI middleware. Add 'trustportidentity_beacon.django.BeaconMiddleware' to
MIDDLEWARE, and configure via Django settings: BEACON_INGEST_URL, BEACON_API_KEY,
BEACON_SERVICE_NAME, BEACON_ENVIRONMENT."""

from __future__ import annotations

import time
import traceback
from typing import Callable

from django.conf import settings

from . import _ActiveTrace, _Client, _current_trace


class BeaconMiddleware:
    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.client = _Client(
            ingest_url=getattr(settings, "BEACON_INGEST_URL", "http://localhost:8443"),
            api_key=getattr(settings, "BEACON_API_KEY", ""),
            service_name=getattr(settings, "BEACON_SERVICE_NAME", "django-service"),
            environment=getattr(settings, "BEACON_ENVIRONMENT", "production"),
            sanitize_pii=getattr(settings, "BEACON_SANITIZE_PII", False),
        )

    def __call__(self, request):
        trace = _ActiveTrace(request.headers.get("traceparent"))
        token = _current_trace.set(trace)
        start = time.monotonic()
        exception_info = None

        try:
            response = self.get_response(request)
            status_code = response.status_code
        except Exception as exc:  # noqa: BLE001
            status_code = 500
            exception_info = {
                "type": type(exc).__name__,
                "message": str(exc),
                "handled": False,
                "stacktrace": [
                    {"file": f.filename, "line": f.lineno, "function": f.name}
                    for f in traceback.extract_tb(exc.__traceback__)
                ],
            }
            _current_trace.reset(token)
            raise

        duration_ms = (time.monotonic() - start) * 1000
        self.client.report(
            trace,
            {
                "method": request.method,
                "route": request.path,
                "url": request.get_full_path(),
                "status_code": status_code,
                "headers": dict(request.headers),
                "client_ip": request.META.get("REMOTE_ADDR"),
            },
            duration_ms,
            exception_info,
        )
        _current_trace.reset(token)
        return response

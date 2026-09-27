# trustportidentity-beacon

Official TrustPort Beacon APM SDK for Python.

## Install

```bash
pip install git+https://github.com/trustportidentity/beacon-python.git
```

## FastAPI / Starlette

```python
from fastapi import FastAPI, Request
from trustportidentity_beacon import BeaconMiddleware, beacon_span

app = FastAPI()

app.add_middleware(
    BeaconMiddleware,
    ingest_url="https://beacon-api.trustportidentity.com",
    api_key="tb_live_...",
    service_name="python-ml-service",
    environment="production",
)

@app.post("/api/v1/predict")
async def predict(request: Request):
    with beacon_span("ml.inference.bert_classifier") as span:
        span.set_tag("model_version", "v2.4")
        return {"label": "risk_low", "confidence": 0.98}
```

## Django

```python
# settings.py
MIDDLEWARE = [
    "trustportidentity_beacon.django.BeaconMiddleware",
    # ...
]
BEACON_INGEST_URL = "https://beacon-api.trustportidentity.com"
BEACON_API_KEY = "tb_live_..."
BEACON_SERVICE_NAME = "django-service"
```

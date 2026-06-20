"""
FastAPI inference server.

Loads the trained ensemble artifact once at startup and serves
low-latency prediction endpoints. Stateless w.r.t. predictions (every
request is independent), so it can be replicated behind a load balancer.

Endpoints
---------
GET  /health         liveness + model status
POST /predict        score a single flow
POST /predict/batch  score many flows in one call
GET  /metrics        rolling operational metrics (dashboard polls this)
GET  /              redirect to interactive docs

Run:
    uvicorn api_server.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from api_server.metrics import MetricsTracker
from ml_training.model import EnsembleDDoSModel
from utils.config import CONFIG, DDOS_LABELS
from utils.logger import get_logger
from utils.schemas import (
    FlowFeatures, BatchFlowRequest,
    PredictionResponse, BatchPredictionResponse,
    HealthResponse, MetricsResponse,
)

logger = get_logger("api_server.app", CONFIG.log_dir, CONFIG.log_level)

# Module-level state, populated at startup.
_STATE: dict = {"model": None, "start_time": time.time()}
_metrics = MetricsTracker()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the model once when the server boots; release it on shutdown."""
    logger.info("API starting — loading model from %s", CONFIG.model.model_path)
    try:
        _STATE["model"] = EnsembleDDoSModel.load(CONFIG.model.model_path)
        _STATE["start_time"] = time.time()
        logger.info("Model loaded successfully — API ready.")
    except (FileNotFoundError, ImportError) as exc:
        # The server still starts so /health can report the problem,
        # but prediction endpoints will return 503.
        logger.error("Model could not be loaded: %s", exc)
        _STATE["model"] = None
    yield
    logger.info("API shutting down.")


app = FastAPI(
    title="Cloud DDoS Detection API",
    description="Ensemble (XGBoost + Random Forest) real-time DDoS detection.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — the Streamlit dashboard runs on a different port/origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten to the dashboard origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)


def _require_model() -> EnsembleDDoSModel:
    """Return the loaded model or raise 503 if it is unavailable."""
    model = _STATE.get("model")
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Train a model first "
                   "(python -m ml_training.train ...).",
        )
    return model


def _true_is_ddos(label: str | None) -> bool | None:
    """Interpret an optional ground-truth label for live-metrics purposes."""
    if label is None:
        return None
    return str(label).strip().lower() != "benign"


# --------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse)
async def health():
    """Liveness probe — used by Docker healthcheck and the dashboard."""
    model = _STATE.get("model")
    return HealthResponse(
        status="ok" if model is not None else "degraded",
        model_loaded=model is not None,
        model_path=CONFIG.model.model_path,
        feature_count=len(model.fe.feature_cols) if model else 0,
        uptime_seconds=time.time() - _STATE["start_time"],
    )


@app.post("/predict", response_model=PredictionResponse)
async def predict(flow: FlowFeatures):
    """Score a single network flow."""
    model = _require_model()
    t0 = time.perf_counter()

    result = model.predict_one(flow.features)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    is_alert = result.confidence >= CONFIG.api.alert_threshold
    _metrics.record(
        is_ddos=result.is_ddos,
        confidence=result.confidence,
        is_alert=is_alert,
        latency_ms=latency_ms,
        true_is_ddos=_true_is_ddos(flow.true_label),
    )

    if is_alert:
        logger.warning("ALERT flow_id=%s confidence=%.3f true_label=%s",
                       flow.flow_id, result.confidence, flow.true_label)

    return PredictionResponse(
        flow_id=flow.flow_id,
        is_ddos=result.is_ddos,
        confidence=result.confidence,
        rf_score=result.rf_score,
        xgb_score=result.xgb_score,
        is_alert=is_alert,
        threshold=model.cfg.decision_threshold,
        latency_ms=latency_ms,
    )


@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: BatchFlowRequest):
    """Score many flows in one call — higher throughput than looping /predict."""
    model = _require_model()
    if not request.flows:
        raise HTTPException(status_code=400, detail="Empty flow list.")

    t0 = time.perf_counter()
    import pandas as pd
    rows = [f.features for f in request.flows]
    results = model.predict_batch(pd.DataFrame(rows))
    total_latency_ms = (time.perf_counter() - t0) * 1000.0
    per_flow_latency = total_latency_ms / len(results)

    responses = []
    for flow, result in zip(request.flows, results):
        is_alert = result.confidence >= CONFIG.api.alert_threshold
        _metrics.record(
            is_ddos=result.is_ddos,
            confidence=result.confidence,
            is_alert=is_alert,
            latency_ms=per_flow_latency,
            true_is_ddos=_true_is_ddos(flow.true_label),
        )
        responses.append(PredictionResponse(
            flow_id=flow.flow_id,
            is_ddos=result.is_ddos,
            confidence=result.confidence,
            rf_score=result.rf_score,
            xgb_score=result.xgb_score,
            is_alert=is_alert,
            threshold=model.cfg.decision_threshold,
            latency_ms=per_flow_latency,
        ))

    return BatchPredictionResponse(
        predictions=responses,
        count=len(responses),
        total_latency_ms=total_latency_ms,
    )


@app.get("/metrics", response_model=MetricsResponse)
async def metrics():
    """Rolling operational metrics. The dashboard polls this every second."""
    return MetricsResponse(**_metrics.snapshot())

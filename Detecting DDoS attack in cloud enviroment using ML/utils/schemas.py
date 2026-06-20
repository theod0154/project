"""
Shared data contracts (Pydantic models).

These define the request/response schema for the API. Keeping them in
utils/ means both the api_server and the simulation client import the
*same* definitions — the contract can never silently drift.
"""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class FlowFeatures(BaseModel):
    """
    A single network flow's features.

    Accepts an arbitrary dict of numeric feature_name -> value pairs.
    We deliberately do NOT hard-code every column: the BCCC dataset has
    ~80 features and the FeatureEngineer derives more. The model's stored
    feature list is the source of truth; any missing feature is zero-filled
    server-side. This keeps the API resilient to minor schema changes.
    """
    features: dict[str, float] = Field(
        ..., description="Mapping of flow feature name to numeric value."
    )
    flow_id: Optional[str] = Field(
        None, description="Optional client-supplied identifier for tracing."
    )
    true_label: Optional[str] = Field(
        None,
        description="Ground-truth label, if known. Used ONLY for live "
                    "accuracy metrics during simulation; never used for prediction.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "features": {
                    "total_packets": 1240, "total_bytes": 62000,
                    "syn_flag_count": 1200, "ack_flag_count": 5,
                    "flow_duration": 0.8,
                },
                "flow_id": "flow-0001",
                "true_label": "DDoS-SYN-Flood",
            }
        }
    }


class BatchFlowRequest(BaseModel):
    """A batch of flows for higher-throughput scoring."""
    flows: list[FlowFeatures]


class PredictionResponse(BaseModel):
    """The model's verdict on one flow."""
    flow_id: Optional[str]
    is_ddos: bool = Field(..., description="True if classified as DDoS.")
    confidence: float = Field(..., ge=0.0, le=1.0,
                              description="Ensemble probability of the DDoS class.")
    rf_score: float = Field(..., ge=0.0, le=1.0,
                            description="Random Forest sub-model probability.")
    xgb_score: float = Field(..., ge=0.0, le=1.0,
                             description="XGBoost sub-model probability.")
    is_alert: bool = Field(..., description="True if confidence >= alert threshold.")
    threshold: float = Field(..., description="Decision threshold used.")
    latency_ms: float = Field(..., description="Server-side inference latency.")


class BatchPredictionResponse(BaseModel):
    predictions: list[PredictionResponse]
    count: int
    total_latency_ms: float


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_path: str
    feature_count: int
    uptime_seconds: float


class MetricsResponse(BaseModel):
    """Rolling operational metrics — what the dashboard polls."""
    total_predictions: int
    ddos_detected: int
    benign_detected: int
    alerts_raised: int
    ddos_rate: float
    avg_confidence: float
    avg_latency_ms: float
    # Live accuracy stats, populated only when true_label is supplied
    live_accuracy: Optional[float] = None
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

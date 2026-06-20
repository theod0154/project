"""
Centralized configuration management.

All tunable parameters live here instead of being scattered as magic
numbers across the codebase. Values can be overridden by environment
variables (useful for Docker) or a YAML file (useful for experiments).

Precedence:  defaults  <  config.yaml  <  environment variables
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import yaml  # optional; only needed if a YAML override file is used
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# --------------------------------------------------------------------------
# Domain constants — the label taxonomy of BCCC-cPacket-Cloud-DDoS-2024.
# Kept as module-level constants because they describe the dataset itself,
# not a tunable parameter.
# --------------------------------------------------------------------------
DDOS_LABELS = [
    "DDoS-SYN-Flood", "DDoS-UDP-Flood", "DDoS-HTTP-Flood",
    "DDoS-ICMP-Flood", "DDoS-DNS-Amplification", "DDoS-NTP-Amplification",
    "DDoS-SSDP-Amplification", "DDoS-Memcached-Amplification",
    "DDoS-TFTP-Amplification", "DDoS-SNMP-Amplification",
    "DDoS-TCP-ACK-Flood", "DDoS-TCP-RST-Flood", "DDoS-TCP-FIN-Flood",
    "DDoS-Slowloris", "DDoS-Rudy", "DDoS-Slow-Read", "DDoS-HTTP-GET-Flood",
]
BENIGN_LABELS = [
    "Benign",  # the dataset's primary benign label
    "Benign-Web", "Benign-Email", "Benign-Streaming", "Benign-VOIP",
    "Benign-FTP", "Benign-SSH", "Benign-Database", "Benign-DNS",
]

# Meta / identifier columns that must never be used as model features —
# they leak information (IPs, ports) or are non-predictive (timestamps).
EXCLUDE_COLS = {
    "label", "src_ip", "dst_ip", "src_port", "dst_port",
    "timestamp", "flow_id", "src_mac", "dst_mac",
    "attack_type", "category", "class",
}


def _env(key: str, default: Any, cast=str) -> Any:
    """Read an environment variable with a typed fallback."""
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        if cast is bool:
            return raw.lower() in ("1", "true", "yes", "on")
        return cast(raw)
    except (ValueError, TypeError):
        return default


@dataclass
class DataConfig:
    """Where data lives and how much of it to use."""
    dataset_path: str = _env("DDOS_DATASET_PATH", "data/BCCC-cPacket-Cloud-DDoS-2024")
    sample_frac: float = _env("DDOS_SAMPLE_FRAC", 1.0, float)
    random_state: int = 42
    test_size: float = 0.2


@dataclass
class ModelConfig:
    """Hyperparameters for the ensemble. Tuned for tabular flow data."""
    # Random Forest
    rf_n_estimators: int = 300
    rf_max_depth: int = 22
    rf_min_samples_split: int = 5
    rf_min_samples_leaf: int = 2

    # XGBoost
    xgb_n_estimators: int = 400
    xgb_max_depth: int = 8
    xgb_learning_rate: float = 0.08
    xgb_subsample: float = 0.85
    xgb_colsample_bytree: float = 0.85

    # Ensemble blend weights (must sum to 1.0)
    rf_weight: float = 0.5
    xgb_weight: float = 0.5

    # Decision threshold for the binary Benign(0)/DDoS(1) call
    decision_threshold: float = 0.50

    # Cross-validation
    cv_folds: int = 5

    # Where the trained artifact is written / read
    model_dir: str = _env("DDOS_MODEL_DIR", "models")
    model_filename: str = "ddos_model.pkl"

    @property
    def model_path(self) -> str:
        return os.path.join(self.model_dir, self.model_filename)


@dataclass
class APIConfig:
    """FastAPI inference server settings."""
    host: str = _env("DDOS_API_HOST", "0.0.0.0")
    port: int = _env("DDOS_API_PORT", 8000, int)
    # Confidence at/above which a prediction is escalated to an alert
    alert_threshold: float = _env("DDOS_ALERT_THRESHOLD", 0.75, float)
    # Rolling in-memory window of recent predictions exposed at /metrics
    metrics_window: int = 1000


@dataclass
class SimConfig:
    """Traffic-replay simulator settings."""
    api_url: str = _env("DDOS_API_URL", "http://localhost:8000")
    flows_per_second: int = _env("DDOS_SIM_SPEED", 15, int)
    duration_seconds: int = _env("DDOS_SIM_DURATION", 120, int)


@dataclass
class Config:
    """Top-level config aggregating every sub-config."""
    data: DataConfig = field(default_factory=DataConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    api: APIConfig = field(default_factory=APIConfig)
    sim: SimConfig = field(default_factory=SimConfig)
    log_level: str = _env("DDOS_LOG_LEVEL", "INFO")
    log_dir: str = _env("DDOS_LOG_DIR", "logs")
    output_dir: str = _env("DDOS_OUTPUT_DIR", "ddos_results")

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        """Load overrides from a YAML file, falling back to defaults."""
        cfg = cls()
        if not (_HAS_YAML and os.path.exists(path)):
            return cfg
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        for section, values in raw.items():
            if hasattr(cfg, section) and isinstance(values, dict):
                sub = getattr(cfg, section)
                for k, v in values.items():
                    if hasattr(sub, k):
                        setattr(sub, k, v)
        return cfg

    def to_dict(self) -> dict:
        return asdict(self)


# A single shared instance imported across the project.
CONFIG = Config.from_yaml(os.getenv("DDOS_CONFIG_FILE", "config.yaml"))

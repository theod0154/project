"""
In-memory rolling metrics for the API server.

The dashboard polls /metrics; this class is what backs that endpoint.
It keeps a bounded deque of recent predictions so memory stays flat
regardless of how long the server runs. Thread-safe because Uvicorn
may serve requests from multiple worker threads.
"""
from __future__ import annotations

import threading
from collections import deque

from utils.config import CONFIG


class MetricsTracker:
    """Thread-safe rolling counters over the last N predictions."""

    def __init__(self, window: int = None):
        self.window = window or CONFIG.api.metrics_window
        self._lock = threading.Lock()
        self._recent = deque(maxlen=self.window)  # each item: dict
        # lifetime counters (not windowed)
        self.total = 0
        self.ddos = 0
        self.benign = 0
        self.alerts = 0
        # confusion counters, only updated when a true label is supplied
        self.tp = self.fp = self.tn = self.fn = 0

    def record(self, *, is_ddos: bool, confidence: float, is_alert: bool,
               latency_ms: float, true_is_ddos: bool | None = None) -> None:
        with self._lock:
            self.total += 1
            if is_ddos:
                self.ddos += 1
            else:
                self.benign += 1
            if is_alert:
                self.alerts += 1

            if true_is_ddos is not None:
                if is_ddos and true_is_ddos:
                    self.tp += 1
                elif is_ddos and not true_is_ddos:
                    self.fp += 1
                elif not is_ddos and true_is_ddos:
                    self.fn += 1
                else:
                    self.tn += 1

            self._recent.append({
                "confidence": confidence,
                "latency_ms": latency_ms,
            })

    def snapshot(self) -> dict:
        """Return a consistent point-in-time view of all metrics."""
        with self._lock:
            n = len(self._recent)
            avg_conf = sum(r["confidence"] for r in self._recent) / n if n else 0.0
            avg_lat = sum(r["latency_ms"] for r in self._recent) / n if n else 0.0
            labelled = self.tp + self.fp + self.tn + self.fn
            live_acc = (self.tp + self.tn) / labelled if labelled else None
            return {
                "total_predictions": self.total,
                "ddos_detected": self.ddos,
                "benign_detected": self.benign,
                "alerts_raised": self.alerts,
                "ddos_rate": self.ddos / self.total if self.total else 0.0,
                "avg_confidence": avg_conf,
                "avg_latency_ms": avg_lat,
                "live_accuracy": live_acc,
                "true_positive": self.tp,
                "false_positive": self.fp,
                "true_negative": self.tn,
                "false_negative": self.fn,
            }

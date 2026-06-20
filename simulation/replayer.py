"""
Traffic-replay simulator.

IMPORTANT — this is a *defensive research* tool. It does NOT generate any
real network traffic or attacks. It replays rows that already exist in the
labeled BCCC-cPacket-Cloud-DDoS-2024 dataset, sending them to the detection
API as if they were arriving live. This is the standard, safe way to
demonstrate a real-time IDS in an academic setting.

The simulator walks through a scripted sequence of "scenarios" (alternating
benign and attack phases), samples matching rows from the dataset, and posts
them to /predict at a configurable rate. It then prints a running accuracy
summary — useful for the thesis demo and screenshots.
"""
from __future__ import annotations

import argparse
import time
from collections import defaultdict, deque
from datetime import datetime

import pandas as pd
import requests

from ml_training.data_loader import DatasetLoader, DatasetError
from utils.config import CONFIG, DDOS_LABELS, BENIGN_LABELS, EXCLUDE_COLS
from utils.logger import get_logger

logger = get_logger("simulation.replayer", CONFIG.log_dir, CONFIG.log_level)


# Scripted demo timeline: (scenario label or 'benign', display name, seconds).
SCENARIOS = [
    ("benign", "Normal traffic", 20),
    ("DDoS-SYN-Flood", "SYN Flood attack", 15),
    ("benign", "Normal traffic", 10),
    ("DDoS-UDP-Flood", "UDP Flood attack", 15),
    ("DDoS-HTTP-Flood", "HTTP Flood attack", 15),
    ("benign", "Normal traffic", 10),
    ("DDoS-DNS-Amplification", "DNS Amplification", 15),
    ("DDoS-Slowloris", "Slowloris attack", 15),
    ("DDoS-ICMP-Flood", "ICMP Flood attack", 15),
    ("DDoS-NTP-Amplification", "NTP Amplification", 15),
    ("benign", "Normal traffic", 10),
]


class TrafficReplayer:
    """Replays dataset rows to the detection API as a timed live stream."""

    def __init__(self, df: pd.DataFrame, api_url: str = None,
                 flows_per_second: int = None):
        self.df = df
        self.api_url = (api_url or CONFIG.sim.api_url).rstrip("/")
        self.fps = flows_per_second or CONFIG.sim.flows_per_second
        self.stats = defaultdict(int)
        self.timeline = deque(maxlen=5000)
        self.alerts = []
        self.session = requests.Session()  # connection reuse -> lower latency

    # ----------------------------------------------------------------------
    def _rows_for(self, scenario: str) -> pd.DataFrame:
        """Select dataset rows matching a scenario; fall back gracefully."""
        if scenario == "benign":
            mask = self.df["label"].isin(BENIGN_LABELS) | (self.df["label"] == "Benign")
        else:
            mask = self.df["label"] == scenario
            if mask.sum() == 0:                       # exact label absent
                mask = self.df["label"].isin(DDOS_LABELS) | (self.df["label"] != "Benign")
        subset = self.df[mask]
        return subset if len(subset) else self.df

    @staticmethod
    def _row_to_features(row: dict) -> dict:
        """Strip meta columns; keep only numeric feature values."""
        return {
            k: float(v) for k, v in row.items()
            if k not in EXCLUDE_COLS and not str(k).startswith("_")
            and isinstance(v, (int, float))
        }

    def _send(self, row: dict, flow_id: str) -> dict | None:
        """POST one flow to the API; return the parsed response or None."""
        payload = {
            "features": self._row_to_features(row),
            "flow_id": flow_id,
            "true_label": str(row.get("label", "")),
        }
        try:
            resp = self.session.post(
                f"{self.api_url}/predict", json=payload, timeout=5
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("Request failed: %s", exc)
            return None

    # ----------------------------------------------------------------------
    def run(self, duration: int = None) -> dict:
        """Replay traffic for `duration` seconds and return summary stats."""
        duration = duration or CONFIG.sim.duration_seconds

        # Pre-flight: make sure the API is up.
        try:
            health = self.session.get(f"{self.api_url}/health", timeout=5).json()
            if not health.get("model_loaded"):
                logger.error("API is up but no model is loaded. Train one first.")
                return {}
            logger.info("API healthy — %d features expected.",
                        health.get("feature_count", 0))
        except requests.RequestException as exc:
            logger.error("Cannot reach API at %s: %s", self.api_url, exc)
            return {}

        logger.info("=" * 58)
        logger.info("TRAFFIC REPLAY — %ds at %d flows/s -> %s",
                    duration, self.fps, self.api_url)
        logger.info("=" * 58)

        start = time.time()
        sc_idx = 0
        sc_start = start
        flow_counter = 0
        interval = 1.0 / self.fps

        while time.time() - start < duration:
            # advance scenario if its window elapsed
            scenario, name, secs = SCENARIOS[sc_idx % len(SCENARIOS)]
            if time.time() - sc_start >= secs:
                sc_idx += 1
                sc_start = time.time()
                scenario, name, secs = SCENARIOS[sc_idx % len(SCENARIOS)]
                logger.info(">> SCENARIO: %s", name)

            # sample a matching row and replay it
            row = self._rows_for(scenario).sample(1).iloc[0].to_dict()
            flow_counter += 1
            flow_id = f"flow-{flow_counter:06d}"
            result = self._send(row, flow_id)

            if result is not None:
                self._record(result, row, name, time.time() - start)

            time.sleep(interval)

        return self._summarize()

    # ----------------------------------------------------------------------
    def _record(self, result: dict, row: dict, scenario: str, ts: float) -> None:
        """Update running stats from one API response."""
        is_ddos = result["is_ddos"]
        conf = result["confidence"]
        true_label = str(row.get("label", ""))
        true_ddos = true_label.strip().lower() != "benign"

        self.stats["total"] += 1
        self.stats["detected_ddos" if is_ddos else "detected_benign"] += 1
        if is_ddos and true_ddos:
            self.stats["tp"] += 1
        elif is_ddos and not true_ddos:
            self.stats["fp"] += 1
        elif not is_ddos and true_ddos:
            self.stats["fn"] += 1
        else:
            self.stats["tn"] += 1

        self.timeline.append({
            "ts": ts, "is_ddos": is_ddos,
            "confidence": conf, "label": true_label,
        })

        if result.get("is_alert"):
            self.alerts.append({
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "type": true_label,
                "confidence": conf,
                "scenario": scenario,
                "correct": true_ddos,
            })

        # compact running console line (throttled to avoid log spam)
        tot = self.stats["total"]
        if tot % 10 == 0:
            d_rate = self.stats["detected_ddos"] / max(tot, 1) * 100
            flag = "DDoS  " if is_ddos else "BENIGN"
            bar = "#" * int(conf * 20) + "-" * (20 - int(conf * 20))
            print(f"\r  [{tot:5d}] {flag} [{bar}] {conf:.2f} "
                  f"| DDoS rate {d_rate:5.1f}% | {true_label[:24]:<24}",
                  end="", flush=True)

    def _summarize(self) -> dict:
        """Print and return the final confusion-based summary."""
        s = self.stats
        tot = s["total"]
        if tot == 0:
            logger.warning("No flows were successfully scored.")
            return dict(s)

        tp, fp, tn, fn = s["tp"], s["fp"], s["tn"], s["fn"]
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        accuracy = (tp + tn) / max(tot, 1)

        print()  # end the running line
        logger.info("=" * 58)
        logger.info("SIMULATION SUMMARY")
        logger.info("  Total scored : %s", f"{tot:,}")
        logger.info("  DDoS detected: %s (%.1f%%)",
                    f"{s['detected_ddos']:,}", s["detected_ddos"] / tot * 100)
        logger.info("  TP=%d  FP=%d  TN=%d  FN=%d", tp, fp, tn, fn)
        logger.info("  Accuracy  : %.4f", accuracy)
        logger.info("  Precision : %.4f", precision)
        logger.info("  Recall    : %.4f", recall)
        logger.info("  F1 Score  : %.4f", f1)
        logger.info("  Alerts    : %d", len(self.alerts))
        logger.info("=" * 58)

        return {**dict(s), "accuracy": accuracy, "precision": precision,
                "recall": recall, "f1": f1}


def parse_args():
    p = argparse.ArgumentParser(description="Replay dataset flows to the DDoS API.")
    p.add_argument("--data", default=CONFIG.data.dataset_path,
                   help="Path to dataset CSV / folder (for sampling rows).")
    p.add_argument("--sample", type=float, default=0.1,
                   help="Fraction of dataset to load into memory for replay.")
    p.add_argument("--api-url", default=CONFIG.sim.api_url)
    p.add_argument("--speed", type=int, default=CONFIG.sim.flows_per_second,
                   help="Flows per second.")
    p.add_argument("--duration", type=int, default=CONFIG.sim.duration_seconds,
                   help="Simulation duration in seconds.")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        df = DatasetLoader(args.data, sample_frac=args.sample).load()
    except DatasetError as exc:
        logger.error("Dataset error: %s", exc)
        return

    replayer = TrafficReplayer(df, api_url=args.api_url, flows_per_second=args.speed)
    replayer.run(duration=args.duration)


if __name__ == "__main__":
    main()

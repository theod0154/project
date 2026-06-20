"""
The ensemble DDoS classifier: XGBoost + Random Forest.

Changes from the original DDoSDetector
---------------------------------------
1. GradientBoostingClassifier -> XGBoost.  The thesis title specifies
   XGBoost; it is also faster and stronger on wide tabular data, and it
   has native imbalance handling via `scale_pos_weight`.
2. Class imbalance is handled in BOTH sub-models:
     - Random Forest : class_weight="balanced"
     - XGBoost       : scale_pos_weight = N_benign / N_ddos
   This is cleaner than the original's manual sample_weight array.
3. The model is a self-contained object: it owns its FeatureEngineer,
   so save()/load() produce a single artifact that can predict end-to-end.
4. Prediction is vectorised — predict_batch scores many flows at once,
   which the API uses for its /predict/batch endpoint.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

try:
    from xgboost import XGBClassifier
    _HAS_XGB = True
except ImportError:  # graceful message instead of an import crash
    _HAS_XGB = False

from ml_training.feature_engineering import FeatureEngineer
from utils.config import CONFIG, DDOS_LABELS
from utils.logger import get_logger

logger = get_logger("ml_training.model", CONFIG.log_dir, CONFIG.log_level)


def label_to_binary(label: Any) -> int:
    """Map any label string to the binary target: Benign->0, anything else->1."""
    return 0 if str(label).strip().lower() == "benign" else 1


@dataclass
class PredictionResult:
    """Structured output of a single-flow prediction."""
    is_ddos: bool
    confidence: float
    rf_score: float
    xgb_score: float

    def as_dict(self) -> dict:
        return {
            "is_ddos": self.is_ddos,
            "confidence": self.confidence,
            "rf_score": self.rf_score,
            "xgb_score": self.xgb_score,
        }


class EnsembleDDoSModel:
    """Random Forest + XGBoost soft-voting ensemble for binary DDoS detection."""

    def __init__(self, config=CONFIG.model):
        if not _HAS_XGB:
            raise ImportError(
                "xgboost is not installed. Run: pip install xgboost"
            )
        self.cfg = config
        self.fe = FeatureEngineer()
        self.trained = False
        self.feature_importance: pd.Series | None = None

        self.rf = RandomForestClassifier(
            n_estimators=config.rf_n_estimators,
            max_depth=config.rf_max_depth,
            min_samples_split=config.rf_min_samples_split,
            min_samples_leaf=config.rf_min_samples_leaf,
            class_weight="balanced",
            n_jobs=-1,
            random_state=CONFIG.data.random_state,
        )
        # XGBoost is constructed in fit() because scale_pos_weight depends
        # on the actual class balance of the training data.
        self.xgb: XGBClassifier | None = None

    # ----------------------------------------------------------------------
    def fit(self, X: pd.DataFrame, y: np.ndarray) -> dict:
        """Train both sub-models. X is the engineered feature matrix,
        y is the binary target. Returns per-model timing info."""
        n_pos = int(np.sum(y == 1))
        n_neg = int(np.sum(y == 0))
        scale_pos_weight = (n_neg / max(n_pos, 1))
        logger.info("Class balance: benign=%s ddos=%s  scale_pos_weight=%.3f",
                    f"{n_neg:,}", f"{n_pos:,}", scale_pos_weight)

        self.xgb = XGBClassifier(
            n_estimators=self.cfg.xgb_n_estimators,
            max_depth=self.cfg.xgb_max_depth,
            learning_rate=self.cfg.xgb_learning_rate,
            subsample=self.cfg.xgb_subsample,
            colsample_bytree=self.cfg.xgb_colsample_bytree,
            scale_pos_weight=scale_pos_weight,
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            n_jobs=-1,
            random_state=CONFIG.data.random_state,
        )

        timings = {}

        logger.info("Training Random Forest (%d trees)...", self.cfg.rf_n_estimators)
        t0 = time.time()
        self.rf.fit(X, y)
        timings["rf_seconds"] = time.time() - t0
        logger.info("  RF trained in %.1fs", timings["rf_seconds"])

        logger.info("Training XGBoost (%d trees)...", self.cfg.xgb_n_estimators)
        t0 = time.time()
        self.xgb.fit(X, y)
        timings["xgb_seconds"] = time.time() - t0
        logger.info("  XGBoost trained in %.1fs", timings["xgb_seconds"])

        # Feature importance — average the two models' normalised importances
        # so the ranking reflects the ensemble, not just one sub-model.
        rf_imp = pd.Series(self.rf.feature_importances_, index=self.fe.feature_cols)
        xgb_imp = pd.Series(self.xgb.feature_importances_, index=self.fe.feature_cols)
        rf_imp = rf_imp / (rf_imp.sum() + 1e-12)
        xgb_imp = xgb_imp / (xgb_imp.sum() + 1e-12)
        self.feature_importance = (
            ((rf_imp + xgb_imp) / 2).sort_values(ascending=False)
        )

        self.trained = True
        return timings

    # ----------------------------------------------------------------------
    def _blend(self, rf_prob: np.ndarray, xgb_prob: np.ndarray) -> np.ndarray:
        """Weighted soft-vote of the two sub-model probabilities."""
        return self.cfg.rf_weight * rf_prob + self.cfg.xgb_weight * xgb_prob

    def predict_proba(self, X: pd.DataFrame) -> dict[str, np.ndarray]:
        """Return rf / xgb / ensemble DDoS-class probabilities for matrix X."""
        rf_prob = self.rf.predict_proba(X)[:, 1]
        xgb_prob = self.xgb.predict_proba(X)[:, 1]
        ens_prob = self._blend(rf_prob, xgb_prob)
        return {"rf": rf_prob, "xgb": xgb_prob, "ensemble": ens_prob}

    def predict_batch(self, df: pd.DataFrame) -> list[PredictionResult]:
        """Score a DataFrame of raw flows (vectorised — used by the API)."""
        if not self.trained:
            raise RuntimeError("Model is not trained / loaded.")
        X = self.fe.prepare(df)
        probs = self.predict_proba(X)
        thr = self.cfg.decision_threshold
        results = []
        for i in range(len(df)):
            ens = float(probs["ensemble"][i])
            results.append(PredictionResult(
                is_ddos=ens >= thr,
                confidence=ens,
                rf_score=float(probs["rf"][i]),
                xgb_score=float(probs["xgb"][i]),
            ))
        return results

    def predict_one(self, flow: dict) -> PredictionResult:
        """Score a single flow given as a {feature: value} dict."""
        clean = {k: v for k, v in flow.items()
                 if not k.startswith("_") and k != "label"}
        return self.predict_batch(pd.DataFrame([clean]))[0]

    # ----------------------------------------------------------------------
    def save(self, path: str | None = None) -> str:
        """Persist the whole model (both sub-models + feature list) to disk."""
        path = path or self.cfg.model_path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump(
            {
                "rf": self.rf,
                "xgb": self.xgb,
                "feature_cols": self.fe.feature_cols,
                "config": self.cfg,
                "feature_importance": self.feature_importance,
            },
            path,
        )
        logger.info("Model saved: %s", path)
        return path

    @classmethod
    def load(cls, path: str | None = None) -> "EnsembleDDoSModel":
        """Reconstruct a ready-to-predict model from a saved artifact."""
        path = path or CONFIG.model.model_path
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model artifact not found: {path}")
        bundle = joblib.load(path)
        model = cls(config=bundle.get("config", CONFIG.model))
        model.rf = bundle["rf"]
        model.xgb = bundle["xgb"]
        model.fe.feature_cols = bundle["feature_cols"]
        model.feature_importance = bundle.get("feature_importance")
        model.trained = True
        logger.info("Model loaded: %s (%d features)",
                    path, len(model.fe.feature_cols))
        return model

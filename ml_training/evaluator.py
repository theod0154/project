"""
Model evaluation: hold-out metrics, cross-validation, ROC/PR curves.

Separated from the model class so that evaluation logic can evolve
independently and be unit-tested without retraining. Produces a single
EvaluationReport dataclass that the plotting module and the thesis
write-up both consume.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_auc_score, roc_curve, precision_recall_curve,
    confusion_matrix, classification_report,
)

from ml_training.model import EnsembleDDoSModel
from utils.config import CONFIG
from utils.logger import get_logger

logger = get_logger("ml_training.evaluator", CONFIG.log_dir, CONFIG.log_level)


@dataclass
class EvaluationReport:
    """Every number and array needed for the thesis results section."""
    # headline metrics, per model
    rf_accuracy: float = 0.0
    rf_f1: float = 0.0
    rf_auc: float = 0.0
    xgb_accuracy: float = 0.0
    xgb_f1: float = 0.0
    xgb_auc: float = 0.0
    ens_accuracy: float = 0.0
    ens_f1: float = 0.0
    ens_auc: float = 0.0
    ens_precision: float = 0.0
    ens_recall: float = 0.0
    # cross-validation
    cv_mean: float = 0.0
    cv_std: float = 0.0
    cv_scores: np.ndarray = field(default_factory=lambda: np.array([]))
    # curve data + raw predictions for plotting
    y_test: np.ndarray = field(default_factory=lambda: np.array([]))
    ens_pred: np.ndarray = field(default_factory=lambda: np.array([]))
    ens_prob: np.ndarray = field(default_factory=lambda: np.array([]))
    fpr: np.ndarray = field(default_factory=lambda: np.array([]))
    tpr: np.ndarray = field(default_factory=lambda: np.array([]))
    prc_precision: np.ndarray = field(default_factory=lambda: np.array([]))
    prc_recall: np.ndarray = field(default_factory=lambda: np.array([]))
    confusion: np.ndarray = field(default_factory=lambda: np.array([]))
    label_dist: pd.Series = field(default_factory=lambda: pd.Series(dtype=int))
    feature_importance: pd.Series = field(default_factory=lambda: pd.Series(dtype=float))


class Evaluator:
    """Runs the full evaluation suite against a trained EnsembleDDoSModel."""

    def __init__(self, model: EnsembleDDoSModel):
        self.model = model

    def evaluate(
        self,
        X_test: pd.DataFrame,
        y_test: np.ndarray,
        X_full: pd.DataFrame | None = None,
        y_full: np.ndarray | None = None,
        label_dist: pd.Series | None = None,
    ) -> EvaluationReport:
        """Compute hold-out metrics on (X_test, y_test); optionally run
        cross-validation on the full (X_full, y_full) set."""
        rep = EvaluationReport()

        # -- hold-out probabilities for every model --------------------
        probs = self.model.predict_proba(X_test)
        thr = self.model.cfg.decision_threshold

        rf_pred = (probs["rf"] >= thr).astype(int)
        xgb_pred = (probs["xgb"] >= thr).astype(int)
        ens_pred = (probs["ensemble"] >= thr).astype(int)

        # -- per-model headline metrics --------------------------------
        rep.rf_accuracy = accuracy_score(y_test, rf_pred)
        rep.rf_f1 = f1_score(y_test, rf_pred, average="weighted")
        rep.rf_auc = roc_auc_score(y_test, probs["rf"])

        rep.xgb_accuracy = accuracy_score(y_test, xgb_pred)
        rep.xgb_f1 = f1_score(y_test, xgb_pred, average="weighted")
        rep.xgb_auc = roc_auc_score(y_test, probs["xgb"])

        rep.ens_accuracy = accuracy_score(y_test, ens_pred)
        rep.ens_f1 = f1_score(y_test, ens_pred, average="weighted")
        rep.ens_auc = roc_auc_score(y_test, probs["ensemble"])
        rep.ens_precision = precision_score(y_test, ens_pred, zero_division=0)
        rep.ens_recall = recall_score(y_test, ens_pred, zero_division=0)

        logger.info("Hold-out results:")
        logger.info("  RF      acc=%.4f f1=%.4f auc=%.4f",
                    rep.rf_accuracy, rep.rf_f1, rep.rf_auc)
        logger.info("  XGBoost acc=%.4f f1=%.4f auc=%.4f",
                    rep.xgb_accuracy, rep.xgb_f1, rep.xgb_auc)
        logger.info("  ENSEMBLE acc=%.4f f1=%.4f auc=%.4f prec=%.4f rec=%.4f",
                    rep.ens_accuracy, rep.ens_f1, rep.ens_auc,
                    rep.ens_precision, rep.ens_recall)

        # -- curve data ------------------------------------------------
        rep.y_test = y_test
        rep.ens_pred = ens_pred
        rep.ens_prob = probs["ensemble"]
        rep.fpr, rep.tpr, _ = roc_curve(y_test, probs["ensemble"])
        rep.prc_precision, rep.prc_recall, _ = precision_recall_curve(
            y_test, probs["ensemble"]
        )
        rep.confusion = confusion_matrix(y_test, ens_pred)

        if self.model.feature_importance is not None:
            rep.feature_importance = self.model.feature_importance
        if label_dist is not None:
            rep.label_dist = label_dist

        # -- cross-validation on the RF (representative, and fast) -----
        if X_full is not None and y_full is not None:
            logger.info("Running %d-fold cross-validation...",
                        self.model.cfg.cv_folds)
            # StratifiedKFold with shuffle=True is essential here: the BCCC
            # dataset stores flows in label order (all Benign, then all
            # Attack...). A plain KFold would put nearly one class per fold,
            # producing meaningless, high-variance scores. Shuffling +
            # stratifying guarantees every fold mirrors the overall class
            # balance.
            skf = StratifiedKFold(
                n_splits=self.model.cfg.cv_folds,
                shuffle=True,
                random_state=CONFIG.data.random_state,
            )
            cv = cross_val_score(
                self.model.rf, X_full, y_full,
                cv=skf,
                scoring="f1_weighted", n_jobs=-1,
            )
            rep.cv_scores = cv
            rep.cv_mean = float(cv.mean())
            rep.cv_std = float(cv.std())
            logger.info("  CV F1 = %.4f +/- %.4f", rep.cv_mean, rep.cv_std)

        return rep

    @staticmethod
    def write_report(rep: EvaluationReport, output_dir: str) -> str:
        """Persist a human-readable classification report to disk."""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "classification_report.txt")
        text = classification_report(
            rep.y_test, rep.ens_pred,
            target_names=["Benign", "DDoS"], digits=4,
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("BCCC-cPacket-Cloud-DDoS-2024 - Ensemble Classification Report\n")
            fh.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
            fh.write(text)
            fh.write(f"\n{rep.model_summary()}\n" if hasattr(rep, "model_summary") else "")
            fh.write(f"\n5-Fold CV F1: {rep.cv_mean:.4f} +/- {rep.cv_std:.4f}\n")
        logger.info("Classification report written: %s", path)
        return path
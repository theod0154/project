"""
Results visualisation — the multi-panel research figure.

Refactored from the original plot_results(): same dark-theme aesthetic,
but driven by the EvaluationReport dataclass instead of a loose dict, and
the real-time simulation panels are now optional (the figure is still
useful when only training has run).
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import seaborn as sns

from ml_training.evaluator import EvaluationReport
from utils.config import CONFIG, DDOS_LABELS
from utils.logger import get_logger

logger = get_logger("ml_training.visualizer", CONFIG.log_dir, CONFIG.log_level)

# colour palette
BG, GRID = "#0D1117", "#1C2430"
RED, GRN, YEL, BLU, PUR = "#FF4455", "#22DD77", "#FFB800", "#4488FF", "#BB44FF"


def _style_axis(ax, title: str) -> None:
    ax.set_facecolor(BG)
    ax.set_title(title, color="white", fontsize=10, fontweight="bold", pad=8)
    ax.tick_params(colors="#AAAAAA", labelsize=8)
    for sp in ax.spines.values():
        sp.set_color(GRID)
    ax.grid(color=GRID, alpha=0.6, linewidth=0.5)


def plot_results(
    report: EvaluationReport,
    sim_stats: dict | None = None,
    timeline: list | None = None,
    alert_log: list | None = None,
    output_dir: str | None = None,
) -> str:
    """Render the full research figure and return the saved PNG path."""
    output_dir = output_dir or CONFIG.output_dir
    sim_stats = sim_stats or {}
    timeline = timeline or []
    alert_log = alert_log or []

    plt.style.use("dark_background")
    fig = plt.figure(figsize=(22, 26), facecolor=BG)
    fig.suptitle(
        "BCCC-cPacket-Cloud-DDoS-2024\n"
        "DDoS Detection — Ensemble (XGBoost + Random Forest) Research Report",
        fontsize=16, fontweight="bold", color="white", y=0.99,
    )
    gs = GridSpec(5, 2, figure=fig, hspace=0.5, wspace=0.35, top=0.95, bottom=0.03)

    # 1 -- label distribution -------------------------------------------
    ax = fig.add_subplot(gs[0, 0])
    dist = report.label_dist
    if len(dist):
        colours = [RED if l in DDOS_LABELS else GRN for l in dist.index]
        ax.barh(range(len(dist)), dist.values, color=colours, alpha=0.85)
        ax.set_yticks(range(len(dist)))
        ax.set_yticklabels(dist.index, fontsize=6, color="#CCCCCC")
        ax.set_xlabel("Flow count", color="#AAAAAA", fontsize=8)
        ax.legend(handles=[mpatches.Patch(color=GRN, label="Benign"),
                           mpatches.Patch(color=RED, label="DDoS")],
                  fontsize=7, facecolor="#1A1A2E", edgecolor="gray")
    _style_axis(ax, "Traffic Class Distribution")

    # 2 -- model comparison ---------------------------------------------
    ax = fig.add_subplot(gs[0, 1])
    models = ["Random\nForest", "XGBoost", "Ensemble"]
    accs = [report.rf_accuracy, report.xgb_accuracy, report.ens_accuracy]
    f1s = [report.rf_f1, report.xgb_f1, report.ens_f1]
    aucs = [report.rf_auc, report.xgb_auc, report.ens_auc]
    x = np.arange(3)
    w = 0.28
    ax.bar(x - w, accs, w, label="Accuracy", color=YEL, alpha=0.85)
    ax.bar(x, f1s, w, label="F1", color=BLU, alpha=0.85)
    ax.bar(x + w, aucs, w, label="AUC", color=PUR, alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(models, color="#CCCCCC", fontsize=9)
    ax.set_ylim(0, 1.12)
    ax.legend(fontsize=7, facecolor="#1A1A2E", edgecolor="gray")
    for i, (a, f, u) in enumerate(zip(accs, f1s, aucs)):
        ax.text(i - w, a + 0.01, f"{a:.3f}", ha="center", fontsize=6, color="white")
        ax.text(i, f + 0.01, f"{f:.3f}", ha="center", fontsize=6, color="white")
        ax.text(i + w, u + 0.01, f"{u:.3f}", ha="center", fontsize=6, color="white")
    _style_axis(ax, "Model Performance (Accuracy / F1 / AUC)")

    # 3 -- confusion matrix ---------------------------------------------
    ax = fig.add_subplot(gs[1, 0])
    if report.confusion.size:
        sns.heatmap(report.confusion, annot=True, fmt="d", cmap="RdYlGn",
                    xticklabels=["Benign", "DDoS"], yticklabels=["Benign", "DDoS"],
                    ax=ax, cbar=False, linewidths=0.5,
                    annot_kws={"size": 12, "weight": "bold"})
        ax.set_xlabel("Predicted", color="#AAAAAA", fontsize=9)
        ax.set_ylabel("Actual", color="#AAAAAA", fontsize=9)
    ax.set_facecolor(BG)
    _style_axis(ax, "Confusion Matrix (Ensemble)")

    # 4 -- ROC curve -----------------------------------------------------
    ax = fig.add_subplot(gs[1, 1])
    fpr = report.fpr if report.fpr.size else np.array([0, 1])
    tpr = report.tpr if report.tpr.size else np.array([0, 1])
    ax.plot(fpr, tpr, color=YEL, lw=2, label=f"ROC (AUC = {report.ens_auc:.4f})")
    ax.fill_between(fpr, tpr, alpha=0.12, color=YEL)
    ax.plot([0, 1], [0, 1], "--", color="gray", lw=1, label="Random")
    ax.set_xlabel("False Positive Rate", color="#AAAAAA", fontsize=9)
    ax.set_ylabel("True Positive Rate", color="#AAAAAA", fontsize=9)
    ax.legend(fontsize=8, facecolor="#1A1A2E", edgecolor="gray")
    _style_axis(ax, "ROC Curve")

    # 5 -- precision-recall curve ---------------------------------------
    ax = fig.add_subplot(gs[2, 0])
    pp = report.prc_precision if report.prc_precision.size else np.array([1, 0])
    pr = report.prc_recall if report.prc_recall.size else np.array([0, 1])
    ax.plot(pr, pp, color=PUR, lw=2)
    ax.fill_between(pr, pp, alpha=0.12, color=PUR)
    ax.set_xlabel("Recall", color="#AAAAAA", fontsize=9)
    ax.set_ylabel("Precision", color="#AAAAAA", fontsize=9)
    _style_axis(ax, "Precision-Recall Curve")

    # 6 -- feature importance -------------------------------------------
    ax = fig.add_subplot(gs[2, 1])
    fi = report.feature_importance
    if fi is not None and len(fi):
        top = fi.head(15)
        colours = plt.cm.plasma(np.linspace(0.15, 0.95, len(top)))
        ax.barh(range(len(top)), top.values, color=colours, alpha=0.88)
        ax.set_yticks(range(len(top)))
        ax.set_yticklabels(top.index, fontsize=7, color="#CCCCCC")
        ax.invert_yaxis()
    _style_axis(ax, "Top-15 Feature Importance (Ensemble)")

    # 7 -- real-time timeline -------------------------------------------
    ax = fig.add_subplot(gs[3, :])
    if timeline:
        ts = [t["ts"] for t in timeline]
        cf = [t["confidence"] for t in timeline]
        colours = [RED if t["is_ddos"] else GRN for t in timeline]
        ax.scatter(ts, cf, c=colours, s=5, alpha=0.45)
        ax.axhline(0.5, color=YEL, lw=1, linestyle="--", alpha=0.8, label="Threshold (0.5)")
        if len(cf) > 20:
            win = max(10, len(cf) // 10)
            avg = pd.Series(cf).rolling(win, min_periods=1).mean()
            ax.plot(ts, avg, color="white", lw=1.5, alpha=0.7, label="Rolling mean")
        ax.set_xlim(0, max(ts) if ts else 1)
        ax.set_ylim(-0.05, 1.05)
        ax.set_xlabel("Time (seconds)", color="#AAAAAA", fontsize=9)
        ax.set_ylabel("DDoS Confidence", color="#AAAAAA", fontsize=9)
        ax.legend(handles=[mpatches.Patch(color=GRN, label="Benign"),
                           mpatches.Patch(color=RED, label="DDoS")],
                  fontsize=8, facecolor="#1A1A2E", edgecolor="gray", loc="upper right")
    else:
        ax.text(0.5, 0.5, "No simulation data (run with simulation enabled)",
                ha="center", va="center", color="#666666", fontsize=11)
    _style_axis(ax, "Real-Time Traffic — Confidence Timeline")

    # 8 -- simulation stats pie -----------------------------------------
    ax = fig.add_subplot(gs[4, 0])
    vals = [max(sim_stats.get(k, 0), 0) for k in ("tp", "tn", "fp", "fn")]
    if sum(vals) > 0:
        ax.pie(vals, labels=["TP", "TN", "FP", "FN"],
               colors=[GRN, BLU, YEL, RED], autopct="%1.1f%%",
               startangle=90, textprops={"color": "white", "fontsize": 8})
    else:
        ax.text(0.5, 0.5, "No simulation data", ha="center", va="center",
                color="#666666", fontsize=10)
    _style_axis(ax, f"Detection Statistics (Total: {sim_stats.get('total', 0):,})")
    ax.grid(False)

    # 9 -- alert log -----------------------------------------------------
    ax = fig.add_subplot(gs[4, 1])
    ax.set_facecolor(BG)
    ax.axis("off")
    ax.set_title("Alert Log (last 18)", color="white", fontsize=10,
                 fontweight="bold", pad=8)
    if alert_log:
        header = f"{'Time':<13} {'Conf':>7}  {'Attack Type'}"
        ax.text(0.03, 0.95, header, transform=ax.transAxes, fontsize=7,
                color=YEL, fontfamily="monospace", va="top")
        for i, a in enumerate(alert_log[-18:]):
            y = 0.88 - i * 0.047
            ok = "OK" if a.get("correct") else "XX"
            line = (f"{a['time']:<13} {a['confidence']:>6.2%}  "
                    f"{a['type'][:26]:<26} {ok}")
            colour = GRN if a.get("correct") else RED
            ax.text(0.03, y, line, transform=ax.transAxes, fontsize=6.5,
                    color=colour, fontfamily="monospace", va="top")
    else:
        ax.text(0.5, 0.5, "No alerts", ha="center", va="center",
                color="#666666", transform=ax.transAxes, fontsize=10)
    for sp in ax.spines.values():
        sp.set_color(GRID)

    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, "ddos_research_results.png")
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    logger.info("Research figure saved: %s", out)
    return out

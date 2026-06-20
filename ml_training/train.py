"""
Training pipeline entrypoint.

Run this once (locally or on the VM) to produce the model artifact that
the API server loads. Replaces the training half of the original main().

    python -m ml_training.train --data data/BCCC-cPacket-Cloud-DDoS-2024
    python -m ml_training.train --data data/sample.csv --sample 0.2
"""
from __future__ import annotations

import argparse
import sys

from sklearn.model_selection import train_test_split

from ml_training.data_loader import DatasetLoader, DatasetError
from ml_training.evaluator import Evaluator
from ml_training.model import EnsembleDDoSModel, label_to_binary
from ml_training.visualizer import plot_results
from utils.config import CONFIG
from utils.logger import get_logger

logger = get_logger("ml_training.train", CONFIG.log_dir, CONFIG.log_level)


def parse_args():
    p = argparse.ArgumentParser(
        description="Train the XGBoost + Random Forest DDoS ensemble."
    )
    p.add_argument("--data", default=CONFIG.data.dataset_path,
                   help="Path to a CSV file or a folder of CSVs.")
    p.add_argument("--sample", type=float, default=CONFIG.data.sample_frac,
                   help="Fraction of the dataset to use (0.0-1.0).")
    p.add_argument("--out", default=CONFIG.output_dir,
                   help="Directory for the research figure and report.")
    p.add_argument("--model-out", default=CONFIG.model.model_path,
                   help="Path for the saved model artifact.")
    p.add_argument("--no-plot", action="store_true",
                   help="Skip generating the research figure.")
    return p.parse_args()


def run_training(data_path: str, sample_frac: float,
                 output_dir: str, model_out: str,
                 make_plot: bool = True) -> EnsembleDDoSModel:
    """Full training pipeline. Returns the trained model."""
    logger.info("=" * 58)
    logger.info("DDoS DETECTION — TRAINING PIPELINE")
    logger.info("=" * 58)

    # 1. Load + clean ---------------------------------------------------
    df = DatasetLoader(data_path, sample_frac=sample_frac).load()

    # 2. Build the model and engineer features -------------------------
    model = EnsembleDDoSModel()
    X = model.fe.prepare(df, fit=True)
    y = df["label"].apply(label_to_binary).values
    logger.info("Feature matrix: %s   positives(DDoS): %.1f%%",
                X.shape, 100 * y.mean())

    # 3. Train / test split (stratified to preserve class balance) -----
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y,
        test_size=CONFIG.data.test_size,
        random_state=CONFIG.data.random_state,
        stratify=y,
    )

    # 4. Fit ------------------------------------------------------------
    model.fit(X_tr, y_tr)

    # 5. Evaluate -------------------------------------------------------
    evaluator = Evaluator(model)
    report = evaluator.evaluate(
        X_test=X_te, y_test=y_te,
        X_full=X, y_full=y,
        label_dist=df["label"].value_counts(),
    )
    Evaluator.write_report(report, output_dir)

    # 6. Persist the artifact ------------------------------------------
    model.save(model_out)

    # 7. Research figure ------------------------------------------------
    if make_plot:
        plot_results(report, output_dir=output_dir)

    logger.info("=" * 58)
    logger.info("TRAINING COMPLETE")
    logger.info("  Model artifact : %s", model_out)
    logger.info("  Report         : %s/classification_report.txt", output_dir)
    logger.info("  Ensemble F1    : %.4f   AUC: %.4f",
                report.ens_f1, report.ens_auc)
    logger.info("=" * 58)
    return model


def main():
    args = parse_args()
    try:
        run_training(
            data_path=args.data,
            sample_frac=args.sample,
            output_dir=args.out,
            model_out=args.model_out,
            make_plot=not args.no_plot,
        )
    except DatasetError as exc:
        logger.error("Dataset error: %s", exc)
        sys.exit(1)
    except ImportError as exc:
        logger.error("Missing dependency: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()

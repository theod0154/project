"""
Dataset loading and cleaning for BCCC-cPacket-Cloud-DDoS-2024.

Refactored from the original DatasetLoader class:
  - replaces print() with structured logging
  - replaces sys.exit() with raised exceptions (a library must not kill
    the interpreter; callers decide how to handle failure)
  - column-name normalisation and numeric coercion are unchanged in spirit
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

from utils.config import CONFIG, DDOS_LABELS, BENIGN_LABELS, EXCLUDE_COLS
from utils.logger import get_logger

logger = get_logger("ml_training.data_loader", CONFIG.log_dir, CONFIG.log_level)


class DatasetError(Exception):
    """Raised when the dataset is missing, empty, or malformed."""


class DatasetLoader:
    """Loads one CSV or a folder of CSVs into a single clean DataFrame."""

    def __init__(self, path: str, sample_frac: float = 1.0):
        self.path = path
        self.sample_frac = sample_frac

    # -- public API --------------------------------------------------------
    def load(self) -> pd.DataFrame:
        if not os.path.exists(self.path):
            raise DatasetError(f"Path not found: {self.path}")

        df = self._load_folder() if os.path.isdir(self.path) else self._load_csv(self.path)
        df = self._clean(df)
        self._log_summary(df)

        if self.sample_frac < 1.0:
            df = df.sample(
                frac=self.sample_frac, random_state=CONFIG.data.random_state
            ).reset_index(drop=True)
            logger.info("After sampling: %s flows (%.0f%%)",
                        f"{len(df):,}", self.sample_frac * 100)

        return df

    # -- loading helpers ---------------------------------------------------
    def _load_folder(self) -> pd.DataFrame:
        csvs = sorted(
            os.path.join(self.path, f)
            for f in os.listdir(self.path)
            if f.lower().endswith(".csv")
        )
        if not csvs:
            raise DatasetError(f"No CSV files found in folder: {self.path}")

        logger.info("Found %d CSV file(s); concatenating...", len(csvs))
        parts = []
        for i, fp in enumerate(csvs, 1):
            logger.info("  [%d/%d] %s", i, len(csvs), os.path.basename(fp))
            parts.append(self._load_csv(fp))
        df = pd.concat(parts, ignore_index=True)
        logger.info("After merge: %s flows", f"{len(df):,}")
        return df

    def _load_csv(self, fp: str) -> pd.DataFrame:
        df = pd.read_csv(fp, low_memory=False)
        logger.info("  %s: %s rows, %d columns",
                    os.path.basename(fp), f"{len(df):,}", len(df.columns))
        return df

    # -- cleaning ----------------------------------------------------------
    def _clean(self, df: pd.DataFrame) -> pd.DataFrame:
        # Normalise column names: lower-case, underscores, no stray spaces.
        df.columns = (
            df.columns.str.strip().str.lower()
            .str.replace(" ", "_").str.replace("-", "_")
        )

        # Locate the label column under any of its common names.
        label_col = next(
            (c for c in ("label", "class", "attack_type", "category")
             if c in df.columns),
            None,
        )
        if label_col is None:
            raise DatasetError(
                "No label/class column found. Check the dataset's column names."
            )

        df = df.rename(columns={label_col: "label"})
        df = df.dropna(subset=["label"])
        df["label"] = df["label"].astype(str).str.strip()

        # Coerce every non-meta column to numeric; replace inf/NaN with 0.
        num_cols = [c for c in df.columns if c not in EXCLUDE_COLS]
        df = df.replace([np.inf, -np.inf], np.nan)
        df[num_cols] = df[num_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

        return df

    # -- reporting ---------------------------------------------------------
    @staticmethod
    def _log_summary(df: pd.DataFrame) -> None:
        labels = df["label"].unique()
        ddos_found = [l for l in labels if l != "Benign"]
        benign_found = [l for l in labels if l == "Benign"]
        unknown = [l for l in labels if l not in DDOS_LABELS and l not in BENIGN_LABELS]

        logger.info("=" * 58)
        logger.info("DATASET SUMMARY")
        logger.info("  Total flows   : %s", f"{len(df):,}")
        logger.info("  Total features: %d", len(df.columns) - 1)
        logger.info("  DDoS classes  : %d", len(ddos_found))
        logger.info("  Benign classes: %d", len(benign_found))
        if unknown:
            logger.warning("  Unknown labels: %s", unknown[:5])
        for lbl, cnt in df["label"].value_counts().items():
            tag = "DDoS  " if lbl != "Benign" else "Benign"
            logger.info("    [%s] %-38s %8s  (%.1f%%)",
                        tag, lbl, f"{cnt:,}", cnt / len(df) * 100)
        logger.info("=" * 58)

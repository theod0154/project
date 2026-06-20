"""
Unit tests for the core ML components.

Run with:  pytest tests/  -q
These are lightweight smoke + contract tests — they verify the modules
wire together correctly, not statistical performance.
"""
import numpy as np
import pandas as pd
import pytest

from ml_training.feature_engineering import FeatureEngineer
from ml_training.model import EnsembleDDoSModel, label_to_binary


# --- fixtures -------------------------------------------------------------
@pytest.fixture
def tiny_df():
    """A minimal DataFrame with the columns the feature engineer expects."""
    rng = np.random.default_rng(0)
    n = 200
    return pd.DataFrame({
        "total_packets": rng.normal(500, 100, n).clip(1),
        "total_bytes": rng.normal(50000, 10000, n).clip(1),
        "fwd_bytes": rng.normal(25000, 5000, n).clip(1),
        "bwd_bytes": rng.normal(25000, 5000, n).clip(1),
        "fwd_packet_count": rng.normal(250, 50, n).clip(1),
        "bwd_packet_count": rng.normal(250, 50, n).clip(1),
        "syn_flag_count": rng.normal(10, 3, n).clip(0),
        "ack_flag_count": rng.normal(200, 40, n).clip(0),
        "fin_flag_count": rng.normal(5, 2, n).clip(0),
        "rst_flag_count": rng.normal(2, 1, n).clip(0),
        "psh_flag_count": rng.normal(30, 10, n).clip(0),
        "flow_duration": rng.normal(10, 3, n).clip(0.1),
        "label": (["Benign"] * (n // 2)) + (["DDoS-SYN-Flood"] * (n // 2)),
    })


# --- label mapping --------------------------------------------------------
def test_label_to_binary():
    assert label_to_binary("Benign") == 0
    assert label_to_binary("benign") == 0       # case-insensitive
    assert label_to_binary(" Benign ") == 0     # whitespace-tolerant
    assert label_to_binary("DDoS-SYN-Flood") == 1
    assert label_to_binary("DDoS-DNS-Amplification") == 1


# --- feature engineering --------------------------------------------------
def test_feature_engineer_fit_freezes_columns(tiny_df):
    fe = FeatureEngineer()
    X = fe.prepare(tiny_df, fit=True)
    assert len(fe.feature_cols) > 0
    # derived features must be present
    for col in ("bytes_ratio", "syn_ack_ratio", "pkt_rate", "flag_density"):
        assert col in X.columns
    # 'label' must never leak into the feature matrix
    assert "label" not in X.columns


def test_feature_engineer_zero_fills_missing(tiny_df):
    """A flow missing some features should still produce the full matrix."""
    fe = FeatureEngineer()
    fe.prepare(tiny_df, fit=True)
    partial = pd.DataFrame([{"total_packets": 100, "total_bytes": 5000}])
    X = fe.prepare(partial)
    assert list(X.columns) == fe.feature_cols   # same columns, same order
    assert not X.isna().any().any()             # no NaNs


def test_feature_engineer_no_inf(tiny_df):
    """Division-based features must never produce inf even with zero inputs."""
    fe = FeatureEngineer()
    fe.prepare(tiny_df, fit=True)
    zeros = pd.DataFrame([{c: 0.0 for c in tiny_df.columns if c != "label"}])
    X = fe.prepare(zeros)
    assert np.isfinite(X.values).all()


# --- model train / predict / save-load ------------------------------------
def test_model_train_and_predict(tiny_df):
    model = EnsembleDDoSModel()
    X = model.fe.prepare(tiny_df, fit=True)
    y = tiny_df["label"].apply(label_to_binary).values
    model.fit(X, y)
    assert model.trained
    assert model.feature_importance is not None

    # single-flow prediction returns a well-formed result
    flow = tiny_df.iloc[0].to_dict()
    result = model.predict_one(flow)
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.is_ddos, bool)


def test_model_save_load_roundtrip(tiny_df, tmp_path):
    model = EnsembleDDoSModel()
    X = model.fe.prepare(tiny_df, fit=True)
    y = tiny_df["label"].apply(label_to_binary).values
    model.fit(X, y)

    path = str(tmp_path / "model.pkl")
    model.save(path)
    reloaded = EnsembleDDoSModel.load(path)

    # the reloaded model must produce identical predictions
    flow = tiny_df.iloc[0].to_dict()
    r1 = model.predict_one(flow)
    r2 = reloaded.predict_one(flow)
    assert abs(r1.confidence - r2.confidence) < 1e-9
    assert reloaded.fe.feature_cols == model.fe.feature_cols


def test_batch_prediction_matches_single(tiny_df):
    model = EnsembleDDoSModel()
    X = model.fe.prepare(tiny_df, fit=True)
    y = tiny_df["label"].apply(label_to_binary).values
    model.fit(X, y)

    batch = model.predict_batch(tiny_df.head(5))
    assert len(batch) == 5
    single = model.predict_one(tiny_df.iloc[0].to_dict())
    assert abs(batch[0].confidence - single.confidence) < 1e-9

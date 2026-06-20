"""
Streamlit monitoring dashboard.

A thin presentation layer — it holds NO ML logic. It polls the FastAPI
server's /health and /metrics endpoints and visualises them:
  - live system status
  - DDoS vs benign counts
  - rolling confidence / detection-rate charts
  - confusion-based live accuracy
  - an alert table
  - a manual single-flow tester that calls /predict

Run:
    streamlit run dashboard/app.py
"""
from __future__ import annotations

import os
import time
from collections import deque

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("DDOS_API_URL", "http://localhost:8000").rstrip("/")
POLL_SECONDS = 2

st.set_page_config(
    page_title="Cloud DDoS Detection — Monitor",
    page_icon="shield",
    layout="wide",
)

# --- session-state history buffers (persist across reruns) ----------------
if "history" not in st.session_state:
    st.session_state.history = deque(maxlen=300)   # (t, ddos_rate, avg_conf)
if "last_total" not in st.session_state:
    st.session_state.last_total = 0


# --- API helpers ----------------------------------------------------------
def api_get(path: str) -> dict | None:
    try:
        r = requests.get(f"{API_URL}{path}", timeout=4)
        r.raise_for_status()
        return r.json()
    except requests.RequestException:
        return None


def api_post(path: str, payload: dict) -> dict | None:
    try:
        r = requests.post(f"{API_URL}{path}", json=payload, timeout=5)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        st.error(f"API request failed: {exc}")
        return None


# --- header ---------------------------------------------------------------
st.title("🛡️ Cloud DDoS Detection — Real-Time Monitor")
st.caption(
    "Ensemble (XGBoost + Random Forest) · BCCC-cPacket-Cloud-DDoS-2024 · "
    f"API: {API_URL}"
)

health = api_get("/health")
if health is None:
    st.error(
        f"Cannot reach the detection API at **{API_URL}**. "
        "Is the api_server container running?"
    )
    st.stop()

# --- status row -----------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("API Status", health["status"].upper())
c2.metric("Model Loaded", "Yes" if health["model_loaded"] else "No")
c3.metric("Features", health["feature_count"])
c4.metric("Uptime", f"{health['uptime_seconds']/60:.1f} min")

if not health["model_loaded"]:
    st.warning("The API is running but no model is loaded. Train a model first.")
    st.stop()

st.divider()

# --- metrics --------------------------------------------------------------
metrics = api_get("/metrics") or {}
total = metrics.get("total_predictions", 0)

# append to history only when new predictions have arrived
if total != st.session_state.last_total:
    st.session_state.history.append({
        "t": time.strftime("%H:%M:%S"),
        "ddos_rate": metrics.get("ddos_rate", 0) * 100,
        "avg_confidence": metrics.get("avg_confidence", 0),
    })
    st.session_state.last_total = total

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Analyzed", f"{total:,}")
m2.metric("DDoS Detected", f"{metrics.get('ddos_detected', 0):,}")
m3.metric("Benign", f"{metrics.get('benign_detected', 0):,}")
m4.metric("Alerts Raised", f"{metrics.get('alerts_raised', 0):,}")
m5.metric("Avg Latency", f"{metrics.get('avg_latency_ms', 0):.2f} ms")

# detection rate gauge-ish bar
ddos_rate = metrics.get("ddos_rate", 0)
st.progress(min(ddos_rate, 1.0),
            text=f"Current DDoS detection rate: {ddos_rate*100:.1f}%")

st.divider()

# --- charts ---------------------------------------------------------------
left, right = st.columns(2)

with left:
    st.subheader("Detection Rate Over Time")
    if len(st.session_state.history) > 1:
        hist_df = pd.DataFrame(list(st.session_state.history)).set_index("t")
        st.line_chart(hist_df[["ddos_rate"]], height=260)
    else:
        st.info("Waiting for traffic… start the simulation to populate this chart.")

with right:
    st.subheader("Average Confidence Over Time")
    if len(st.session_state.history) > 1:
        hist_df = pd.DataFrame(list(st.session_state.history)).set_index("t")
        st.line_chart(hist_df[["avg_confidence"]], height=260)
    else:
        st.info("Waiting for traffic…")

# --- live accuracy / confusion -------------------------------------------
st.subheader("Live Detection Quality")
labelled = (metrics.get("true_positive", 0) + metrics.get("false_positive", 0)
            + metrics.get("true_negative", 0) + metrics.get("false_negative", 0))
if labelled > 0:
    q1, q2, q3, q4, q5 = st.columns(5)
    q1.metric("Live Accuracy",
              f"{(metrics.get('live_accuracy') or 0)*100:.2f}%")
    q2.metric("True Positive", metrics.get("true_positive", 0))
    q3.metric("False Positive", metrics.get("false_positive", 0))
    q4.metric("True Negative", metrics.get("true_negative", 0))
    q5.metric("False Negative", metrics.get("false_negative", 0))
else:
    st.info("Live accuracy appears once flows with ground-truth labels are scored "
            "(the simulator sends these automatically).")

st.divider()

# --- manual single-flow tester -------------------------------------------
with st.expander("🔬 Manual Flow Tester — score a single flow"):
    st.caption("Enter a few feature values for a quick what-if check.")
    st.warning(
        "Note: this tester sends only a handful of features; the rest are "
        "zero-filled server-side. With most features zero, the derived "
        "ratios collapse and the verdict can be unreliable. For accurate "
        "scoring the model needs a **complete** flow record — which is "
        "exactly what the traffic simulator sends. Treat this tool as a "
        "rough demo, not a benchmark."
    )
    cc1, cc2, cc3 = st.columns(3)
    total_packets = cc1.number_input("total_packets", value=1200.0, step=100.0)
    total_bytes = cc2.number_input("total_bytes", value=60000.0, step=1000.0)
    flow_duration = cc3.number_input("flow_duration", value=0.8, step=0.1)
    cc4, cc5, cc6 = st.columns(3)
    syn_flag_count = cc4.number_input("syn_flag_count", value=1100.0, step=50.0)
    ack_flag_count = cc5.number_input("ack_flag_count", value=5.0, step=1.0)
    fwd_bytes = cc6.number_input("fwd_bytes", value=58000.0, step=1000.0)

    if st.button("Predict", type="primary"):
        payload = {
            "features": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "flow_duration": flow_duration,
                "syn_flag_count": syn_flag_count,
                "ack_flag_count": ack_flag_count,
                "fwd_bytes": fwd_bytes,
            },
            "flow_id": "manual-test",
        }
        result = api_post("/predict", payload)
        if result:
            verdict = "🔴 DDoS" if result["is_ddos"] else "🟢 Benign"
            st.markdown(f"### Verdict: {verdict}")
            r1, r2, r3 = st.columns(3)
            r1.metric("Ensemble Confidence", f"{result['confidence']:.3f}")
            r2.metric("RF Score", f"{result['rf_score']:.3f}")
            r3.metric("XGBoost Score", f"{result['xgb_score']:.3f}")
            if result["is_alert"]:
                st.error(f"ALERT — confidence above threshold "
                         f"({result['threshold']:.2f})")

# --- auto-refresh ---------------------------------------------------------
st.divider()
auto = st.checkbox("Auto-refresh", value=True)
if auto:
    time.sleep(POLL_SECONDS)
    st.rerun()

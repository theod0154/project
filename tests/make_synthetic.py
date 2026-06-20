"""Generate a synthetic BCCC-cPacket-like dataset to smoke-test the pipeline.
NOT part of the thesis deliverable — just a test fixture."""
import numpy as np
import pandas as pd

rng = np.random.default_rng(42)
N = 8000

def make_rows(n, label, attack):
    base = {
        "flow_id": [f"f{i}" for i in range(n)],
        "src_ip": ["10.0.0.1"] * n,
        "dst_ip": ["10.0.0.2"] * n,
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.integers(1, 1024, n),
        "timestamp": rng.integers(0, 1e6, n),
    }
    if attack == "syn":
        d = dict(
            total_packets=rng.normal(5000, 800, n), total_bytes=rng.normal(250000, 40000, n),
            fwd_bytes=rng.normal(240000, 30000, n), bwd_bytes=rng.normal(1000, 300, n),
            fwd_packet_count=rng.normal(4900, 700, n), bwd_packet_count=rng.normal(20, 10, n),
            syn_flag_count=rng.normal(4800, 600, n), ack_flag_count=rng.normal(10, 5, n),
            fin_flag_count=rng.normal(2, 1, n), rst_flag_count=rng.normal(5, 3, n),
            psh_flag_count=rng.normal(3, 2, n), flow_duration=rng.normal(0.5, 0.2, n),
            flow_iat_mean=rng.normal(0.0001, 0.00005, n), flow_iat_std=rng.normal(0.00002, 1e-5, n),
            flow_iat_max=rng.normal(0.001, 0.0005, n), flow_iat_min=rng.normal(1e-6, 5e-7, n),
            fwd_pkt_len_max=rng.normal(64, 5, n), fwd_pkt_len_min=rng.normal(60, 3, n),
            fwd_pkt_len_mean=rng.normal(62, 2, n), fwd_pkt_len_std=rng.normal(2, 0.5, n),
            bwd_pkt_len_mean=rng.normal(60, 5, n), active_mean=rng.normal(0.1, 0.05, n),
            idle_mean=rng.normal(0.01, 0.005, n), bwd_iat_mean=rng.normal(0.002, 0.001, n),
            fwd_iat_mean=rng.normal(0.0001, 0.00005, n),
        )
    elif attack == "ampl":
        d = dict(
            total_packets=rng.normal(800, 150, n), total_bytes=rng.normal(900000, 100000, n),
            fwd_bytes=rng.normal(5000, 1000, n), bwd_bytes=rng.normal(890000, 90000, n),
            fwd_packet_count=rng.normal(50, 15, n), bwd_packet_count=rng.normal(750, 120, n),
            syn_flag_count=rng.normal(2, 1, n), ack_flag_count=rng.normal(40, 10, n),
            fin_flag_count=rng.normal(2, 1, n), rst_flag_count=rng.normal(1, 1, n),
            psh_flag_count=rng.normal(30, 10, n), flow_duration=rng.normal(2.0, 0.5, n),
            flow_iat_mean=rng.normal(0.002, 0.0008, n), flow_iat_std=rng.normal(0.001, 0.0004, n),
            flow_iat_max=rng.normal(0.05, 0.02, n), flow_iat_min=rng.normal(1e-5, 5e-6, n),
            fwd_pkt_len_max=rng.normal(120, 20, n), fwd_pkt_len_min=rng.normal(80, 10, n),
            fwd_pkt_len_mean=rng.normal(100, 10, n), fwd_pkt_len_std=rng.normal(15, 4, n),
            bwd_pkt_len_mean=rng.normal(1400, 100, n), active_mean=rng.normal(0.5, 0.2, n),
            idle_mean=rng.normal(0.3, 0.1, n), bwd_iat_mean=rng.normal(0.001, 0.0004, n),
            fwd_iat_mean=rng.normal(0.01, 0.004, n),
        )
    elif attack == "slow":
        d = dict(
            total_packets=rng.normal(40, 12, n), total_bytes=rng.normal(8000, 2000, n),
            fwd_bytes=rng.normal(6000, 1500, n), bwd_bytes=rng.normal(2000, 600, n),
            fwd_packet_count=rng.normal(30, 8, n), bwd_packet_count=rng.normal(10, 4, n),
            syn_flag_count=rng.normal(1, 1, n), ack_flag_count=rng.normal(25, 6, n),
            fin_flag_count=rng.normal(1, 1, n), rst_flag_count=rng.normal(1, 1, n),
            psh_flag_count=rng.normal(20, 6, n), flow_duration=rng.normal(120, 30, n),
            flow_iat_mean=rng.normal(3.0, 1.0, n), flow_iat_std=rng.normal(2.0, 0.8, n),
            flow_iat_max=rng.normal(20, 8, n), flow_iat_min=rng.normal(0.5, 0.2, n),
            fwd_pkt_len_max=rng.normal(200, 40, n), fwd_pkt_len_min=rng.normal(100, 20, n),
            fwd_pkt_len_mean=rng.normal(150, 25, n), fwd_pkt_len_std=rng.normal(30, 8, n),
            bwd_pkt_len_mean=rng.normal(120, 30, n), active_mean=rng.normal(5, 2, n),
            idle_mean=rng.normal(10, 4, n), bwd_iat_mean=rng.normal(4, 1.5, n),
            fwd_iat_mean=rng.normal(3, 1.2, n),
        )
    else:  # benign
        d = dict(
            total_packets=rng.normal(200, 80, n), total_bytes=rng.normal(80000, 30000, n),
            fwd_bytes=rng.normal(40000, 15000, n), bwd_bytes=rng.normal(40000, 15000, n),
            fwd_packet_count=rng.normal(100, 40, n), bwd_packet_count=rng.normal(100, 40, n),
            syn_flag_count=rng.normal(3, 2, n), ack_flag_count=rng.normal(180, 50, n),
            fin_flag_count=rng.normal(3, 2, n), rst_flag_count=rng.normal(1, 1, n),
            psh_flag_count=rng.normal(60, 20, n), flow_duration=rng.normal(15, 6, n),
            flow_iat_mean=rng.normal(0.08, 0.03, n), flow_iat_std=rng.normal(0.05, 0.02, n),
            flow_iat_max=rng.normal(1.0, 0.4, n), flow_iat_min=rng.normal(0.001, 0.0005, n),
            fwd_pkt_len_max=rng.normal(1400, 200, n), fwd_pkt_len_min=rng.normal(60, 15, n),
            fwd_pkt_len_mean=rng.normal(600, 150, n), fwd_pkt_len_std=rng.normal(400, 100, n),
            bwd_pkt_len_mean=rng.normal(700, 180, n), active_mean=rng.normal(1.0, 0.4, n),
            idle_mean=rng.normal(2.0, 0.8, n), bwd_iat_mean=rng.normal(0.09, 0.03, n),
            fwd_iat_mean=rng.normal(0.08, 0.03, n),
        )
    base.update({k: np.abs(v) for k, v in d.items()})
    base["label"] = [label] * n
    return pd.DataFrame(base)

parts = [
    make_rows(N, "Benign", "benign"),
    make_rows(N // 4, "DDoS-SYN-Flood", "syn"),
    make_rows(N // 6, "DDoS-DNS-Amplification", "ampl"),
    make_rows(N // 6, "DDoS-NTP-Amplification", "ampl"),
    make_rows(N // 8, "DDoS-Slowloris", "slow"),
    make_rows(N // 8, "DDoS-UDP-Flood", "syn"),
]
df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv("data/synthetic_test.csv", index=False)
print(f"Wrote data/synthetic_test.csv: {len(df)} rows, {len(df.columns)} cols")
print(df["label"].value_counts())

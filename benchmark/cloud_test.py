"""Cloud DDoS API benchmark."""
from __future__ import annotations
import argparse, asyncio, json, statistics, time
from pathlib import Path
import aiohttp
import pandas as pd

EXCLUDE_COLS = {"label", "src_ip", "dst_ip", "src_port", "dst_port",
                "timestamp", "flow_id", "src_mac", "dst_mac",
                "attack_type", "category", "class"}


def load_test_flows(data_path, n_samples=1000):
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
    half = n_samples // 2
    benign_df = df[df["label"].str.lower() == "benign"]
    ddos_df = df[df["label"].str.lower() != "benign"]
    benign = benign_df.sample(n=min(half, len(benign_df)), random_state=42)
    ddos = ddos_df.sample(n=min(half, len(ddos_df)), random_state=42)
    sample = pd.concat([benign, ddos]).sample(frac=1, random_state=42)
    flows = []
    for _, row in sample.iterrows():
        features = {k: float(v) for k, v in row.items()
                    if k not in EXCLUDE_COLS and isinstance(v, (int, float))
                    and pd.notna(v)}
        flows.append({"features": features,
                      "flow_id": f"bench-{len(flows):05d}",
                      "true_label": str(row["label"])})
    print(f"Loaded {len(flows)} test flows")
    return flows


async def send_request(session, url, payload):
    start = time.perf_counter()
    try:
        async with session.post(f"{url}/predict", json=payload,
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            result = await resp.json()
            return {"success": True,
                    "latency_ms": (time.perf_counter() - start) * 1000,
                    "is_ddos_pred": result.get("is_ddos"),
                    "true_is_ddos": payload["true_label"].strip().lower() != "benign"}
    except Exception as e:
        return {"success": False, "error": str(e)[:80],
                "latency_ms": (time.perf_counter() - start) * 1000}


async def run_concurrent(url, flows, concurrency):
    connector = aiohttp.TCPConnector(limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*[send_request(session, url, flows[i % len(flows)])
                                for i in range(min(5, concurrency))])
        return await asyncio.gather(*[send_request(session, url, f) for f in flows])


def calculate_metrics(results, duration_s):
    ok = [r for r in results if r["success"]]
    if not ok:
        return {"error": "No successful requests"}
    latencies = sorted([r["latency_ms"] for r in ok])
    tp = sum(1 for r in ok if r["is_ddos_pred"] and r["true_is_ddos"])
    fp = sum(1 for r in ok if r["is_ddos_pred"] and not r["true_is_ddos"])
    tn = sum(1 for r in ok if not r["is_ddos_pred"] and not r["true_is_ddos"])
    fn = sum(1 for r in ok if not r["is_ddos_pred"] and r["true_is_ddos"])
    p = tp / max(tp + fp, 1); r = tp / max(tp + fn, 1)
    return {"total": len(results), "successful": len(ok),
            "failed": len(results) - len(ok),
            "duration_s": round(duration_s, 2),
            "throughput_rps": round(len(ok) / duration_s, 1),
            "latency_p50_ms": round(statistics.median(latencies), 2),
            "latency_p95_ms": round(latencies[int(len(latencies) * 0.95)], 2),
            "latency_p99_ms": round(latencies[int(len(latencies) * 0.99)], 2),
            "latency_avg_ms": round(statistics.mean(latencies), 2),
            "f1_score": round(2 * p * r / max(p + r, 1e-9), 4),
            "accuracy": round((tp + tn) / max(tp + fp + tn + fn, 1), 4),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def run_benchmark(url, data_path, concurrency_levels, n_samples, output):
    import requests
    try:
        r = requests.get(f"{url}/health", timeout=5).json()
        if not r.get("model_loaded"):
            print("❌ Загвар load болоогүй!")
            return
        print(f"✅ API healthy: {r.get('feature_count')} features\n")
    except Exception as e:
        print(f"❌ Cannot reach API: {e}")
        return

    flows = load_test_flows(data_path, n_samples)
    all_results = {}

    print(f"\n{'='*78}\nBENCHMARK — {url}\n{'='*78}")
    print(f"{'Conc':>6} {'Time(s)':>8} {'RPS':>8} {'p50':>7} {'p95':>7} {'p99':>7} {'F1':>7} {'Err':>5}")
    print("-" * 78)

    for c in concurrency_levels:
        start = time.perf_counter()
        results = asyncio.run(run_concurrent(url, flows, c))
        elapsed = time.perf_counter() - start
        m = calculate_metrics(results, elapsed)
        all_results[f"c{c}"] = m
        print(f"{c:>6} {m['duration_s']:>8.2f} {m['throughput_rps']:>8.1f} "
              f"{m['latency_p50_ms']:>7.1f} {m['latency_p95_ms']:>7.1f} "
              f"{m['latency_p99_ms']:>7.1f} {m['f1_score']:>7.3f} {m['failed']:>5}")
        time.sleep(2)

    Path(output).write_text(json.dumps({
        "url": url, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_samples": n_samples, "results": all_results
    }, indent=2))
    print(f"\n💾 Saved: {output}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--data", required=True)
    p.add_argument("--concurrency", nargs="+", type=int, default=[1, 5, 10, 25, 50])
    p.add_argument("--samples", type=int, default=500)
    p.add_argument("--output", default="results.json")
    a = p.parse_args()
    run_benchmark(a.url, a.data, a.concurrency, a.samples, a.output)

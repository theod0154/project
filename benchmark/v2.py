"""Cloud benchmark v2 — httpx, sequential per concurrency level."""
import argparse, json, statistics, time, threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import pandas as pd

EXCLUDE = {"label", "src_ip", "dst_ip", "src_port", "dst_port",
           "timestamp", "flow_id", "src_mac", "dst_mac",
           "attack_type", "category", "class"}


def load_flows(path, n):
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
    benign = df[df["label"].str.lower() == "benign"]
    ddos = df[df["label"].str.lower() != "benign"]
    half = n // 2
    sample = pd.concat([
        benign.sample(n=min(half, len(benign)), random_state=42),
        ddos.sample(n=min(half, len(ddos)), random_state=42),
    ]).sample(frac=1, random_state=42).reset_index(drop=True)
    flows = []
    for _, row in sample.iterrows():
        features = {k: float(v) for k, v in row.items()
                    if k not in EXCLUDE and isinstance(v, (int, float))
                    and pd.notna(v)}
        flows.append({"features": features,
                      "flow_id": f"b{len(flows):04d}",
                      "true_label": str(row["label"])})
    return flows


def call(session, url, payload, timeout):
    start = time.perf_counter()
    try:
        r = session.post(f"{url}/predict", json=payload, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        if r.status_code == 200:
            j = r.json()
            return {"ok": True, "ms": elapsed,
                    "pred_ddos": j["is_ddos"],
                    "true_ddos": payload["true_label"].strip().lower() != "benign"}
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {"ok": False, "ms": elapsed, "err": str(e)[:60]}
    return {"ok": False, "ms": elapsed, "err": f"HTTP {r.status_code}"}


def bench_one(url, flows, concurrency, timeout=30):
    session = requests.Session()
    # warmup
    for f in flows[:3]:
        call(session, url, f, timeout)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        results = list(ex.map(lambda f: call(session, url, f, timeout), flows))
    elapsed = time.perf_counter() - start
    session.close()
    return results, elapsed


def metrics(results, duration):
    ok = [r for r in results if r["ok"]]
    err = [r for r in results if not r["ok"]]
    if not ok:
        return {"err": "all failed", "errors": len(err)}
    lats = sorted(r["ms"] for r in ok)
    tp = sum(1 for r in ok if r["pred_ddos"] and r["true_ddos"])
    fp = sum(1 for r in ok if r["pred_ddos"] and not r["true_ddos"])
    tn = sum(1 for r in ok if not r["pred_ddos"] and not r["true_ddos"])
    fn = sum(1 for r in ok if not r["pred_ddos"] and r["true_ddos"])
    p = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
    return {
        "n": len(results), "ok": len(ok), "err": len(err),
        "time_s": round(duration, 2),
        "rps": round(len(ok) / duration, 2),
        "p50": round(statistics.median(lats), 1),
        "p95": round(lats[int(len(lats) * 0.95)], 1),
        "p99": round(lats[int(len(lats) * 0.99)], 1),
        "avg": round(statistics.mean(lats), 1),
        "f1": round(2 * p * rec / max(p + rec, 1e-9), 4),
        "acc": round((tp + tn) / max(tp + fp + tn + fn, 1), 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--data", required=True)
    p.add_argument("--concurrency", nargs="+", type=int, default=[1, 2, 5, 10])
    p.add_argument("--samples", type=int, default=100)
    p.add_argument("--output", default="results.json")
    args = p.parse_args()

    h = requests.get(f"{args.url}/health", timeout=5).json()
    print(f"✅ API: {h['feature_count']} features, uptime {h['uptime_seconds']:.0f}s\n")

    flows = load_flows(args.data, args.samples)
    print(f"Loaded {len(flows)} flows\n")

    print(f"{'='*78}\n{'Conc':>5} {'Time(s)':>9} {'RPS':>7} {'p50':>7} "
          f"{'p95':>7} {'p99':>7} {'avg':>7} {'F1':>7} {'Err':>5}")
    print("-" * 78)

    all_res = {}
    for c in args.concurrency:
        results, elapsed = bench_one(args.url, flows, c)
        m = metrics(results, elapsed)
        all_res[f"c{c}"] = m
        print(f"{c:>5} {m['time_s']:>9.2f} {m['rps']:>7.2f} "
              f"{m['p50']:>7.0f} {m['p95']:>7.0f} {m['p99']:>7.0f} "
              f"{m['avg']:>7.0f} {m['f1']:>7.3f} {m['err']:>5}")
        time.sleep(3)

    Path(args.output).write_text(json.dumps({
        "url": args.url, "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": all_res}, indent=2))
    print(f"\n💾 {args.output}")


if __name__ == "__main__":
    main()

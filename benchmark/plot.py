"""DDoS илрүүлэлтийн гүйцэтгэлийн харьцуулсан график (Local vs AWS)."""
import json
import matplotlib.pyplot as plt
from pathlib import Path

BG = "#FFFFFF"
GRID = "#E0E0E0"
TEXT = "#1A1A2E"
AWS_COLOR = "#C0392B"
LOCAL_COLOR = "#27AE60"

plt.rcParams["font.family"] = ["DejaVu Sans", "Liberation Sans", "sans-serif"]
plt.rcParams["axes.unicode_minus"] = False

aws = json.loads(Path("results_aws_full.json").read_text())["results"]
local = json.loads(Path("results_local_full.json").read_text())["results"]

concurrencies = sorted([int(k[1:]) for k in aws.keys()])

fig, axes = plt.subplots(2, 2, figsize=(15, 11), facecolor=BG)
fig.suptitle("Үүлэн орчны DDoS халдлага илрүүлэх системийн гүйцэтгэлийн харьцуулалт\n"
             "Локал хүрээлэн (Kali Linux) ба AWS US-East-1 (Virginia, t2.micro)",
             color=TEXT, fontsize=14, fontweight="bold", y=0.995)

panels = [
    ("p50", "Хариу өгөх дундаж хугацаа (p50)",
     "Хариу хугацаа (мс)",
     "Хүсэлтүүдийн 50% энэ хугацаанаас бага дотор боловсруулагдсан"),
    ("p95", "95-р хувийн хариу хугацаа (p95)",
     "Хариу хугацаа (мс)",
     "Хүсэлтүүдийн 95% энэ хугацаанаас бага дотор боловсруулагдсан"),
    ("rps", "Дамжуулах чадавхи (Throughput)",
     "Секундэд боловсруулсан хүсэлт",
     "Системийн нэгж хугацаанд гүйцэтгэх ажлын хэмжээ"),
    ("f1", "Илрүүлэлтийн нарийвчлал (F1 оноо)",
     "F1 оноо",
     "Precision болон Recall-ын гармоник дундаж"),
]

for ax, (metric, title, ylabel, subtitle) in zip(axes.flat, panels):
    aws_y = [aws[f"c{c}"][metric] for c in concurrencies]
    local_y = [local[f"c{c}"][metric] for c in concurrencies]

    ax.plot(concurrencies, local_y, marker="s", linewidth=2.5, markersize=11,
            label="Локал хүрээлэн", color=LOCAL_COLOR,
            markeredgecolor="white", markeredgewidth=1.5)
    ax.plot(concurrencies, aws_y, marker="o", linewidth=2.5, markersize=11,
            label="AWS үүлэн орчин (t2.micro)", color=AWS_COLOR,
            markeredgecolor="white", markeredgewidth=1.5)

    for x, y in zip(concurrencies, local_y):
        label = f"{y:.0f}" if metric != "f1" else f"{y:.3f}"
        ax.annotate(label, (x, y), textcoords="offset points", xytext=(0, 12),
                    ha="center", fontsize=8, color=LOCAL_COLOR, fontweight="bold")
    for x, y in zip(concurrencies, aws_y):
        label = f"{y:.0f}" if metric != "f1" else f"{y:.3f}"
        ax.annotate(label, (x, y), textcoords="offset points", xytext=(0, -17),
                    ha="center", fontsize=8, color=AWS_COLOR, fontweight="bold")

    if metric == "rps":
        ax.axhline(7.7, color="#888", linestyle=":", linewidth=1.2, alpha=0.7)
        ax.text(concurrencies[-1], 7.7, "  Онолын дээд хязгаар (1 vCPU)",
                fontsize=8, color="#666", va="center")

    ax.set_xlabel("Зэрэгцээ хүсэлтийн тоо (Concurrency)",
                  color=TEXT, fontsize=10, fontweight="500")
    ax.set_ylabel(ylabel, color=TEXT, fontsize=10, fontweight="500")
    ax.set_title(title, color=TEXT, fontweight="bold", fontsize=12, pad=12)
    ax.text(0.5, -0.22, subtitle, transform=ax.transAxes, ha="center",
            fontsize=8, color="#666", style="italic")

    ax.legend(facecolor="#F8F8F8", edgecolor="#BBB", labelcolor=TEXT,
              fontsize=9, loc="best", framealpha=0.95)
    ax.grid(alpha=0.6, color=GRID, linestyle="--", linewidth=0.7)
    ax.set_facecolor(BG)
    ax.tick_params(colors=TEXT, labelsize=9)
    for spine in ax.spines.values():
        spine.set_color("#999")
        spine.set_linewidth(0.8)
    ax.set_xticks(concurrencies)
    if metric == "f1":
        ax.set_ylim(0.9, 1.02)

fig.text(0.5, 0.01,
         "Хэмжилт: Mongolia → US-East-1 сүлжээний дундаж RTT ≈ 422 мс  |  "
         "Туршилтын дээж: 200 урсгал × 6 түвшин = 1,200 хүсэлт",
         ha="center", fontsize=9, color="#555", style="italic")

plt.tight_layout(rect=[0, 0.03, 1, 0.97])
plt.savefig("benchmark_comparison.png", dpi=150, facecolor=BG, bbox_inches="tight")
print("✅ Хадгалагдсан: benchmark_comparison.png")

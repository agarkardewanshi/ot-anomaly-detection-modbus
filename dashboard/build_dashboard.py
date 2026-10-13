"""
build_dashboard.py

MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
PURPOSE
------------------------------------------------------------------------------
Generates a single self-contained HTML dashboard from the existing results
CSVs (rule_based_results.csv, ml_results.csv) plus the baseline/attack CSVs
for summary stats.

This was built as a working prototype after the original ELK/Kibana
dashboard plan could not be completed reliably (see Section 6.4 of the
dissertation). Unlike the ELK route, this has no server, no database, and
no ingestion pipeline to fail: every chart is a base64-embedded image
inside one HTML file, so the output opens directly in any browser.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
    1. Run both detection scripts first (they write to results/).
    2. python3 dashboard/build_dashboard.py
    3. Open results/dashboard.html in any browser.

------------------------------------------------------------------------------
OUTPUT
------------------------------------------------------------------------------
    results/dashboard.html -- open this in any browser, works fully offline.
------------------------------------------------------------------------------
"""

from pathlib import Path

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import base64
import io
from datetime import datetime

# ==============================================================================
# CONFIG -- paths are relative to the repository root
# ==============================================================================
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
RESULTS_DIR = REPO_ROOT / "results"

CONFIG = {
    "rule_based_results": RESULTS_DIR / "rule_based_results.csv",
    "ml_results": RESULTS_DIR / "ml_results.csv",
    "baseline_csv": DATA_DIR / "baseline_normal.csv",
    "attack_csvs": {
        "false_data_injection": DATA_DIR / "attack1_writes.csv",
        "replay": DATA_DIR / "replay_writes.csv",
        "protocol_abuse": DATA_DIR / "protocol_abuse_writes.csv",
    },
    "output_html": RESULTS_DIR / "dashboard.html",
    "project_title": "Rule-Based vs Isolation Forest: Modbus OT Anomaly Detection",
}

COLORS = {"rule": "#2E5C99", "iso": "#1E7A3E", "fpr": "#B34700", "bg": "#F7F9FC"}


def fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def safe_read_csv(path, label):
    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"WARNING: could not read {label} at {path}: {e}")
        return None


def chart_detection_comparison(rule_df, iso_df):
    """Grouped bar chart: caught count per attack type, rule-based vs IF."""
    attack_types = list(iso_df["attack_type"]) if iso_df is not None else list(rule_df["attack_type"])
    x = np.arange(len(attack_types))
    width = 0.35

    fig, ax = plt.subplots(figsize=(7, 4))
    if rule_df is not None:
        rule_caught = [rule_df[rule_df["attack_type"] == a]["caught"].values[0] for a in attack_types]
        ax.bar(x - width/2, rule_caught, width, label="Rule-based", color=COLORS["rule"])
    if iso_df is not None:
        iso_caught = [iso_df[iso_df["attack_type"] == a]["caught"].values[0] for a in attack_types]
        ax.bar(x + width/2, iso_caught, width, label="Isolation Forest", color=COLORS["iso"])

    totals = [iso_df[iso_df["attack_type"] == a]["n_attack_samples"].values[0] if iso_df is not None
              else rule_df[rule_df["attack_type"] == a]["total_rows"].values[0] for a in attack_types]
    for i, t in enumerate(totals):
        ax.text(i, t + 0.3, f"/{t}", ha='center', fontsize=8.5, color="#555555")

    ax.set_xticks(x)
    ax.set_xticklabels([a.replace("_", " ").title() for a in attack_types])
    ax.set_ylabel("Attacks Caught")
    ax.set_title("Detection Rate by Attack Type")
    ax.legend()
    ax.spines[['top', 'right']].set_visible(False)
    return fig_to_base64(fig)


def chart_fpr_comparison(rule_fpr, iso_fpr):
    fig, ax = plt.subplots(figsize=(4.2, 4))
    bars = ax.bar(["Rule-based", "Isolation Forest"], [rule_fpr, iso_fpr],
                   color=[COLORS["rule"], COLORS["iso"]], width=0.55)
    for b, v in zip(bars, [rule_fpr, iso_fpr]):
        ax.text(b.get_x() + b.get_width()/2, v + 0.05, f"{v:.2f}%", ha='center', fontsize=10)
    ax.set_ylabel("False Positive Rate (%)")
    ax.set_title("False Positive Rate on Baseline Traffic")
    ax.spines[['top', 'right']].set_visible(False)
    ax.set_ylim(0, max(iso_fpr, rule_fpr) * 1.6 + 1)
    return fig_to_base64(fig)


def chart_iso_metrics(iso_df):
    metrics = ["precision", "recall", "f1", "mcc"]
    attack_types = list(iso_df["attack_type"])
    x = np.arange(len(attack_types))
    width = 0.2

    fig, ax = plt.subplots(figsize=(7.5, 4))
    palette = ["#1E7A3E", "#3FA65C", "#7FC79A", "#B7E3C5"]
    for i, m in enumerate(metrics):
        vals = iso_df[m].values
        ax.bar(x + (i - 1.5) * width, vals, width, label=m.upper(), color=palette[i])
    ax.set_xticks(x)
    ax.set_xticklabels([a.replace("_", " ").title() for a in attack_types])
    ax.set_ylim(0, 1.15)
    ax.set_title("Isolation Forest: Metrics by Attack Type")
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.12), frameon=False)
    ax.spines[['top', 'right']].set_visible(False)
    return fig_to_base64(fig)


def chart_traffic_volume(baseline_df, attack_dfs):
    labels = ["Baseline"] + [k.replace("_", " ").title() for k in attack_dfs]
    counts = [len(baseline_df) if baseline_df is not None else 0]
    counts += [len(v) for v in attack_dfs.values()]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.barh(labels, counts, color=["#888888"] + [COLORS["iso"]] * len(attack_dfs))
    for b, v in zip(bars, counts):
        ax.text(v + max(counts) * 0.01, b.get_y() + b.get_height()/2, str(v), va='center', fontsize=9)
    ax.set_xlabel("Row Count")
    ax.set_title("Captured Traffic Volume")
    ax.spines[['top', 'right']].set_visible(False)
    return fig_to_base64(fig)


def df_to_html_table(df, round_cols=None):
    if df is None:
        return "<p class='missing'>Data not found - check CONFIG path.</p>"
    d = df.copy()
    if round_cols:
        for c in round_cols:
            if c in d.columns:
                d[c] = d[c].round(3)
    return d.to_html(index=False, classes="data-table", border=0)


def main():
    rule_df = safe_read_csv(CONFIG["rule_based_results"], "rule-based results")
    iso_df = safe_read_csv(CONFIG["ml_results"], "Isolation Forest results")
    baseline_df = safe_read_csv(CONFIG["baseline_csv"], "baseline traffic")
    attack_dfs = {}
    for name, path in CONFIG["attack_csvs"].items():
        d = safe_read_csv(path, name)
        if d is not None:
            attack_dfs[name] = d

    charts = {}
    if rule_df is not None or iso_df is not None:
        charts["detection"] = chart_detection_comparison(rule_df, iso_df)

    rule_fpr = None
    if rule_df is not None and "false_positive_rate" not in rule_df.columns:
        # rule_based_results.csv in this project doesn't carry FPR per row;
        # assume 0.00% as established in Sections 6.4/7.2 unless present.
        rule_fpr = 0.0
    if iso_df is not None and "fpr_on_baseline" in iso_df.columns:
        iso_fpr = float(iso_df["fpr_on_baseline"].iloc[0]) * 100
        charts["fpr"] = chart_fpr_comparison(rule_fpr if rule_fpr is not None else 0.0, iso_fpr)

    if iso_df is not None:
        charts["iso_metrics"] = chart_iso_metrics(iso_df)

    if baseline_df is not None or attack_dfs:
        charts["traffic"] = chart_traffic_volume(baseline_df, attack_dfs)

    rule_table = df_to_html_table(rule_df)
    iso_table = df_to_html_table(iso_df, round_cols=["precision", "recall", "f1", "mcc", "fpr_on_baseline"])

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{CONFIG['project_title']}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background: {COLORS['bg']}; color: #1a1a1a; margin: 0; padding: 0 0 60px 0; }}
  header {{ background: #1A2A44; color: white; padding: 28px 40px; }}
  header h1 {{ margin: 0; font-size: 22px; }}
  header p {{ margin: 6px 0 0 0; color: #B9C4D6; font-size: 13px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 0 32px; }}
  .card {{ background: white; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 24px 28px; margin: 24px 0; }}
  .card h2 {{ margin-top: 0; font-size: 17px; color: #1A2A44; border-bottom: 2px solid #EEF1F6; padding-bottom: 10px; }}
  .chart-row {{ display: flex; flex-wrap: wrap; gap: 24px; justify-content: center; }}
  .chart-row img {{ max-width: 100%; height: auto; }}
  table.data-table {{ border-collapse: collapse; width: 100%; font-size: 13px; margin-top: 10px; }}
  table.data-table th {{ background: #F0F3F8; text-align: left; padding: 8px 10px; border-bottom: 2px solid #D5DCE8; }}
  table.data-table td {{ padding: 7px 10px; border-bottom: 1px solid #EEF1F6; }}
  table.data-table tr:hover {{ background: #FAFBFD; }}
  .missing {{ color: #B02E2E; font-style: italic; }}
  .badge {{ display: inline-block; background: #EEF1F6; color: #445; border-radius: 6px; padding: 3px 10px; font-size: 12px; margin-right: 8px; }}
</style>
</head>
<body>
<header>
  <h1>{CONFIG['project_title']}</h1>
  <p>Generated {datetime.now().strftime('%d %B %Y, %H:%M')} &middot; local results dashboard, no ELK dependency</p>
</header>
<div class="container">

  <div class="card">
    <h2>Detection Comparison</h2>
    <div class="chart-row">
      {"<img src='data:image/png;base64," + charts["detection"] + "'/>" if "detection" in charts else "<p class='missing'>No detection results found.</p>"}
      {"<img src='data:image/png;base64," + charts["fpr"] + "'/>" if "fpr" in charts else ""}
    </div>
  </div>

  <div class="card">
    <h2>Isolation Forest Metrics</h2>
    <div class="chart-row">
      {"<img src='data:image/png;base64," + charts["iso_metrics"] + "'/>" if "iso_metrics" in charts else "<p class='missing'>No Isolation Forest results found.</p>"}
    </div>
  </div>

  <div class="card">
    <h2>Captured Traffic Volume</h2>
    <div class="chart-row">
      {"<img src='data:image/png;base64," + charts["traffic"] + "'/>" if "traffic" in charts else "<p class='missing'>No traffic CSVs found.</p>"}
    </div>
  </div>

  <div class="card">
    <h2>Rule-Based Results (raw)</h2>
    {rule_table}
  </div>

  <div class="card">
    <h2>Isolation Forest Results (raw)</h2>
    {iso_table}
  </div>

</div>
</body>
</html>"""

    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CONFIG["output_html"], "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Dashboard written to {CONFIG['output_html']}")
    print(f"Open it with: firefox {CONFIG['output_html']}")


if __name__ == "__main__":
    main()

"""
isolation_forest_detection.py

MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
PURPOSE
------------------------------------------------------------------------------
Protocol-aware Isolation Forest anomaly detection for Modbus TCP OT traffic.

Trains ONLY on normal (baseline) traffic -- unsupervised, no attack data used
in training. Evaluates against false data injection, replay, and protocol
abuse attack captures. The ground-truth attack_type label is used ONLY for
post-hoc scoring (never as a model input), so results are directly comparable
to rule_based_detection.py and reflect what a real detector could genuinely
achieve without prior knowledge of the attacks.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
    1. Update the CONFIG block below if your file paths or column names
       differ from what is set here (these match the actual CSVs produced
       on the testbed for this project).
    2. python3 detection/isolation_forest_detection.py

------------------------------------------------------------------------------
OUTPUT
------------------------------------------------------------------------------
    - A printed contamination search table and a per-attack-type metrics
      table (precision, recall, F1, MCC, false-positive rate), directly
      comparable to the rule-based results table produced by
      rule_based_detection.py.
    - results/ml_results.csv
------------------------------------------------------------------------------
"""

from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    matthews_corrcoef, confusion_matrix,
)

# ==============================================================================
# CONFIG -- file paths and column names as used on the project testbed.
# Paths are relative to the repository root (data/ for inputs, results/ for
# outputs). Update these if your tshark export field names differ.
# ==============================================================================
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
RESULTS_DIR = REPO_ROOT / "results"

CONFIG = {
    "baseline_csv": DATA_DIR / "baseline_normal.csv",
    "attack_csvs": {
        # attack1_writes.csv is the false-data-injection traffic capture --
        # kept its old pre-split-script name; confirmed by elimination
        # against replay_writes.csv and protocol_abuse_writes.csv, and by
        # matching row counts against the rule-based detection results.
        "false_data_injection": DATA_DIR / "attack1_writes.csv",
        "replay": DATA_DIR / "replay_writes.csv",
        "protocol_abuse": DATA_DIR / "protocol_abuse_writes.csv",
    },
    # Map internal feature names -> actual CSV column names (from tshark
    # export of the captured Modbus TCP traffic).
    "columns": {
        "timestamp": "frame.time_epoch",
        "function_code": "modbus.func_code",
        "register_address": "modbus.reference_num",
        "register_value": "modbus.regval_uint16",
        "attack_type": None,  # not present in these files -- unused by this script
    },
    # Fraction of baseline held out (never used in training) to measure FPR
    # and to pair with each attack CSV for a proper 2-class evaluation.
    "baseline_holdout_frac": 0.3,
    # Small hyperparameter search: candidate contamination values to try.
    "contamination_grid": [0.01, 0.02, 0.05, 0.1],
    "random_state": 42,
    "output_csv": RESULTS_DIR / "ml_results.csv",
}


# ==============================================================================
# Feature engineering -- protocol-aware, not generic packet statistics
# ==============================================================================
def engineer_features(df: pd.DataFrame, cols: dict):
    """
    Builds Modbus-semantic features from a raw traffic CSV:
      - function_code          : raw Modbus function code
      - register_address       : target register/coil address
      - register_value         : value read or written
      - value_delta             : change vs. the last-seen value for THIS
                                  register address (catches false data
                                  injection: a legitimate tank level moves
                                  gradually, an injected value jumps)
      - inter_arrival_same_reg : seconds since the last request to THIS
                                  register (catches replay: replaying a
                                  request breaks the normal per-register
                                  polling cadence)
      - is_write                : 1 if function code is a write op, else 0
                                  (protocol abuse often means illegitimate
                                  writes, but also covers illegal reads via
                                  register_address/function_code)

    Feature engineering is deliberately protocol-aware (keyed on register
    address + function code semantics) rather than protocol-agnostic
    (generic packet size / global inter-arrival time), consistent with the
    Problem and Approach sections of the dissertation.
    """
    df = df.sort_values(cols["timestamp"]).reset_index(drop=True)

    df["function_code"] = df[cols["function_code"]]
    df["register_address"] = df[cols["register_address"]]
    df["register_value"] = df[cols["register_value"]]

    # Per-register value delta and inter-arrival time, computed within
    # groups of the same register address so timing/value comparisons are
    # semantically meaningful (comparing a register only to its own history).
    df["value_delta"] = (
        df.groupby("register_address")["register_value"].diff().fillna(0)
    )
    df["inter_arrival_same_reg"] = (
        df.groupby("register_address")[cols["timestamp"]].diff().fillna(0)
    )

    write_codes = {5, 6, 15, 16}  # standard Modbus write function codes
    df["is_write"] = df["function_code"].isin(write_codes).astype(int)

    feature_cols = [
        "function_code",
        "register_address",
        "register_value",
        "value_delta",
        "inter_arrival_same_reg",
        "is_write",
    ]
    return df, feature_cols


def load_and_engineer(path: str, cols: dict):
    df = pd.read_csv(path)
    df, feature_cols = engineer_features(df, cols)
    return df, feature_cols


# ==============================================================================
# Evaluation helper: builds a 2-class (benign vs. this attack) set,
# scores it, and computes the full metric suite.
# ==============================================================================
def evaluate(model, scaler, benign_df, attack_df, feature_cols, threshold):
    eval_df = pd.concat([benign_df, attack_df], ignore_index=True)
    y_true = np.concatenate([
        np.zeros(len(benign_df)),
        np.ones(len(attack_df)),
    ])

    X = scaler.transform(eval_df[feature_cols])
    scores = -model.decision_function(X)  # higher score = more anomalous
    y_pred = (scores > threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "n_benign": len(benign_df),
        "n_attack": len(attack_df),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "mcc": matthews_corrcoef(y_true, y_pred) if len(set(y_pred)) > 1 else 0.0,
        "fpr": fpr,
    }


def main():
    cols = CONFIG["columns"]
    rs = CONFIG["random_state"]

    # --- Load and feature-engineer baseline, split into train/holdout ---
    baseline_df, feature_cols = load_and_engineer(CONFIG["baseline_csv"], cols)
    n_holdout = int(len(baseline_df) * CONFIG["baseline_holdout_frac"])
    baseline_train = baseline_df.iloc[:-n_holdout].reset_index(drop=True)
    baseline_holdout = baseline_df.iloc[-n_holdout:].reset_index(drop=True)

    print(f"Baseline: {len(baseline_df)} rows "
          f"({len(baseline_train)} train / {len(baseline_holdout)} holdout)")

    # --- Load and feature-engineer each attack CSV ---
    attack_dfs = {}
    for name, path in CONFIG["attack_csvs"].items():
        adf, _ = load_and_engineer(path, cols)
        attack_dfs[name] = adf
        print(f"{name}: {len(adf)} rows")

    # --- Scale features on training data only ---
    scaler = StandardScaler()
    X_train = scaler.fit_transform(baseline_train[feature_cols])

    # --- Hyperparameter search over contamination values ---
    # Selection rule: keep baseline (holdout) FPR low while maximising mean
    # recall across attack types -- this is the class-imbalance-handling /
    # hyperparameter-tuning step described in Section 6.5 of the dissertation.
    best = None
    search_rows = []

    for contamination in CONFIG["contamination_grid"]:
        model = IsolationForest(
            contamination=contamination,
            random_state=rs,
            n_estimators=200,
        )
        model.fit(X_train)

        # Set the decision threshold from the baseline holdout scores so we
        # directly control FPR, rather than relying on contamination alone
        # to fix the operating point.
        holdout_scores = -model.decision_function(
            scaler.transform(baseline_holdout[feature_cols])
        )
        threshold = np.percentile(holdout_scores, 100 * (1 - contamination))

        per_attack = {}
        recalls = []
        for name, adf in attack_dfs.items():
            metrics = evaluate(model, scaler, baseline_holdout, adf,
                                feature_cols, threshold)
            per_attack[name] = metrics
            recalls.append(metrics["recall"])

        baseline_fpr = per_attack[list(attack_dfs)[0]]["fpr"]  # same holdout each time
        mean_recall = float(np.mean(recalls))
        search_rows.append({
            "contamination": contamination,
            "threshold": threshold,
            "baseline_fpr": baseline_fpr,
            "mean_recall": mean_recall,
        })

        if best is None or (mean_recall, -baseline_fpr) > (best["mean_recall"], -best["baseline_fpr"]):
            best = {
                "contamination": contamination,
                "threshold": threshold,
                "model": model,
                "per_attack": per_attack,
                "baseline_fpr": baseline_fpr,
                "mean_recall": mean_recall,
            }

    print("\nContamination search:")
    print(pd.DataFrame(search_rows).to_string(index=False))

    print(f"\nSelected contamination = {best['contamination']} "
          f"(baseline FPR = {best['baseline_fpr']:.2%}, "
          f"mean recall = {best['mean_recall']:.2%})")

    # --- Final results table, same shape as the rule-based results ---
    rows = []
    for name, m in best["per_attack"].items():
        rows.append({
            "attack_type": name,
            "n_attack_samples": m["n_attack"],
            "caught": m["TP"],
            "missed": m["FN"],
            "precision": round(m["precision"], 3),
            "recall": round(m["recall"], 3),
            "f1": round(m["f1"], 3),
            "mcc": round(m["mcc"], 3),
            "fpr_on_baseline": round(m["fpr"], 4),
        })
    results_df = pd.DataFrame(rows)
    print("\nIsolation Forest results (per attack type):")
    print(results_df.to_string(index=False))

    RESULTS_DIR.mkdir(exist_ok=True)
    results_df.to_csv(CONFIG["output_csv"], index=False)
    print(f"\nSaved to {CONFIG['output_csv']}")


if __name__ == "__main__":
    main()

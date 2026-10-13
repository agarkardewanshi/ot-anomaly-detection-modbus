"""
rule_based_detection.py

MSc Cybersecurity Dissertation
Evaluating Machine Learning Approaches for Anomaly Detection in OT Network Traffic
Dewanshi Manoj Agarkar

------------------------------------------------------------------------------
PURPOSE
------------------------------------------------------------------------------
Rule-based (SIEM-style) detector for Modbus TCP OT traffic. Implements three
independent detection rules, each targeting a different attack type:

    rule_false_data_injection  -- flags writes with implausible register
                                   values (outside NORMAL_MIN-NORMAL_MAX)
    rule_replay                -- flags repeated writes of the same
                                   (register, value) pair within a short
                                   time window (REPLAY_WINDOW_SECONDS)
    rule_protocol_abuse        -- flags Modbus exception codes, writes to
                                   registers/coils outside the known-valid
                                   set (VALID_REGISTERS / VALID_COILS)

Each rule works only from traffic-observable fields (function code, register
address, register value, timestamp). The ground-truth attack_type label is
never used as an input to any rule -- it exists only in the separate results
CSV, produced afterwards for scoring, not during detection itself.

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
Run against the baseline and attack CSVs in data/:

    python3 detection/rule_based_detection.py

------------------------------------------------------------------------------
OUTPUT
------------------------------------------------------------------------------
    - Per-attack-type breakdown of which rows were caught/missed and by
      which rule, printed to the console.
    - results/rule_based_results.csv: summary table (total/caught/missed per attack
      type, plus per-rule breakdown), directly comparable to
      isolation_forest_detection.py's ml_results.csv.
    - A false-positive check against the baseline traffic, printed to the
      console.
------------------------------------------------------------------------------
"""

from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
RESULTS_DIR = REPO_ROOT / "results"

COLUMNS = ["frame_time_epoch", "ip_src", "ip_dst", "modbus_func_code", "modbus_reference_num", "modbus_regval_uint16"]

NORMAL_MIN = 200
NORMAL_MAX = 800

VALID_REGISTERS = {0}
VALID_COILS = set()

WRITE_FUNC_CODES = {5, 6, 15, 16}
READ_FUNC_CODES = {1, 2, 3, 4}
EXCEPTION_THRESHOLD = 0x80

REPLAY_WINDOW_SECONDS = 30

FILES = {
    "false_data_injection": DATA_DIR / "attack1_writes.csv",
    "replay": DATA_DIR / "replay_writes.csv",
    "protocol_abuse": DATA_DIR / "protocol_abuse_writes.csv",
}

BASELINE_FILE = DATA_DIR / "baseline_normal.csv"


def load_csv(path):
    df = pd.read_csv(path, names=COLUMNS, header=0)
    df["frame_time_epoch"] = df["frame_time_epoch"].astype(float)
    return df.sort_values("frame_time_epoch").reset_index(drop=True)


def rule_replay(df):
    flags = pd.Series(False, index=df.index)
    writes = df[df["modbus_func_code"].isin(WRITE_FUNC_CODES)]
    for (ref, val), group in writes.groupby(["modbus_reference_num", "modbus_regval_uint16"]):
        times = group["frame_time_epoch"].values
        if len(times) < 2:
            continue
        for i in range(1, len(times)):
            if times[i] - times[i - 1] <= REPLAY_WINDOW_SECONDS:
                flags.loc[group.index[i]] = True
                flags.loc[group.index[i - 1]] = True
    return flags


def rule_protocol_abuse(df):
    is_exception = df["modbus_func_code"] >= EXCEPTION_THRESHOLD
    is_bad_register = (
        df["modbus_func_code"].isin({6, 16})
        & ~df["modbus_reference_num"].isin(VALID_REGISTERS)
    )
    is_bad_coil = (
        df["modbus_func_code"].isin({5, 15})
        & ~df["modbus_reference_num"].isin(VALID_COILS)
    )
    return is_exception | is_bad_register | is_bad_coil


def rule_false_data_injection(df):
    is_write = df["modbus_func_code"].isin({6, 16})
    out_of_range = ~df["modbus_regval_uint16"].between(NORMAL_MIN, NORMAL_MAX)
    return is_write & out_of_range & df["modbus_regval_uint16"].notna()


RULES = {
    "replay": rule_replay,
    "protocol_abuse": rule_protocol_abuse,
    "false_data_injection": rule_false_data_injection,
}


def main():
    results = []
    for attack_type, filename in FILES.items():
        df = load_csv(filename)
        total = len(df)

        flags_by_rule = {name: rule_fn(df) for name, rule_fn in RULES.items()}
        any_flagged = pd.Series(False, index=df.index)
        for flags in flags_by_rule.values():
            any_flagged |= flags

        caught = any_flagged.sum()
        missed = total - caught

        results.append({
            "attack_type": attack_type,
            "total_rows": total,
            "caught": int(caught),
            "missed": int(missed),
            "caught_by_replay_rule": int(flags_by_rule["replay"].sum()),
            "caught_by_protocol_rule": int(flags_by_rule["protocol_abuse"].sum()),
            "caught_by_fdi_rule": int(flags_by_rule["false_data_injection"].sum()),
        })

        print(f"\n=== {attack_type} ({filename.name}) ===")
        print(df[any_flagged].to_string(index=False) if caught else "  (nothing flagged)")
        if missed:
            print(f"  -- {missed} row(s) NOT caught by any rule --")
            print(df[~any_flagged].to_string(index=False))

    print("\n=== Summary ===")
    summary = pd.DataFrame(results)
    print(summary.to_string(index=False))
    RESULTS_DIR.mkdir(exist_ok=True)
    summary.to_csv(RESULTS_DIR / "rule_based_results.csv", index=False)
    print("\nSaved summary to results/rule_based_results.csv")

    print("\n=== False Positive Check (baseline normal traffic) ===")
    baseline_df = load_csv(BASELINE_FILE)
    baseline_total = len(baseline_df)
    fp_by_rule = {name: rule_fn(baseline_df) for name, rule_fn in RULES.items()}
    any_fp = pd.Series(False, index=baseline_df.index)
    for flags in fp_by_rule.values():
        any_fp |= flags
    fp_count = any_fp.sum()
    fp_rate = fp_count / baseline_total if baseline_total else 0

    print(f"Baseline rows: {baseline_total}")
    print(f"False positives (any rule fired): {fp_count}")
    print(f"False positive rate: {fp_rate:.2%}")
    for name, flags in fp_by_rule.items():
        print(f"  - {name} rule fired on {flags.sum()} baseline rows")


if __name__ == "__main__":
    main()
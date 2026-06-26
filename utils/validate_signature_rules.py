from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.preprocess import clean_payload_text, normalize_cve_labels

RULE_TO_LABEL = {
    "wsman-38649": "CVE-2021-38649",
    "fortinet-13379": "CVE-2018-13379",
    "hikvision-7921": "CVE-2017-7921",
    "sonicwall-20016": "CVE-2021-20016",
    "spip-27372": "CVE-2023-27372",
}


def rule_hits(payload: str, labels: set[str]) -> set[str]:
    text = clean_payload_text(payload).lower()
    hits: set[str] = set()
    if "/wsman" in text and {"CVE-2021-38645", "CVE-2021-38647", "CVE-2021-38648"}.issubset(labels):
        hits.add("wsman-38649")
    if "/remote/fgt_lang" in text and ("../" in text or "%2e%2e" in text):
        hits.add("fortinet-13379")
    if "/onvif-http/snapshot" in text:
        hits.add("hikvision-7921")
    if "/__api__/v1/logon/" in text and "/authenticate" in text:
        hits.add("sonicwall-20016")
    if ("/spip.php" in text or "/spip.ph%70" in text) and "spip_pass" in text:
        hits.add("spip-27372")
    return hits


def load_frames(paths: list[Path], payload_column: str, label_column: str) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for path in paths:
        frame = pd.read_csv(path)
        if payload_column not in frame.columns:
            raise KeyError(f"{path} missing payload column {payload_column!r}")
        if label_column not in frame.columns:
            raise KeyError(f"{path} missing label column {label_column!r}")
        frame = frame[[payload_column, label_column]].copy()
        frame["source_file"] = str(path)
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def evaluate_rows(labels_list: list[set[str]], hits_list: list[set[str]], rows: np.ndarray) -> dict[str, dict[str, float | int | str]]:
    stats: dict[str, Counter[str]] = defaultdict(Counter)
    for row_idx in rows:
        labels = labels_list[int(row_idx)]
        hits = hits_list[int(row_idx)]
        for rule, target in RULE_TO_LABEL.items():
            if rule in hits and target in labels:
                stats[rule]["tp"] += 1
            elif rule in hits and target not in labels:
                stats[rule]["fp"] += 1
            elif rule not in hits and target in labels:
                stats[rule]["fn"] += 1

    output: dict[str, dict[str, float | int | str]] = {}
    for rule, target in RULE_TO_LABEL.items():
        tp = stats[rule]["tp"]
        fp = stats[rule]["fp"]
        fn = stats[rule]["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        output[rule] = {
            "rule": rule,
            "target": target,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": tp + fn,
            "hits": tp + fp,
        }
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate payload signature rules on labeled training data.")
    parser.add_argument("--input", action="append", required=True, type=Path, help="CSV with payload and cve_labels; repeatable")
    parser.add_argument("--payload-column", default="payload_clean")
    parser.add_argument("--label-column", default="cve_labels")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260626)
    parser.add_argument("--min-train-precision", type=float, default=0.90)
    parser.add_argument("--min-train-tp", type=int, default=1)
    parser.add_argument("--output-summary", required=True, type=Path)
    parser.add_argument("--output-folds", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    frame = load_frames(args.input, args.payload_column, args.label_column)
    labels_list = [set(normalize_cve_labels(value)) for value in frame[args.label_column].fillna("")]
    payloads = frame[args.payload_column].fillna("").astype(str).tolist()
    hits_list = [rule_hits(payload, labels) for payload, labels in zip(payloads, labels_list)]

    indices = np.arange(len(frame))
    rng = np.random.default_rng(args.seed)
    rng.shuffle(indices)
    fold_ids = np.empty(len(frame), dtype=np.int32)
    for fold_no, fold_rows in enumerate(np.array_split(indices, args.folds)):
        fold_ids[fold_rows] = fold_no

    all_summary = evaluate_rows(labels_list, hits_list, np.arange(len(frame)))
    summary = pd.DataFrame(all_summary.values()).sort_values(["precision", "tp", "rule"], ascending=[False, False, True])

    fold_output: list[dict[str, float | int | str | bool]] = []
    for fold_no in range(args.folds):
        valid_rows = np.where(fold_ids == fold_no)[0]
        train_rows = np.where(fold_ids != fold_no)[0]
        train_stats = evaluate_rows(labels_list, hits_list, train_rows)
        valid_stats = evaluate_rows(labels_list, hits_list, valid_rows)
        for rule, train_row in train_stats.items():
            valid_row = valid_stats[rule]
            selected = bool(
                float(train_row["precision"]) >= args.min_train_precision
                and int(train_row["tp"]) >= args.min_train_tp
            )
            fold_output.append(
                {
                    "fold": fold_no,
                    "rule": rule,
                    "target": train_row["target"],
                    "selected": selected,
                    "train_tp": train_row["tp"],
                    "train_fp": train_row["fp"],
                    "train_fn": train_row["fn"],
                    "train_precision": train_row["precision"],
                    "train_recall": train_row["recall"],
                    "valid_tp": valid_row["tp"],
                    "valid_fp": valid_row["fp"],
                    "valid_fn": valid_row["fn"],
                    "valid_precision": valid_row["precision"],
                    "valid_recall": valid_row["recall"],
                }
            )

    args.output_summary.parent.mkdir(parents=True, exist_ok=True)
    args.output_folds.parent.mkdir(parents=True, exist_ok=True)
    summary.to_csv(args.output_summary, index=False)
    pd.DataFrame(fold_output).to_csv(args.output_folds, index=False)
    print(summary.to_string(index=False, float_format=lambda value: f"{value:.6f}"))
    print(f"Wrote {args.output_summary}")
    print(f"Wrote {args.output_folds}")


if __name__ == "__main__":
    main()

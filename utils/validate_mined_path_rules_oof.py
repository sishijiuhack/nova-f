from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.preprocess import clean_payload_text, normalize_cve_labels


def extract_method_path(payload: str) -> tuple[str, str]:
    cleaned = clean_payload_text(payload)
    parts = cleaned.split(" ", 2)
    if len(parts) < 2:
        return "", ""
    return parts[0].upper(), parts[1].split("?", 1)[0].lower()


def normalize_path(path: str) -> str:
    path = re.sub(r"%[0-9a-fA-F]{2}", "%xx", path)
    path = re.sub(r"[0-9a-fA-F]{16,}", "{hex}", path)
    path = re.sub(r"\d+", "{num}", path)
    return path


def candidate_keys(method: str, path: str, *, match_level: str) -> list[str]:
    if not method or not path:
        return []
    normalized = normalize_path(path)
    parts = [part for part in normalized.split("/") if part]
    keys = [f"{method} {normalized}"]
    if match_level == "all":
        if len(parts) >= 2:
            keys.append(f"{method} /{parts[0]}/{parts[1]}")
        if parts:
            keys.append(f"{method} /{parts[0]}")
    return keys


def load_frames(paths: list[Path], payload_column: str, label_column: str) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for path in paths:
        frame = pd.read_csv(path)
        if payload_column not in frame.columns:
            raise KeyError(f"{path} missing {payload_column!r}")
        if label_column not in frame.columns:
            raise KeyError(f"{path} missing {label_column!r}")
        frame = frame[[payload_column, label_column]].copy()
        frame["source_file"] = str(path)
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def mine_rules(
    keys_list: list[list[str]],
    labels_list: list[set[str]],
    rows: np.ndarray,
    *,
    min_support: int,
    min_precision: float,
) -> dict[str, str]:
    key_counts: Counter[str] = Counter()
    key_label_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row_idx in rows:
        labels = labels_list[int(row_idx)]
        if not labels:
            continue
        for key in keys_list[int(row_idx)]:
            key_counts[key] += 1
            for label in labels:
                key_label_counts[key][label] += 1

    rules: dict[str, str] = {}
    for key, total in key_counts.items():
        if not total:
            continue
        label, count = key_label_counts[key].most_common(1)[0]
        precision = count / total
        if count >= min_support and precision >= min_precision:
            rules[key] = label
    return rules


def evaluate_rules(
    keys_list: list[list[str]],
    labels_list: list[set[str]],
    rows: np.ndarray,
    rules: dict[str, str],
    *,
    max_additions: int,
) -> dict[str, float | int]:
    tp = fp = fn = changed = 0
    per_label: dict[str, Counter[str]] = defaultdict(Counter)
    target_labels = set(rules.values())

    for row_idx in rows:
        labels = labels_list[int(row_idx)]
        additions: list[str] = []
        for key in keys_list[int(row_idx)]:
            label = rules.get(key)
            if label and label not in additions:
                additions.append(label)
                if len(additions) >= max_additions:
                    break
        if additions:
            changed += 1
        predicted = set(additions)
        expected = labels & target_labels
        tp += len(predicted & expected)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        for label in predicted | expected:
            bucket = per_label[label]
            if label in predicted and label in expected:
                bucket["tp"] += 1
            elif label in predicted:
                bucket["fp"] += 1
            else:
                bucket["fn"] += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    micro_f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    f1s: list[float] = []
    for counts in per_label.values():
        label_precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
        label_recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
        f1s.append(2 * label_precision * label_recall / (label_precision + label_recall) if label_precision + label_recall else 0.0)
    return {
        "rule_count": len(rules),
        "changed_rows": changed,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "micro_f1": micro_f1,
        "macro_f1": sum(f1s) / len(f1s) if f1s else 0.0,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OOF-validate mined method/path signature rules on labeled training data.")
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--payload-column", default="payload_clean")
    parser.add_argument("--label-column", default="cve_labels")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260626)
    parser.add_argument("--min-support", type=int, default=50)
    parser.add_argument("--min-precision", type=float, default=1.0)
    parser.add_argument("--match-level", choices=["exact", "all"], default="exact")
    parser.add_argument("--max-additions", type=int, default=1)
    parser.add_argument("--output-folds", required=True, type=Path)
    parser.add_argument("--output-rules", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    frame = load_frames(args.input, args.payload_column, args.label_column)
    labels_list = [
        set(label for label in normalize_cve_labels(value) if label.startswith("CVE-"))
        for value in frame[args.label_column].fillna("")
    ]
    keys_list = [
        candidate_keys(*extract_method_path(str(payload)), match_level=args.match_level)
        for payload in frame[args.payload_column].fillna("").astype(str)
    ]

    indices = np.arange(len(frame))
    rng = np.random.default_rng(args.seed)
    rng.shuffle(indices)
    fold_ids = np.empty(len(frame), dtype=np.int32)
    for fold_no, fold_rows in enumerate(np.array_split(indices, args.folds)):
        fold_ids[fold_rows] = fold_no

    fold_rows_out: list[dict[str, float | int]] = []
    rule_rows: list[dict[str, str | int]] = []
    for fold_no in range(args.folds):
        train_rows = np.where(fold_ids != fold_no)[0]
        valid_rows = np.where(fold_ids == fold_no)[0]
        rules = mine_rules(
            keys_list,
            labels_list,
            train_rows,
            min_support=args.min_support,
            min_precision=args.min_precision,
        )
        metrics = evaluate_rules(keys_list, labels_list, valid_rows, rules, max_additions=args.max_additions)
        fold_rows_out.append({"fold": fold_no, **metrics})
        for signature, label in rules.items():
            rule_rows.append({"fold": fold_no, "signature": signature, "label": label})
        print(
            f"fold={fold_no} rules={len(rules)} changed={metrics['changed_rows']} "
            f"precision={metrics['precision']:.6f} recall={metrics['recall']:.6f} "
            f"micro_f1={metrics['micro_f1']:.6f}",
            flush=True,
        )

    args.output_folds.parent.mkdir(parents=True, exist_ok=True)
    args.output_rules.parent.mkdir(parents=True, exist_ok=True)
    folds = pd.DataFrame(fold_rows_out)
    folds.to_csv(args.output_folds, index=False)
    pd.DataFrame(rule_rows).to_csv(args.output_rules, index=False)
    metric_cols = ["precision", "recall", "micro_f1", "macro_f1"]
    print("\nMean metrics:")
    print(folds[metric_cols].mean().to_string(float_format=lambda value: f"{value:.6f}"))
    print(f"Wrote {args.output_folds}")
    print(f"Wrote {args.output_rules}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.preprocess import normalize_cve_labels


def label_set(value: object) -> set[str]:
    return set(normalize_cve_labels(value))


def evaluate(true_sets: list[set[str]], pred_sets: list[set[str]]) -> dict[str, float]:
    tp = fp = fn = exact = answered = 0
    per_label: dict[str, Counter[str]] = defaultdict(Counter)
    for expected, predicted in zip(true_sets, pred_sets):
        if predicted:
            answered += 1
        if expected == predicted:
            exact += 1
        tp += len(expected & predicted)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        for label in expected | predicted:
            bucket = per_label[label]
            if label in expected and label in predicted:
                bucket["tp"] += 1
            elif label in predicted:
                bucket["fp"] += 1
            else:
                bucket["fn"] += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    micro_f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    f1s: list[float] = []
    zero_f1 = 0
    for counts in per_label.values():
        label_precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
        label_recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
        f1 = 2 * label_precision * label_recall / (label_precision + label_recall) if label_precision + label_recall else 0.0
        if f1 == 0:
            zero_f1 += 1
        f1s.append(f1)
    return {
        "rows": float(len(true_sets)),
        "answer_rate": answered / len(true_sets) if true_sets else 0.0,
        "exact_match": exact / len(true_sets) if true_sets else 0.0,
        "precision": precision,
        "recall": recall,
        "micro_f1": micro_f1,
        "macro_f1": sum(f1s) / len(f1s) if f1s else 0.0,
        "zero_f1_labels": float(zero_f1),
    }


def per_label_f1(true_sets: list[set[str]], pred_sets: list[set[str]]) -> dict[str, float]:
    stats: dict[str, Counter[str]] = defaultdict(Counter)
    for expected, predicted in zip(true_sets, pred_sets):
        for label in expected & predicted:
            stats[label]["tp"] += 1
        for label in predicted - expected:
            stats[label]["fp"] += 1
        for label in expected - predicted:
            stats[label]["fn"] += 1
    out: dict[str, float] = {}
    for label, counts in stats.items():
        precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
        recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
        out[label] = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return out


def copy_high_confidence_labelset(
    base_pred: set[str],
    idxs: np.ndarray,
    sims: np.ndarray,
    train_labels: list[list[str]],
    *,
    threshold: float,
    max_labels: int,
    require_superset: bool,
) -> set[str]:
    if not len(idxs) or sims[0] < threshold:
        return set(base_pred)
    idx = int(idxs[0])
    if idx < 0 or idx >= len(train_labels):
        return set(base_pred)
    labels = [label for label in train_labels[idx] if label.startswith("CVE-")]
    if not labels or len(labels) > max_labels:
        return set(base_pred)
    labelset = set(labels)
    if require_superset and not set(base_pred).issubset(labelset):
        return set(base_pred)
    return labelset


def add_consensus_labels(
    base_pred: set[str],
    idxs: np.ndarray,
    sims: np.ndarray,
    train_labels: list[list[str]],
    *,
    threshold: float,
    min_votes: int,
    max_labels: int,
) -> set[str]:
    pred = set(base_pred)
    votes: Counter[str] = Counter()
    for idx, sim in zip(idxs, sims):
        if sim < threshold:
            continue
        idx_int = int(idx)
        if idx_int < 0 or idx_int >= len(train_labels):
            continue
        for label in train_labels[idx_int]:
            if label.startswith("CVE-"):
                votes[label] += 1
    for label, count in votes.most_common():
        if count < min_votes:
            continue
        pred.add(label)
        if len(pred) >= max_labels:
            break
    return pred


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Experiment with multi-label output rescue strategies from cached top-k search.")
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--pred", required=True, type=Path)
    parser.add_argument("--search", required=True, type=Path)
    parser.add_argument("--meta", required=True, type=Path)
    parser.add_argument("--id-column", default="id")
    parser.add_argument("--strategy", choices=["copy-top1", "consensus"], required=True)
    parser.add_argument("--thresholds", default="0.99")
    parser.add_argument("--min-votes", default="2")
    parser.add_argument("--max-labels", type=int, default=5)
    parser.add_argument("--require-superset", action="store_true")
    parser.add_argument("--output-summary", required=True, type=Path)
    parser.add_argument("--output-pred", type=Path, default=None)
    parser.add_argument("--output-label-delta", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    truth = pd.read_csv(args.truth)
    pred = pd.read_csv(args.pred)
    truth[args.id_column] = truth[args.id_column].astype(str)
    pred[args.id_column] = pred[args.id_column].astype(str)
    merged = truth[[args.id_column, "cve_labels"]].merge(
        pred[[args.id_column, "cve_labels"]],
        on=args.id_column,
        how="left",
        suffixes=("_true", "_pred"),
    )
    true_sets = [label_set(value) for value in merged["cve_labels_true"].fillna("")]
    base_sets = [label_set(value) for value in merged["cve_labels_pred"].fillna("")]

    search = np.load(args.search)
    distances = search["D"]
    indices = search["I"]
    if len(distances) != len(base_sets):
        raise ValueError("search rows do not match prediction rows")
    meta = json.loads(args.meta.read_text(encoding="utf-8"))
    train_labels = [normalize_cve_labels(value) for value in meta["cve_labels"]]

    base_metrics = evaluate(true_sets, base_sets)
    base_label_f1 = per_label_f1(true_sets, base_sets)
    rows: list[dict[str, float | int | str]] = []
    best_sets = base_sets
    best_score = base_metrics["micro_f1"]
    best_name = "baseline"

    thresholds = [float(item) for item in args.thresholds.split(",") if item.strip()]
    min_votes_values = [int(item) for item in args.min_votes.split(",") if item.strip()]
    for threshold in thresholds:
        vote_values = [0] if args.strategy == "copy-top1" else min_votes_values
        for min_votes in vote_values:
            pred_sets: list[set[str]] = []
            changed = 0
            for base_pred, idxs, sims in zip(base_sets, indices, distances):
                if args.strategy == "copy-top1":
                    new_pred = copy_high_confidence_labelset(
                        base_pred,
                        idxs,
                        sims,
                        train_labels,
                        threshold=threshold,
                        max_labels=args.max_labels,
                        require_superset=args.require_superset,
                    )
                else:
                    new_pred = add_consensus_labels(
                        base_pred,
                        idxs,
                        sims,
                        train_labels,
                        threshold=threshold,
                        min_votes=min_votes,
                        max_labels=args.max_labels,
                    )
                if new_pred != base_pred:
                    changed += 1
                pred_sets.append(new_pred)

            metrics = evaluate(true_sets, pred_sets)
            name = f"{args.strategy}:threshold={threshold}:min_votes={min_votes}"
            rows.append(
                {
                    "strategy": args.strategy,
                    "threshold": threshold,
                    "min_votes": min_votes,
                    "max_labels": args.max_labels,
                    "require_superset": args.require_superset,
                    "changed_rows": changed,
                    **metrics,
                    "delta_micro_f1": metrics["micro_f1"] - base_metrics["micro_f1"],
                    "delta_macro_f1": metrics["macro_f1"] - base_metrics["macro_f1"],
                }
            )
            if metrics["micro_f1"] > best_score:
                best_score = metrics["micro_f1"]
                best_sets = pred_sets
                best_name = name

    result = pd.DataFrame(rows).sort_values(["micro_f1", "macro_f1"], ascending=[False, False])
    args.output_summary.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output_summary, index=False)
    print(result.head(20).to_string(index=False, float_format=lambda value: f"{value:.6f}"))
    print(f"Best: {best_name}")

    if args.output_pred:
        args.output_pred.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(
            {
                args.id_column: merged[args.id_column],
                "cve_labels": [" ".join(sorted(labels)) for labels in best_sets],
            }
        ).to_csv(args.output_pred, index=False)

    if args.output_label_delta:
        new_label_f1 = per_label_f1(true_sets, best_sets)
        labels = sorted(set(base_label_f1) | set(new_label_f1))
        pd.DataFrame(
            [
                {
                    "label": label,
                    "base_f1": base_label_f1.get(label, 0.0),
                    "new_f1": new_label_f1.get(label, 0.0),
                    "delta_f1": new_label_f1.get(label, 0.0) - base_label_f1.get(label, 0.0),
                }
                for label in labels
            ]
        ).sort_values("delta_f1", ascending=False).to_csv(args.output_label_delta, index=False)


if __name__ == "__main__":
    main()

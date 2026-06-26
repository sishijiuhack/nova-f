from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

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


def candidate_keys(method: str, path: str) -> list[str]:
    if not method or not path:
        return []
    normalized = normalize_path(path)
    parts = [part for part in normalized.split("/") if part]
    keys = [f"{method} {normalized}"]
    if len(parts) >= 2:
        keys.append(f"{method} /{parts[0]}/{parts[1]}")
    if parts:
        keys.append(f"{method} /{parts[0]}")
    return keys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply mined high-precision path signature rules to predictions.")
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--truth-or-test", required=True, type=Path)
    parser.add_argument("--pred", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--changes-output", type=Path, default=None)
    parser.add_argument("--id-column", default="id")
    parser.add_argument("--payload-column", default="payload_decoded")
    parser.add_argument("--min-precision", type=float, default=0.99)
    parser.add_argument("--min-support", type=int, default=20)
    parser.add_argument("--only-empty", action="store_true")
    parser.add_argument("--max-additions", type=int, default=1)
    parser.add_argument("--match-level", choices=["exact", "all"], default="all")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rules = pd.read_csv(args.rules)
    required = {"signature", "label", "support", "precision"}
    missing = required - set(rules.columns)
    if missing:
        raise KeyError(f"rules missing columns: {', '.join(sorted(missing))}")
    rules = rules[
        (rules["precision"].astype(float) >= args.min_precision)
        & (rules["support"].astype(int) >= args.min_support)
    ].copy()
    rule_map = {str(row.signature): str(row.label) for row in rules.itertuples(index=False)}

    source = pd.read_csv(args.truth_or_test)
    pred = pd.read_csv(args.pred)
    source[args.id_column] = source[args.id_column].astype(str)
    pred[args.id_column] = pred[args.id_column].astype(str)
    merged = pred.merge(
        source[[args.id_column, args.payload_column]],
        on=args.id_column,
        how="left",
        validate="one_to_one",
    )

    rows: list[dict[str, str]] = []
    changes: list[dict[str, str]] = []
    for row in merged.itertuples(index=False):
        row_id = str(getattr(row, args.id_column))
        labels = normalize_cve_labels(getattr(row, "cve_labels"))
        payload = str(getattr(row, args.payload_column) or "")
        additions: list[str] = []
        if not args.only_empty or not labels:
            method, path = extract_method_path(payload)
            keys = candidate_keys(method, path)
            if args.match_level == "exact":
                keys = keys[:1]
            for key in keys:
                label = rule_map.get(key)
                if label and label not in labels and label not in additions:
                    additions.append(label)
                    if len(additions) >= args.max_additions:
                        break
        labels = sorted(labels + additions)
        rows.append({"id": row_id, "cve_labels": " ".join(labels)})
        if additions:
            changes.append(
                {
                    "id": row_id,
                    "added": " ".join(additions),
                    "labels": " ".join(labels),
                    "payload_clean": clean_payload_text(payload)[:300],
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.output, index=False)
    if args.changes_output:
        args.changes_output.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(changes).to_csv(args.changes_output, index=False)
    print(f"Loaded rules: {len(rule_map)}")
    print(f"Changed rows: {len(changes)}")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

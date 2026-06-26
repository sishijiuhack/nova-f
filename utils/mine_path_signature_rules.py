from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
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
    method = parts[0].upper()
    path = parts[1].split("?", 1)[0].lower()
    return method, path


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
    parser = argparse.ArgumentParser(description="Mine high-precision method/path signature rules from labeled CSVs.")
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--payload-column", default="payload_clean")
    parser.add_argument("--label-column", default="cve_labels")
    parser.add_argument("--min-support", type=int, default=5)
    parser.add_argument("--min-precision", type=float, default=0.95)
    parser.add_argument("--max-labels-per-key", type=int, default=1)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    key_counts: Counter[str] = Counter()
    key_label_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for path in args.input:
        frame = pd.read_csv(path)
        if args.payload_column not in frame.columns:
            raise KeyError(f"{path} missing {args.payload_column!r}")
        if args.label_column not in frame.columns:
            raise KeyError(f"{path} missing {args.label_column!r}")
        for payload, raw_labels in zip(frame[args.payload_column].fillna(""), frame[args.label_column].fillna("")):
            labels = [label for label in normalize_cve_labels(raw_labels) if label.startswith("CVE-")]
            if not labels:
                continue
            method, path_value = extract_method_path(str(payload))
            for key in candidate_keys(method, path_value):
                key_counts[key] += 1
                for label in labels:
                    key_label_counts[key][label] += 1

    rows: list[dict[str, float | int | str]] = []
    for key, total in key_counts.items():
        for label, count in key_label_counts[key].most_common(args.max_labels_per_key):
            precision = count / total if total else 0.0
            if count >= args.min_support and precision >= args.min_precision:
                rows.append(
                    {
                        "signature": key,
                        "label": label,
                        "support": count,
                        "total_hits": total,
                        "precision": precision,
                    }
                )

    result = pd.DataFrame(rows).sort_values(["support", "precision", "signature"], ascending=[False, False, True])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(result.head(50).to_string(index=False, float_format=lambda value: f"{value:.6f}"))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

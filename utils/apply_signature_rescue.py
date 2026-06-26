from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.preprocess import clean_payload_text, normalize_cve_labels


def labels_from_value(value: object) -> list[str]:
    return normalize_cve_labels(value)


def add_label(labels: list[str], label: str) -> bool:
    if label not in labels:
        labels.append(label)
        labels.sort()
        return True
    return False


def remove_label(labels: list[str], label: str) -> bool:
    if label in labels:
        labels.remove(label)
        return True
    return False


def apply_rules(payload: str, labels: list[str], *, enabled_rules: set[str], remove_conflicts: bool) -> tuple[list[str], list[str]]:
    text = clean_payload_text(payload).lower()
    changed: list[str] = []

    if "wsman-38649" in enabled_rules and "/wsman" in text and {"CVE-2021-38645", "CVE-2021-38647", "CVE-2021-38648"}.issubset(labels):
        if add_label(labels, "CVE-2021-38649"):
            changed.append("add:CVE-2021-38649")

    if "fortinet-13379" in enabled_rules and "/remote/fgt_lang" in text and ("../" in text or "%2e%2e" in text):
        if add_label(labels, "CVE-2018-13379"):
            changed.append("add:CVE-2018-13379")

    if "hikvision-7921" in enabled_rules and "/onvif-http/snapshot" in text:
        if add_label(labels, "CVE-2017-7921"):
            changed.append("add:CVE-2017-7921")

    if "sonicwall-20016" in enabled_rules and "/__api__/v1/logon/" in text and "/authenticate" in text:
        if add_label(labels, "CVE-2021-20016"):
            changed.append("add:CVE-2021-20016")

    if "spip-27372" in enabled_rules and ("/spip.php" in text or "/spip.ph%70" in text) and "spip_pass" in text:
        if add_label(labels, "CVE-2023-27372"):
            changed.append("add:CVE-2023-27372")
        if remove_conflicts and remove_label(labels, "CVE-2024-8517"):
            changed.append("remove:CVE-2024-8517")

    return labels, changed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply explicit payload-signature recall rules to prediction CSV.")
    parser.add_argument("--truth-or-test", required=True, type=Path, help="CSV containing id and payload column")
    parser.add_argument("--pred", required=True, type=Path, help="Prediction CSV containing id and cve_labels")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--changes-output", type=Path, default=None)
    parser.add_argument("--id-column", default="id")
    parser.add_argument("--payload-column", default="payload_decoded")
    parser.add_argument(
        "--rules",
        default="all",
        help="Comma-separated rules or 'all': wsman-38649,fortinet-13379,hikvision-7921,sonicwall-20016,spip-27372",
    )
    parser.add_argument("--remove-conflicts", action="store_true", help="Remove known conflicting labels for signatures")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = pd.read_csv(args.truth_or_test)
    pred = pd.read_csv(args.pred)
    if args.id_column not in source.columns or args.id_column not in pred.columns:
        raise KeyError(f"both CSVs must contain {args.id_column!r}")
    if args.payload_column not in source.columns:
        raise KeyError(f"source CSV must contain {args.payload_column!r}")
    if "cve_labels" not in pred.columns:
        raise KeyError("prediction CSV must contain 'cve_labels'")

    source[args.id_column] = source[args.id_column].astype(str)
    pred[args.id_column] = pred[args.id_column].astype(str)
    merged = pred.merge(
        source[[args.id_column, args.payload_column]],
        on=args.id_column,
        how="left",
        validate="one_to_one",
    )
    all_rules = {"wsman-38649", "fortinet-13379", "hikvision-7921", "sonicwall-20016", "spip-27372"}
    if args.rules.strip().lower() == "all":
        enabled_rules = all_rules
    else:
        enabled_rules = {rule.strip() for rule in args.rules.split(",") if rule.strip()}
        unknown = enabled_rules - all_rules
        if unknown:
            raise ValueError(f"unknown rules: {', '.join(sorted(unknown))}")

    rows: list[dict[str, str]] = []
    change_rows: list[dict[str, str]] = []
    for row in merged.itertuples(index=False):
        row_id = str(getattr(row, args.id_column))
        payload = str(getattr(row, args.payload_column) or "")
        labels = labels_from_value(getattr(row, "cve_labels"))
        new_labels, changes = apply_rules(payload, labels, enabled_rules=enabled_rules, remove_conflicts=args.remove_conflicts)
        rows.append({"id": row_id, "cve_labels": " ".join(new_labels)})
        if changes:
            change_rows.append(
                {
                    "id": row_id,
                    "changes": " ".join(changes),
                    "labels": " ".join(new_labels),
                    "payload_clean": clean_payload_text(payload)[:300],
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.output, index=False)
    if args.changes_output:
        args.changes_output.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(change_rows).to_csv(args.changes_output, index=False)
    print(f"Wrote {args.output}")
    print(f"Changed rows: {len(change_rows)}")


if __name__ == "__main__":
    main()

# What: checks three rules that the schema and the contributor docs already state
#       about every record, and that no CI step enforced: severity agrees with
#       aivss.aivss_score; aivss.aivss_severity, when present, is the band of
#       aivss.aivss_score; and the required text fields are not blank.
# Why:  each rule is written down -- the schema's descriptions of severity
#       ("Must agree with aivss.aivss_score") and of aivss_severity ("derived from
#       aivss_score"), and the PR template's "present and non-empty" -- yet a record
#       breaking any one of them on its own still passed every blocking step of
#       tests.yml. Every record in records/ met all three when this check was added,
#       so it fails rather than warns.
# How:  one plain function per rule over the parsed record; main() runs them over
#       records/AVE-*.json, the files validate_records.py reads, and exits 1 on any
#       finding. Presence, types, enums, patterns and formats stay with the schema:
#       a value the schema already refuses is not reported a second time here.
import json
import sys
from pathlib import Path

RECORDS_DIR = Path("records")

# README, "Adding a new AVE record", Step 2:
# "Severity: CRITICAL >= 9.0 · HIGH >= 7.0 · MEDIUM >= 4.0 · LOW < 4.0"
BANDS = (("CRITICAL", 9.0), ("HIGH", 7.0), ("MEDIUM", 4.0))
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# The required text fields the schema leaves unconstrained (no minLength, pattern,
# enum or format). Every record, drafts included, must carry these...
CORE_TEXT_FIELDS = ("schema_version", "title", "description", "attack_class",
                    "behavioral_fingerprint")
# ...and these as well once status is active or deprecated.
FULL_TEXT_FIELDS = CORE_TEXT_FIELDS + ("remediation", "researcher")


def band(score: float) -> str:
    for name, floor in BANDS:
        if score >= floor:
            return name
    return "LOW"


def stated_score(record: dict) -> float | None:
    """aivss.aivss_score when it is a number; None otherwise, since a missing or
    mistyped score is the schema's finding, not this script's."""
    aivss = record.get("aivss")
    score = aivss.get("aivss_score") if isinstance(aivss, dict) else None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    return score


def check_severity_matches_score(record: dict) -> list[str]:
    severity = record.get("severity")
    score = stated_score(record)
    if severity not in SEVERITIES or score is None or severity == band(score):
        return []
    return [f"severity is {severity}, but aivss.aivss_score {score} is in the {band(score)} band"]


def check_aivss_severity_is_derived(record: dict) -> list[str]:
    aivss = record.get("aivss")
    stated = aivss.get("aivss_severity") if isinstance(aivss, dict) else None
    score = stated_score(record)
    if stated not in SEVERITIES or score is None or stated == band(score):
        return []
    return [f"aivss.aivss_severity is {stated}, but aivss.aivss_score {score} is in the {band(score)} band"]


def check_required_text_not_blank(record: dict) -> list[str]:
    fields = CORE_TEXT_FIELDS if record.get("status") == "draft" else FULL_TEXT_FIELDS
    return [f"required field {field} is blank" for field in fields
            if isinstance(record.get(field), str) and not record[field].strip()]


def check_record(record: dict) -> list[str]:
    return (check_severity_matches_score(record)
            + check_aivss_severity_is_derived(record)
            + check_required_text_not_blank(record))


def main() -> int:
    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    if not paths:
        print(f"No records found under {RECORDS_DIR}/", file=sys.stderr)
        return 1

    findings = []
    for path in paths:
        record = json.loads(path.read_text(encoding="utf-8"))
        findings += [f"{record.get('ave_id', path.name)}: {problem}" for problem in check_record(record)]

    for finding in findings:
        print(finding)
    if findings:
        print(f"\n{len(findings)} finding(s) across {len(paths)} records.", file=sys.stderr)
        return 1
    print(f"All {len(paths)} records follow the three stated rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

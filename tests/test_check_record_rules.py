"""scripts/check_record_rules.py: three rules the schema and the contributor docs
state about every record, each of which a record could break on its own and still
pass every blocking step of tests.yml.

The shipped-corpus test at the top is what CI runs against; the rest drive each
rule on a fixture record, with the exact message expected, so a check that
stopped refusing would turn a test red rather than pass quietly.
"""
import json

import pytest

from scripts import check_record_rules as rules


def record(**overrides):
    """An active record carrying the fields the three rules read, valid for all of
    them, so that a refusal below can only come from the override."""
    base = {
        "ave_id": "AVE-2026-99999",
        "schema_version": "1.1.0",
        "status": "active",
        "published": "2026-10-18T00:00:00Z",
        "title": "Fixture record",
        "description": "A fixture record for the stated-rules check.",
        "attack_class": "test",
        "severity": "HIGH",
        "behavioral_fingerprint": "Component does something the fixture describes.",
        "aivss": {"aivss_score": 8.0, "aivss_severity": "HIGH"},
        "owasp_mcp": ["MCP01"],
        "indicators_of_compromise": ["fixture indicator"],
        "remediation": "Fixture remediation.",
        "references": [{"tag": "Source", "text": "Source", "url": "https://example.com"}],
        "researcher": "Fixture Researcher",
    }
    base.update(overrides)
    return base


# --- the shipped corpus -------------------------------------------------------


def test_every_shipped_record_follows_the_three_rules():
    paths = sorted(rules.RECORDS_DIR.glob("AVE-*.json"))
    findings = [f"{path.name}: {problem}" for path in paths
                for problem in rules.check_record(json.loads(path.read_text(encoding="utf-8")))]

    assert paths, "no records found to check"
    assert findings == []


def test_the_fixture_record_follows_every_rule():
    """The negative control for every refusal below."""
    assert rules.check_record(record()) == []


# --- severity and aivss.aivss_severity against the score ----------------------


@pytest.mark.parametrize("score,expected", [
    (10, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
    (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0, "LOW"),
])
def test_band_edges_follow_the_readme(score, expected):
    assert rules.band(score) == expected


@pytest.mark.parametrize("score,severity", [(9.0, "CRITICAL"), (7.0, "HIGH"), (6.9, "MEDIUM"), (3.9, "LOW")])
def test_a_severity_on_its_band_edge_passes(score, severity):
    assert rules.check_record(record(severity=severity,
                                     aivss={"aivss_score": score, "aivss_severity": severity})) == []


def test_a_severity_outside_its_score_band_is_reported():
    assert rules.check_severity_matches_score(record(severity="LOW")) == [
        "severity is LOW, but aivss.aivss_score 8.0 is in the HIGH band"]


def test_an_integer_score_is_read_like_a_decimal_one():
    """Shipped records carry whole-number scores (AVE-2026-00001 states 8)."""
    assert rules.check_severity_matches_score(record(severity="MEDIUM", aivss={"aivss_score": 8})) == [
        "severity is MEDIUM, but aivss.aivss_score 8 is in the HIGH band"]


def test_an_aivss_severity_not_derived_from_the_score_is_reported():
    assert rules.check_aivss_severity_is_derived(
        record(aivss={"aivss_score": 8.0, "aivss_severity": "MEDIUM"})) == [
        "aivss.aivss_severity is MEDIUM, but aivss.aivss_score 8.0 is in the HIGH band"]


def test_an_absent_aivss_severity_is_not_reported():
    """The field is optional; a record that omits it has said nothing false."""
    assert rules.check_aivss_severity_is_derived(record(aivss={"aivss_score": 8.0})) == []


@pytest.mark.parametrize("aivss", [
    {"aivss_severity": "CRITICAL"},
    {"aivss_score": "8.0", "aivss_severity": "CRITICAL"},
    {"aivss_score": True, "aivss_severity": "CRITICAL"},
    "8.0",
])
def test_a_missing_or_mistyped_score_is_left_to_the_schema(aivss):
    """No band can be read from it; the schema already reports it. Both severities
    are CRITICAL so that a score read anyway (True reads as 1, LOW) would be
    reported, and a missing one would raise: dropping either guard turns this red."""
    broken = record(severity="CRITICAL", aivss=aivss)
    assert rules.check_severity_matches_score(broken) == []
    assert rules.check_aivss_severity_is_derived(broken) == []


@pytest.mark.parametrize("overrides", [
    {"severity": "high"},
    {"severity": ""},
    {"aivss": {"aivss_score": 8.0, "aivss_severity": "high"}},
    {"ave_id": ""},
    {"status": ""},
    {"published": ""},
])
def test_a_value_the_schema_already_refuses_is_not_reported_again(overrides):
    """An off-enum severity, or a blank ave_id, status or published, already fails
    the schema's enum, pattern or format; reporting it here would say it twice."""
    assert rules.check_record(record(**overrides)) == []


# --- required text --------------------------------------------------------------


@pytest.mark.parametrize("field", ["schema_version", "title", "description", "attack_class",
                                   "behavioral_fingerprint", "remediation", "researcher"])
@pytest.mark.parametrize("blank", ["", "   ", "\n"])
def test_a_blank_required_text_field_is_reported(field, blank):
    assert rules.check_required_text_not_blank(record(**{field: blank})) == [
        f"required field {field} is blank"]


def test_a_draft_needs_only_its_core_text():
    """README: a draft needs only the eight-field core; the rest of the fifteen
    apply once status is active or deprecated."""
    draft = record(status="draft", researcher="", remediation="")
    assert rules.check_required_text_not_blank(draft) == []
    assert rules.check_required_text_not_blank(dict(draft, title=" ")) == [
        "required field title is blank"]


def test_a_deprecated_record_is_held_like_an_active_one():
    assert rules.check_required_text_not_blank(record(status="deprecated", researcher="")) == [
        "required field researcher is blank"]


def test_an_absent_field_is_left_to_the_schema():
    """Presence is the schema's rule; this check reports what it lets through."""
    absent = record()
    del absent["researcher"]
    assert rules.check_required_text_not_blank(absent) == []


# --- the wiring: main() over a directory ------------------------------------------


def write_records(directory, records):
    for name, content in records.items():
        (directory / name).write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")


def test_main_fails_on_a_record_that_breaks_a_rule(tmp_path, monkeypatch, capsys):
    """Asserts the wiring, not the functions: with check_severity_matches_score
    dropped from check_record(), every test above would still pass and this one
    would not. The next test does the same for the other two rules."""
    write_records(tmp_path, {"AVE-2026-99999.json": record(severity="LOW")})
    monkeypatch.setattr(rules, "RECORDS_DIR", tmp_path)

    assert rules.main() == 1
    assert "AVE-2026-99999: severity is LOW, but aivss.aivss_score 8.0 is in the HIGH band" in capsys.readouterr().out


def test_main_reports_every_finding_of_every_record(tmp_path, monkeypatch, capsys):
    write_records(tmp_path, {
        "AVE-2026-99998.json": record(ave_id="AVE-2026-99998", researcher=" "),
        "AVE-2026-99999.json": record(aivss={"aivss_score": 8.0, "aivss_severity": "LOW"}),
    })
    monkeypatch.setattr(rules, "RECORDS_DIR", tmp_path)

    assert rules.main() == 1
    assert capsys.readouterr().out.splitlines() == [
        "AVE-2026-99998: required field researcher is blank",
        "AVE-2026-99999: aivss.aivss_severity is LOW, but aivss.aivss_score 8.0 is in the HIGH band",
    ]


def test_main_passes_the_same_record_unbroken(tmp_path, monkeypatch):
    """The negative control for the two tests above."""
    write_records(tmp_path, {"AVE-2026-99999.json": record()})
    monkeypatch.setattr(rules, "RECORDS_DIR", tmp_path)

    assert rules.main() == 0

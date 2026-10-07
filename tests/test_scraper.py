from pathlib import Path

import yaml

from scraper.attack_scraper import AttackScraper, records_to_yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "minimal_attack_stix.json"


def test_parse_stix_fixture():
    bundle = AttackScraper.load_stix(FIXTURE)
    records = AttackScraper.parse(bundle)
    assert len(records) == 1
    row = records[0]
    assert row.technique_id == "T1059.001"
    assert row.strategy_id == "DET0455"
    assert row.analytic_id == "AN1252"
    assert row.log_source == "WinEventLog:PowerShell"
    assert row.channel == "EventCode=4104"


def test_records_to_yaml_mapping_and_unknown_source():
    records = AttackScraper.parse(AttackScraper.load_stix(FIXTURE))
    rows, unknown = records_to_yaml(records, {"WinEventLog:PowerShell": "powershell_scriptblock"})
    assert not unknown
    assert rows[0]["sources"][0]["id"] == "powershell_scriptblock"
    assert rows[0]["sources"][0]["role"] == "primary"


def test_unknown_sources_are_reported():
    records = AttackScraper.parse(AttackScraper.load_stix(FIXTURE))
    rows, unknown = records_to_yaml(records, {})
    assert rows[0]["sources"] == []
    assert unknown[0]["raw_log_source"] == "WinEventLog:PowerShell"

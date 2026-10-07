from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "19.2"
DEFAULT_DOMAIN = "enterprise-attack"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-{version}.json"
)
DEFAULT_OUTPUT = ROOT / "data" / "generated" / "techniques_scraped.yml"
DEFAULT_RAW_OUTPUT = ROOT / "data" / "generated" / "telemetry_records.json"
DEFAULT_REPORT_OUTPUT = ROOT / "data" / "generated" / "scrape_report.json"
DEFAULT_SOURCE_MAPPING = ROOT / "data" / "source_mapping.yml"
DEFAULT_SOURCE_CATALOG = ROOT / "data" / "sources.yml"
DEFAULT_TECHNIQUES = ROOT / "data" / "techniques.yml"


def _slug(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "unknown"


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _mitre_url(obj: dict[str, Any], fallback_kind: str, external_id: str | None, anchor: str | None = None) -> str:
    if external_id:
        if fallback_kind == "technique":
            return f"https://attack.mitre.org/techniques/{external_id}/"
        if fallback_kind == "strategy":
            return f"https://attack.mitre.org/detectionstrategies/{external_id}/"
        if fallback_kind == "analytic":
            base = f"https://attack.mitre.org/detectionstrategies/{anchor or external_id}/"
            return f"{base}#{external_id}" if anchor else base
        if fallback_kind == "data-component":
            return f"https://attack.mitre.org/datacomponents/{external_id}/"
    return "https://attack.mitre.org/"


@dataclass(frozen=True)
class TelemetryRecord:
    technique_id: str
    technique_name: str
    tactic: str
    strategy_id: str
    strategy_name: str
    analytic_id: str
    analytic_name: str
    data_component_id: str
    data_component_name: str
    log_source: str
    channel: str
    platform: str
    evidence: str


class AttackScraper:
    def __init__(self, version: str = DEFAULT_VERSION, domain: str = DEFAULT_DOMAIN):
        if domain != DEFAULT_DOMAIN:
            raise ValueError("This MVP scraper currently supports enterprise-attack only")
        self.version = version
        self.domain = domain

    @property
    def url(self) -> str:
        return DEFAULT_URL.format(version=self.version)

    def download(self, destination: Path | None = None, timeout: int = 60) -> Path:
        destination = destination or ROOT / "data" / "generated" / f"{self.domain}-{self.version}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(
            self.url,
            headers={"User-Agent": "attack-telemetry-planner/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read()
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Could not download ATT&CK STIX data from {self.url}: {exc}. "
                "Check internet access or use --stix-file."
            ) from exc
        destination.write_bytes(data)
        return destination

    @staticmethod
    def load_stix(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
            raise ValueError("Not a valid STIX bundle: expected an 'objects' list")
        return bundle

    @staticmethod
    def _active(obj: dict[str, Any]) -> bool:
        return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)

    @staticmethod
    def parse(bundle: dict[str, Any]) -> list[TelemetryRecord]:
        objects = [o for o in bundle["objects"] if isinstance(o, dict) and AttackScraper._active(o)]
        by_id = {o.get("id"): o for o in objects if o.get("id")}
        techniques = {
            o["id"]: o for o in objects if o.get("type") == "attack-pattern"
            and "enterprise-attack" in o.get("x_mitre_domains", ["enterprise-attack"])
        }
        strategies = {
            o["id"]: o for o in objects if o.get("type") == "x-mitre-detection-strategy"
            and "enterprise-attack" in o.get("x_mitre_domains", ["enterprise-attack"])
        }
        analytics = {
            o["id"]: o for o in objects if o.get("type") == "x-mitre-analytic"
            and "enterprise-attack" in o.get("x_mitre_domains", ["enterprise-attack"])
        }
        data_components = {
            o["id"]: o for o in objects if o.get("type") == "x-mitre-data-component"
            and "enterprise-attack" in o.get("x_mitre_domains", ["enterprise-attack"])
        }

        strategy_to_techniques: dict[str, set[str]] = defaultdict(set)
        for rel in objects:
            if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
                continue
            source = rel.get("source_ref")
            target = rel.get("target_ref")
            if source in strategies and target in techniques:
                strategy_to_techniques[source].add(target)

        records: list[TelemetryRecord] = []
        for strategy_id, strategy in strategies.items():
            tech_ids = strategy_to_techniques.get(strategy_id, set())
            analytic_ids = strategy.get("x_mitre_analytic_refs", [])
            for analytic_id in analytic_ids:
                analytic = analytics.get(analytic_id)
                if not analytic:
                    continue
                refs = analytic.get("x_mitre_log_source_references", []) or []
                platforms = analytic.get("x_mitre_platforms", []) or []
                for ref in refs:
                    dc_id = ref.get("x_mitre_data_component_ref", "")
                    dc = data_components.get(dc_id, {})
                    external_analytic = _external_id(analytic) or analytic_id
                    external_strategy = _external_id(strategy) or strategy_id
                    evidence = _mitre_url(analytic, "analytic", external_analytic, anchor=external_strategy)
                    # The current ATT&CK model puts the exact log source on the analytic reference.
                    # Data Components additionally retain log-source metadata in x_mitre_log_sources.
                    log_source = str(ref.get("name", "")).strip()
                    channel = str(ref.get("channel", "")).strip()
                    if not log_source:
                        for item in dc.get("x_mitre_log_sources", []) or []:
                            if item.get("name"):
                                log_source = str(item["name"]).strip()
                                channel = channel or str(item.get("channel", "")).strip()
                                break
                    dc_external = _external_id(dc) or dc_id
                    if not log_source:
                        continue
                    for tech_id in tech_ids:
                        tech = techniques[tech_id]
                        tech_external = _external_id(tech) or tech_id
                        platforms_text = ", ".join(platforms) if platforms else "Any"
                        records.append(
                            TelemetryRecord(
                                technique_id=tech_external,
                                technique_name=tech.get("name", tech_external),
                                tactic=_extract_tactic(tech),
                                strategy_id=_external_id(strategy) or strategy_id,
                                strategy_name=strategy.get("name", strategy_id),
                                analytic_id=external_analytic,
                                analytic_name=analytic.get("name", external_analytic),
                                data_component_id=dc_external,
                                data_component_name=dc.get("name", dc_external),
                                log_source=log_source,
                                channel=channel,
                                platform=platforms_text,
                                evidence=evidence,
                            )
                        )
        return _dedupe_records(records)


def _extract_tactic(technique: dict[str, Any]) -> str:
    # ATT&CK attack-pattern objects generally expose kill-chain phases, with Enterprise
    # tactic names under kill_chain_phases[]. This is deliberately best-effort.
    phases = technique.get("kill_chain_phases", []) or []
    tactics = [
        p.get("phase_name", "").replace("-", " ").title()
        for p in phases
        if p.get("kill_chain_name") in {"mitre-attack", "mitre-enterprise-attack"}
        and p.get("phase_name")
    ]
    return tactics[0] if tactics else "Unknown"


def _dedupe_records(records: list[TelemetryRecord]) -> list[TelemetryRecord]:
    seen: set[tuple[str, str, str, str, str]] = set()
    result: list[TelemetryRecord] = []
    for record in records:
        key = (
            record.technique_id,
            record.strategy_id,
            record.analytic_id,
            record.data_component_id,
            record.log_source,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return sorted(result, key=lambda r: (r.technique_id, r.analytic_id, r.log_source, r.channel))


def load_mapping(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return dict(raw.get("log_source_to_source_id", {}))


def load_source_ids(path: Path) -> set[str]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return {item["id"] for item in raw}


def records_to_yaml(
    records: list[TelemetryRecord],
    source_mapping: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[str, dict[str, Any]] = {}
    unknown: dict[str, dict[str, Any]] = {}
    for r in records:
        technique = grouped.setdefault(
            r.technique_id,
            {
                "id": r.technique_id,
                "name": r.technique_name,
                "tactic": r.tactic,
                "sources": [],
            },
        )
        source_id = source_mapping.get(r.log_source)
        if not source_id:
            key = _slug(r.log_source)
            unknown.setdefault(
                key,
                {
                    "suggested_id": f"attck_{key}",
                    "name": r.log_source,
                    "raw_log_source": r.log_source,
                    "examples": [],
                },
            )
            if len(unknown[key]["examples"]) < 5:
                unknown[key]["examples"].append(
                    {
                        "technique": r.technique_id,
                        "analytic": r.analytic_id,
                        "channel": r.channel,
                    }
                )
            continue
        ref_key = (source_id, r.analytic_id, r.data_component_id, r.channel)
        if any(
            (x["id"], x.get("analytic_id"), x.get("data_component_id"), x.get("channel")) == ref_key
            for x in technique["sources"]
        ):
            continue
        technique["sources"].append(
            {
                "id": source_id,
                "role": "primary",
                "why": (
                    f"ATT&CK analytic {r.analytic_id} uses {r.log_source} "
                    f"for {r.data_component_name}. Channel: {r.channel or 'n/a'}"
                ),
                "evidence": r.evidence,
                "analytic_id": r.analytic_id,
                "data_component_id": r.data_component_id,
                "raw_log_source": r.log_source,
                "channel": r.channel,
            }
        )
    # Keep the source shape compatible with the planner loader while retaining
    # extra evidence fields for humans and future tooling.
    for tech in grouped.values():
        for source in tech["sources"]:
            source.setdefault("role_basis", "attack_analytics")
    return list(grouped.values()), list(unknown.values())


def write_yaml(path: Path, rows: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"metadata": metadata, "techniques": rows}
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")


def apply_to_planner(scraped_path: Path, techniques_path: Path = DEFAULT_TECHNIQUES, source_catalog_path: Path = DEFAULT_SOURCE_CATALOG) -> None:
    raw = yaml.safe_load(scraped_path.read_text(encoding="utf-8")) or {}
    rows = raw.get("techniques", raw if isinstance(raw, list) else [])
    source_ids = load_source_ids(source_catalog_path)
    filtered: list[dict[str, Any]] = []
    for row in rows:
        sources = [s for s in row.get("sources", []) if s.get("id") in source_ids]
        if not sources:
            continue
        clean_sources = []
        for source in sources:
            clean_sources.append({k: v for k, v in source.items() if k in {"id", "role", "why", "evidence"}})
        filtered.append(
            {
                "id": row["id"],
                "name": row["name"],
                "tactic": row.get("tactic", "Unknown"),
                "sources": clean_sources,
            }
        )
    techniques_path.with_suffix(techniques_path.suffix + ".bak").write_text(
        techniques_path.read_text(encoding="utf-8"), encoding="utf-8"
    )
    techniques_path.write_text(yaml.safe_dump(filtered, sort_keys=False, allow_unicode=True), encoding="utf-8")


def run(
    version: str = DEFAULT_VERSION,
    stix_file: Path | None = None,
    output: Path = DEFAULT_OUTPUT,
    raw_output: Path = DEFAULT_RAW_OUTPUT,
    report_output: Path = DEFAULT_REPORT_OUTPUT,
    mapping_file: Path = DEFAULT_SOURCE_MAPPING,
    apply: bool = False,
    selected_techniques: set[str] | None = None,
) -> dict[str, Any]:
    scraper = AttackScraper(version=version)
    stix_file = stix_file or scraper.download()
    bundle = scraper.load_stix(stix_file)
    records = scraper.parse(bundle)
    if selected_techniques:
        records = [r for r in records if r.technique_id in selected_techniques]
    mapping = load_mapping(mapping_file)
    rows, unknown = records_to_yaml(records, mapping)
    metadata = {
        "attack_version": version,
        "domain": DEFAULT_DOMAIN,
        "source_url": scraper.url,
        "record_count": len(records),
        "technique_count": len(rows),
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "role_basis": "attack_analytics",
        "note": "Primary means directly referenced by an ATT&CK analytic; supporting is not inferred by this scraper.",
    }
    write_yaml(output, rows, metadata)
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    raw_output.write_text(
        json.dumps([asdict(r) for r in records], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report = {
        **metadata,
        "unknown_log_sources": unknown,
        "unknown_log_source_count": len(unknown),
        "output": str(output),
        "raw_output": str(raw_output),
    }
    report_output.parent.mkdir(parents=True, exist_ok=True)
    report_output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if apply:
        apply_to_planner(output, DEFAULT_TECHNIQUES, DEFAULT_SOURCE_CATALOG)
        report["applied_to"] = str(DEFAULT_TECHNIQUES)
        report["backup"] = str(DEFAULT_TECHNIQUES.with_suffix(DEFAULT_TECHNIQUES.suffix + ".bak"))
    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Extract ATT&CK technique-to-telemetry mappings from STIX")
    p.add_argument("--version", default=DEFAULT_VERSION, help="ATT&CK Enterprise version, e.g. 19.2")
    p.add_argument("--stix-file", type=Path, help="Use a local STIX JSON bundle instead of downloading")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--raw-output", type=Path, default=DEFAULT_RAW_OUTPUT)
    p.add_argument("--report-output", type=Path, default=DEFAULT_REPORT_OUTPUT)
    p.add_argument("--mapping-file", type=Path, default=DEFAULT_SOURCE_MAPPING)
    p.add_argument("--techniques", help="Comma-separated ATT&CK IDs to keep, e.g. T1059.001,T1110")
    p.add_argument("--apply", action="store_true", help="Replace data/techniques.yml with mapped scraped techniques (creates .bak)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    selected = {x.strip() for x in args.techniques.split(",") if x.strip()} if args.techniques else None
    try:
        report = run(
            version=args.version,
            stix_file=args.stix_file,
            output=args.output,
            raw_output=args.raw_output,
            report_output=args.report_output,
            mapping_file=args.mapping_file,
            apply=args.apply,
            selected_techniques=selected,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"ATT&CK v{report['attack_version']} parsed successfully")
    print(f"Telemetry records: {report['record_count']}")
    print(f"Techniques: {report['technique_count']}")
    print(f"Unknown log sources: {report['unknown_log_source_count']}")
    print(f"YAML: {report['output']}")
    print(f"Raw JSON: {report['raw_output']}")
    print(f"Report: {args.report_output}")
    if args.apply:
        print(f"Planner KB updated: {report['applied_to']}")
        print(f"Backup: {report['backup']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

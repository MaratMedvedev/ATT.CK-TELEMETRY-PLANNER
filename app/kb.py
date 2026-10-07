from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Environment, Source, Technique, TechniqueSource

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_sources(path: Path | None = None) -> dict[str, Source]:
    path = path or DATA_DIR / "sources.yml"
    raw = _load_yaml(path) or []
    result: dict[str, Source] = {}
    for item in raw:
        source = Source(
            id=item["id"],
            name=item["name"],
            category=item.get("category", "Other"),
            cost=int(item["cost"]),
            description=item.get("description", ""),
        )
        if source.id in result:
            raise ValueError(f"Duplicate source id: {source.id}")
        if source.cost < 1:
            raise ValueError(f"Source cost must be >= 1: {source.id}")
        result[source.id] = source
    return result


def load_techniques(
    path: Path | None = None,
    sources: dict[str, Source] | None = None,
) -> dict[str, Technique]:
    path = path or DATA_DIR / "techniques.yml"
    sources = sources or load_sources()
    raw = _load_yaml(path) or []
    result: dict[str, Technique] = {}
    for item in raw:
        refs: list[TechniqueSource] = []
        if not item.get("sources"):
            raise ValueError(f"Technique has no sources: {item['id']}")
        for ref in item["sources"]:
            if ref["id"] not in sources:
                raise ValueError(
                    f"Unknown source id {ref['id']} in technique {item['id']}"
                )
            if ref["role"] not in {"primary", "supporting"}:
                raise ValueError(f"Invalid role {ref['role']} in {item['id']}")
            refs.append(
                TechniqueSource(
                    source_id=ref["id"],
                    role=ref["role"],
                    why=ref.get("why", ""),
                    evidence=ref.get("evidence", ""),
                )
            )
        technique = Technique(
            id=item["id"],
            name=item["name"],
            tactic=item.get("tactic", "Unknown"),
            sources=tuple(refs),
        )
        if technique.id in result:
            raise ValueError(f"Duplicate technique id: {technique.id}")
        result[technique.id] = technique
    return result


def load_environments(path: Path | None = None) -> dict[str, Environment]:
    path = path or DATA_DIR / "environments"
    result: dict[str, Environment] = {}
    for file in sorted(path.glob("*.yml")):
        raw = _load_yaml(file)
        env = Environment(
            id=raw["id"],
            name=raw["name"],
            enabled_sources=tuple(raw.get("enabled_sources", [])),
            description=raw.get("description", ""),
        )
        result[env.id] = env
    return result


def validate_knowledge_base(
    sources: dict[str, Source] | None = None,
    techniques: dict[str, Technique] | None = None,
    environments: dict[str, Environment] | None = None,
) -> list[str]:
    sources = sources or load_sources()
    techniques = techniques or load_techniques(sources=sources)
    environments = environments or load_environments()
    errors: list[str] = []

    for technique in techniques.values():
        for ref in technique.sources:
            if ref.source_id not in sources:
                errors.append(
                    f"Technique {technique.id} references unknown source {ref.source_id}"
                )
        if not any(r.role == "primary" for r in technique.sources):
            errors.append(f"Technique {technique.id} has no primary source")
        for ref in technique.sources:
            if not ref.evidence.startswith("http"):
                errors.append(
                    f"Technique {technique.id}/{ref.source_id} has invalid evidence URL"
                )

    for env in environments.values():
        for source_id in env.enabled_sources:
            if source_id not in sources:
                errors.append(
                    f"Environment {env.id} references unknown source {source_id}"
                )

    # Guard against a completely useless source catalog entry.
    referenced = {r.source_id for t in techniques.values() for r in t.sources}
    for source_id in sources:
        if source_id not in referenced:
            errors.append(f"Source {source_id} is not referenced by any technique")

    return errors

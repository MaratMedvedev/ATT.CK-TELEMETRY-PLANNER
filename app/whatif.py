from __future__ import annotations

from .coverage import coverage
from .models import Scenario, Source, Technique


def make_scenario(
    name: str,
    techniques: list[Technique],
    sources: dict[str, Source],
    enabled: set[str],
) -> Scenario:
    return Scenario(
        name=name,
        sources=tuple(sorted(enabled)),
        coverage=coverage(techniques, enabled),
        cost=sum(sources[s].cost for s in enabled),
    )


def compare_scenarios(
    techniques: list[Technique],
    sources: dict[str, Source],
    base: set[str],
    additions: dict[str, set[str]],
) -> list[Scenario]:
    scenarios = [make_scenario("Current", techniques, sources, base)]
    for name, extra in additions.items():
        scenarios.append(
            make_scenario(name, techniques, sources, base | set(extra))
        )
    return scenarios

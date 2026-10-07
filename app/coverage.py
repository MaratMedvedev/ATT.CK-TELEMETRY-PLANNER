from __future__ import annotations

from collections.abc import Iterable

from .models import Technique

PRIMARY_WEIGHT = 1.0
SUPPORTING_WEIGHT = 0.5


def technique_score(
    technique: Technique,
    available_sources: Iterable[str],
    primary_weight: float = PRIMARY_WEIGHT,
    supporting_weight: float = SUPPORTING_WEIGHT,
) -> float:
    available = set(available_sources)
    roles = {ref.role for ref in technique.sources if ref.source_id in available}
    if "primary" in roles:
        return primary_weight
    if "supporting" in roles:
        return supporting_weight
    return 0.0


def coverage(
    techniques: Iterable[Technique],
    available_sources: Iterable[str],
    primary_weight: float = PRIMARY_WEIGHT,
    supporting_weight: float = SUPPORTING_WEIGHT,
) -> float:
    techniques = tuple(techniques)
    if not techniques:
        return 0.0
    total = sum(
        technique_score(
            t,
            available_sources,
            primary_weight=primary_weight,
            supporting_weight=supporting_weight,
        )
        for t in techniques
    )
    return total / (len(techniques) * primary_weight)


def coverage_breakdown(
    techniques: Iterable[Technique],
    available_sources: Iterable[str],
    primary_weight: float = PRIMARY_WEIGHT,
    supporting_weight: float = SUPPORTING_WEIGHT,
) -> dict[str, float]:
    return {
        t.id: technique_score(
            t,
            available_sources,
            primary_weight=primary_weight,
            supporting_weight=supporting_weight,
        )
        for t in techniques
    }

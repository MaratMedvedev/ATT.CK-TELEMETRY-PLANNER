from __future__ import annotations

from itertools import combinations
from typing import Iterable

from .coverage import coverage, technique_score
from .models import Recommendation, Source, Technique


def _why_for_source(
    techniques: Iterable[Technique], source_id: str
) -> tuple[str, ...]:
    reasons = []
    for technique in techniques:
        for ref in technique.sources:
            if ref.source_id == source_id:
                reasons.append(f"{technique.id} {technique.name}: {ref.why}")
    return tuple(dict.fromkeys(reasons))


def greedy_recommendations(
    techniques: Iterable[Technique],
    sources: dict[str, Source],
    current: Iterable[str],
    candidates: Iterable[str] | None = None,
    target: float = 1.0,
    primary_weight: float = 1.0,
    supporting_weight: float = 0.5,
) -> tuple[list[Recommendation], set[str]]:
    techniques = tuple(techniques)
    available = set(current)
    pool = set(candidates if candidates is not None else sources.keys()) - available
    recommendations: list[Recommendation] = []

    while coverage(
        techniques,
        available,
        primary_weight=primary_weight,
        supporting_weight=supporting_weight,
    ) < target and pool:
        base = coverage(
            techniques,
            available,
            primary_weight=primary_weight,
            supporting_weight=supporting_weight,
        )

        def gain_per_cost(source_id: str) -> float:
            gain = coverage(
                techniques,
                available | {source_id},
                primary_weight=primary_weight,
                supporting_weight=supporting_weight,
            ) - base
            return gain / sources[source_id].cost

        best = max(pool, key=gain_per_cost)
        score = gain_per_cost(best)
        gain = coverage(
            techniques,
            available | {best},
            primary_weight=primary_weight,
            supporting_weight=supporting_weight,
        ) - base
        if gain <= 0:
            break

        available.add(best)
        pool.remove(best)
        recommendations.append(
            Recommendation(
                source_id=best,
                source_name=sources[best].name,
                gain=gain,
                gain_points=gain * 100.0,
                cost=sources[best].cost,
                score=score,
                new_coverage=coverage(
                    techniques,
                    available,
                    primary_weight=primary_weight,
                    supporting_weight=supporting_weight,
                ),
                why=_why_for_source(techniques, best),
            )
        )
    return recommendations, available


def optimal_min_cost(
    techniques: Iterable[Technique],
    sources: dict[str, Source],
    current: Iterable[str],
    candidates: Iterable[str] | None = None,
    target: float = 1.0,
    primary_weight: float = 1.0,
    supporting_weight: float = 0.5,
) -> tuple[set[str], float]:
    techniques = tuple(techniques)
    current = set(current)
    pool = sorted(set(candidates if candidates is not None else sources.keys()) - current)
    best_set: set[str] | None = None
    best_cost: float = float("inf")

    for r in range(len(pool) + 1):
        for subset in combinations(pool, r):
            chosen = current | set(subset)
            score = coverage(
                techniques,
                chosen,
                primary_weight=primary_weight,
                supporting_weight=supporting_weight,
            )
            if score >= target:
                cost = sum(sources[s].cost for s in subset)
                if cost < best_cost:
                    best_cost = cost
                    best_set = set(subset)
        if best_set is not None:
            # We still need to continue within this cardinality to find the
            # cheapest subset of the same size.
            continue

    if best_set is None:
        return set(), float("inf")
    return best_set, best_cost


def cheapest_first(
    techniques: Iterable[Technique],
    sources: dict[str, Source],
    current: Iterable[str],
    target: float = 1.0,
) -> tuple[set[str], float]:
    techniques = tuple(techniques)
    available = set(current)
    chosen = set()
    for source_id in sorted(sources, key=lambda x: (sources[x].cost, x)):
        if coverage(techniques, available) >= target:
            break
        available.add(source_id)
        chosen.add(source_id)
    return chosen, sum(sources[s].cost for s in chosen)


def broad_first(
    techniques: Iterable[Technique],
    sources: dict[str, Source],
    current: Iterable[str],
    target: float = 1.0,
) -> tuple[set[str], float]:
    techniques = tuple(techniques)
    available = set(current)
    chosen = set()
    while coverage(techniques, available) < target:
        candidates = set(sources) - available
        if not candidates:
            break
        current_scores = {
            s: coverage(techniques, available | {s}) - coverage(techniques, available)
            for s in candidates
        }
        best = max(current_scores, key=lambda x: (current_scores[x], -sources[x].cost, x))
        if current_scores[best] <= 0:
            break
        available.add(best)
        chosen.add(best)
    return chosen, sum(sources[s].cost for s in chosen)

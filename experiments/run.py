from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.coverage import coverage
from app.kb import load_sources, load_techniques, validate_knowledge_base
from app.optimizer import broad_first, cheapest_first, greedy_recommendations, optimal_min_cost

OUT = ROOT / "experiments" / "out"
OUT.mkdir(exist_ok=True)

sources = load_sources()
techniques_dict = load_techniques(sources=sources)
techniques = list(techniques_dict.values())
errors = validate_knowledge_base(sources, techniques_dict)
if errors:
    raise SystemExit("KB validation errors:\n" + "\n".join(errors))

base = {"windows_security"}

# E1: named profiles.
profiles = {
    "Minimal": {"windows_security"},
    "Standard": {"windows_security", "sysmon"},
    "Enhanced": {"windows_security", "sysmon", "powershell_scriptblock", "zeek_conn"},
    "Full": set(sources),
}
e1 = pd.DataFrame(
    [
        {
            "profile": name,
            "coverage_pct": coverage(techniques, enabled) * 100,
            "cost": sum(sources[s].cost for s in enabled),
        }
        for name, enabled in profiles.items()
    ]
)
e1.to_csv(OUT / "e1_profiles.csv", index=False)

# E2: greedy vs exact optimum vs simple baselines.
rows = []
for target in [0.8, 0.9, 1.0]:
    greedy_recs, greedy_final = greedy_recommendations(techniques, sources, base, target=target)
    greedy_set = greedy_final - base
    greedy_cost = sum(sources[s].cost for s in greedy_set)
    optimal_set, optimal_cost = optimal_min_cost(techniques, sources, base, target=target)
    cheap_set, cheap_cost = cheapest_first(techniques, sources, base, target=target)
    broad_set, broad_cost = broad_first(techniques, sources, base, target=target)

    random_costs = []
    pool = sorted(set(sources) - base)
    rng = random.Random(42)
    for _ in range(1000):
        shuffled = pool[:]
        rng.shuffle(shuffled)
        available = set(base)
        chosen = set()
        for s in shuffled:
            if coverage(techniques, available) >= target:
                break
            available.add(s)
            chosen.add(s)
        if coverage(techniques, available) >= target:
            random_costs.append(sum(sources[s].cost for s in chosen))

    rows.extend(
        [
            {"target_pct": target * 100, "strategy": "greedy", "cost": greedy_cost},
            {"target_pct": target * 100, "strategy": "optimal", "cost": optimal_cost},
            {"target_pct": target * 100, "strategy": "cheapest_first", "cost": cheap_cost},
            {"target_pct": target * 100, "strategy": "broad_first", "cost": broad_cost},
            {"target_pct": target * 100, "strategy": "random_mean_1000", "cost": sum(random_costs) / len(random_costs) if random_costs else None},
        ]
    )

e2 = pd.DataFrame(rows)
e2.to_csv(OUT / "e2_strategies.csv", index=False)

# E3: exact cost/coverage frontier using all source subsets.
frontier = []
source_ids = sorted(sources)
from itertools import combinations
for r in range(len(source_ids) + 1):
    for subset in combinations(source_ids, r):
        enabled = base | set(subset)
        cost = sum(sources[s].cost for s in enabled)
        score = coverage(techniques, enabled)
        frontier.append((cost, score))
frontier_df = pd.DataFrame(frontier, columns=["cost", "coverage"]).drop_duplicates()
frontier_df = frontier_df.sort_values(["cost", "coverage"]).groupby("cost", as_index=False).max()
frontier_df["coverage_pct"] = frontier_df["coverage"] * 100
frontier_df.to_csv(OUT / "e3_frontier.csv", index=False)

# E4: sensitivity to the project-specific weights.
rows = []
for sw in [0.3, 0.5, 0.7]:
    for target in [0.8, 0.9, 1.0]:
        recs, final = greedy_recommendations(
            techniques, sources, base, target=target, primary_weight=1.0, supporting_weight=sw
        )
        selected = final - base
        rows.append(
            {
                "supporting_weight": sw,
                "target_pct": target * 100,
                "greedy_plan": "+".join(sorted(selected)),
                "cost": sum(sources[s].cost for s in selected),
                "result_coverage_pct": coverage(
                    techniques, final, primary_weight=1.0, supporting_weight=sw
                )
                * 100,
            }
        )

e4 = pd.DataFrame(rows)
e4.to_csv(OUT / "e4_sensitivity.csv", index=False)

summary = {
    "base_sources": sorted(base),
    "source_costs": {s: sources[s].cost for s in sources},
    "techniques": [t.id for t in techniques],
    "files": [
        "e1_profiles.csv",
        "e2_strategies.csv",
        "e3_frontier.csv",
        "e4_sensitivity.csv",
    ],
}
(OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

print(e1.to_string(index=False))
print("\nSaved experiments to", OUT)

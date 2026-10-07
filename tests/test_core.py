from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.coverage import coverage, technique_score
from app.kb import load_environments, load_sources, load_techniques, validate_knowledge_base
from app.optimizer import greedy_recommendations, optimal_min_cost


def test_kb_validates():
    sources = load_sources()
    techniques = load_techniques(sources=sources)
    envs = load_environments()
    assert validate_knowledge_base(sources, techniques, envs) == []


def test_primary_and_supporting_weights():
    sources = load_sources()
    techs = load_techniques(sources=sources)
    ps = techs["T1059.001"]
    assert technique_score(ps, {"sysmon"}) == 0.5
    assert technique_score(ps, {"powershell_scriptblock"}) == 1.0


def test_minimal_coverage():
    sources = load_sources()
    techs = list(load_techniques(sources=sources).values())
    assert round(coverage(techs, {"windows_security"}), 6) == round(2 / 6, 6)


def test_greedy_reaches_target_or_exhausts():
    sources = load_sources()
    techs = list(load_techniques(sources=sources).values())
    recs, final = greedy_recommendations(techs, sources, {"windows_security"}, target=0.9)
    assert coverage(techs, final) >= 0.9
    assert len(recs) > 0


def test_bruteforce_is_not_more_expensive_than_greedy():
    sources = load_sources()
    techs = list(load_techniques(sources=sources).values())
    recs, final = greedy_recommendations(techs, sources, {"windows_security"}, target=0.9)
    greedy_cost = sum(sources[s].cost for s in final - {"windows_security"})
    optimal, optimal_cost = optimal_min_cost(techs, sources, {"windows_security"}, target=0.9)
    assert optimal
    assert optimal_cost <= greedy_cost


def test_environment_sources_are_known():
    sources = load_sources()
    envs = load_environments()
    all_ids = set(sources)
    for env in envs.values():
        assert set(env.enabled_sources) <= all_ids

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.coverage import coverage, coverage_breakdown  # noqa: E402
from app.kb import load_environments, load_sources, load_techniques, validate_knowledge_base  # noqa: E402
from app.optimizer import greedy_recommendations, optimal_min_cost  # noqa: E402

st.set_page_config(page_title="ATT&CK Telemetry Planner", layout="wide")

sources = load_sources()
techniques = load_techniques(sources=sources)
environments = load_environments()
errors = validate_knowledge_base(sources, techniques, environments)

st.title("ATT&CK Telemetry Planner")
st.caption("Start from detection goals → work backwards to the telemetry you actually need.")

if errors:
    st.error("Knowledge base validation failed:")
    st.code("\n".join(errors))
    st.stop()

source_names = {sid: s.name for sid, s in sources.items()}

with st.sidebar:
    st.header("Scenario")
    env_label_to_id = {f"{e.name} — {e.description}": e.id for e in environments.values()}
    profile_labels = list(env_label_to_id)
    default_profile = next((i for i, label in enumerate(profile_labels) if env_label_to_id[label] == "minimal"), 0)
    selected_label = st.selectbox("Profile", profile_labels, index=default_profile)
    env_id = env_label_to_id[selected_label]
    environment = environments[env_id]

    selected_tech_ids = st.multiselect(
        "ATT&CK techniques",
        options=list(techniques),
        default=list(techniques),
        format_func=lambda tid: f"{tid} — {techniques[tid].name}",
    )

    if not selected_tech_ids:
        st.warning("Select at least one technique.")
        st.stop()

    selected_techniques = [techniques[tid] for tid in selected_tech_ids]

    st.subheader("Current telemetry")
    default_current = list(environment.enabled_sources)
    current = {
        sid
        for sid in sources
        if st.checkbox(
            source_names[sid],
            value=sid in default_current,
            key=f"source-{sid}",
            help=sources[sid].description,
        )
    }

    st.subheader("Costs")
    costs = {}
    for sid, src in sources.items():
        costs[sid] = st.slider(
            f"{src.name}", min_value=1, max_value=5, value=src.cost, key=f"cost-{sid}"
        )

    target = st.slider("Target coverage", 0.0, 1.0, 0.90, 0.05)
    primary_weight = st.number_input("Primary weight", 0.1, 2.0, 1.0, 0.1)
    supporting_weight = st.number_input("Supporting weight", 0.0, primary_weight, 0.5, 0.1)

# Apply UI cost overrides without mutating the dataclasses.
from dataclasses import replace
ui_sources = {sid: replace(src, cost=costs[sid]) for sid, src in sources.items()}

current_cov = coverage(
    selected_techniques,
    current,
    primary_weight=primary_weight,
    supporting_weight=supporting_weight,
)

tab1, tab2, tab3, tab4 = st.tabs(
    ["Coverage Matrix", "Recommendations", "What-If", "Methodology / KB"]
)

with tab1:
    c1, c2, c3 = st.columns(3)
    c1.metric("Current coverage", f"{current_cov * 100:.1f}%")
    c2.metric("Techniques", str(len(selected_techniques)))
    c3.metric("Telemetry cost", str(sum(ui_sources[s].cost for s in current)))

    rows = []
    for technique in selected_techniques:
        row = {"Technique": f"{technique.id} — {technique.name}"}
        refs = {r.source_id: r.role for r in technique.sources}
        for sid in sources:
            role = refs.get(sid, "")
            row[source_names[sid]] = role
        row["Score"] = coverage_breakdown(
            [technique], current, primary_weight=primary_weight, supporting_weight=supporting_weight
        )[technique.id]
        rows.append(row)

    df = pd.DataFrame(rows).set_index("Technique")
    st.dataframe(df, use_container_width=True)
    st.info("P = primary telemetry, S = supporting telemetry. Score is a project-specific metric, not an official MITRE score.")

with tab2:
    recs, final_sources = greedy_recommendations(
        selected_techniques,
        ui_sources,
        current,
        target=target,
        primary_weight=primary_weight,
        supporting_weight=supporting_weight,
    )
    if not recs:
        st.success("No additional source has positive marginal gain for the current scenario.")
    else:
        for idx, rec in enumerate(recs, start=1):
            with st.expander(f"{idx}. +{rec.source_name} — +{rec.gain_points:.1f} pp, cost {rec.cost}", expanded=idx == 1):
                st.write(f"Coverage after step: **{rec.new_coverage * 100:.1f}%**")
                st.write(f"Greedy score (gain/cost): **{rec.score:.3f}**")
                for why in rec.why:
                    st.write(f"• {why}")

    greedy_set = final_sources - current
    opt_set, opt_cost = optimal_min_cost(
        selected_techniques,
        ui_sources,
        current,
        target=target,
        primary_weight=primary_weight,
        supporting_weight=supporting_weight,
    )
    greedy_cost = sum(ui_sources[s].cost for s in greedy_set)
    m1, m2, m3 = st.columns(3)
    m1.metric("Greedy cost", str(greedy_cost))
    m2.metric("Optimal cost", "—" if opt_cost == float("inf") else f"{opt_cost:g}")
    m3.metric("Gap", "—" if opt_cost == float("inf") else f"{greedy_cost - opt_cost:g}")

with tab3:
    st.subheader("Compare scenarios")
    available_options = {sid: name for sid, name in source_names.items() if sid not in current}
    selected_extra = st.multiselect(
        "Add sources to the What-If scenario",
        options=list(available_options),
        format_func=lambda sid: available_options[sid],
        default=[],
    )
    scenario_sets = {
        "Current": current,
        "What-If": current | set(selected_extra),
    }
    recs, final_sources = greedy_recommendations(
        selected_techniques,
        ui_sources,
        current,
        target=target,
        primary_weight=primary_weight,
        supporting_weight=supporting_weight,
    )
    scenario_sets["Greedy plan"] = final_sources
    scenarios = []
    for name, enabled in scenario_sets.items():
        scenarios.append(
            {
                "Scenario": name,
                "Coverage": coverage(
                    selected_techniques,
                    enabled,
                    primary_weight=primary_weight,
                    supporting_weight=supporting_weight,
                ) * 100,
                "Cost": sum(ui_sources[s].cost for s in enabled),
            }
        )
    s_df = pd.DataFrame(scenarios)
    st.dataframe(s_df, use_container_width=True, hide_index=True)
    fig = px.scatter(s_df, x="Cost", y="Coverage", text="Scenario", size_max=18)
    fig.update_layout(yaxis_range=[0, 105], height=450, margin=dict(l=10, r=10, t=30, b=10))
    st.plotly_chart(fig, use_container_width=True)

with tab4:
    st.markdown("### Assumptions")
    st.write(
        "A technique is scored as primary when at least one available primary source exists; "
        "otherwise supporting data yields a partial score. The weights are configurable because they are a project-specific experimental metric."
    )
    st.markdown("### Knowledge base")
    kb_rows = []
    for t in selected_techniques:
        for ref in t.sources:
            kb_rows.append(
                {
                    "Technique": t.id,
                    "Name": t.name,
                    "Source": source_names[ref.source_id],
                    "Role": ref.role,
                    "Why": ref.why,
                    "Evidence": ref.evidence,
                }
            )
    st.dataframe(pd.DataFrame(kb_rows), use_container_width=True, hide_index=True)
    st.markdown("### Important boundary")
    st.write("This MVP plans telemetry from ATT&CK techniques; it does not ingest real host/network logs and it is not a SIEM.")

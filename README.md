# ATT&CK Telemetry Planner

Small Streamlit prototype for planning telemetry from ATT&CK detection goals.

> We start with what we want to detect and work backwards to determine what logs we need.

## What it does

- select ATT&CK techniques;
- select current telemetry sources;
- calculate coverage by technique and overall;
- recommend additional sources with a cost-aware greedy algorithm;
- compare the greedy plan with an exact brute-force optimum;
- run interactive What-If scenarios;
- expose the knowledge base and evidence URLs.

## Project structure

```text
attack-telemetry-planner/
├── app/
│   ├── main.py
│   ├── models.py
│   ├── kb.py
│   ├── coverage.py
│   ├── optimizer.py
│   └── whatif.py
├── data/
│   ├── sources.yml
│   ├── techniques.yml
│   └── environments/
├── experiments/
│   └── run.py
├── tests/
├── docs/
├── requirements.txt
└── README.md
```

## Run locally

Python 3.11+ is recommended.

### 1. Create a virtual environment

```bash
python -m venv .venv
```

### 2. Activate it

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run tests

```bash
pytest -q
```

### 5. Run experiments

```bash
python experiments/run.py
```

The generated CSV files appear in `experiments/out/`.

### 6. Start the demo

```bash
streamlit run app/main.py
```

The browser opens the local Streamlit app. No internet connection is required for the application itself.

## 3-minute live-demo script

1. Open **Minimal** profile.
2. Leave all six techniques selected.
3. Show the **Coverage Matrix** and the current coverage.
4. Open **Recommendations** and show the first suggested telemetry source, its gain and cost.
5. Open **What-If**, add one source manually, and show the coverage change.
6. Return to **Recommendations** and compare greedy cost with the brute-force optimum.
7. Finish with the sentence: **The goal is not to collect every log; it is to collect a small set that gives enough detection visibility.**

## Important scope statement

This is an MVP planning tool. It does not parse real logs, replace a SIEM, or generate Sigma rules. The coverage score and source costs are project-specific experimental assumptions.

## Knowledge-base note

The included YAML is a defensible demo seed for six ATT&CK techniques and five telemetry sources. Before submitting the final report, re-check every role/evidence mapping against the exact ATT&CK release you cite and keep the version/date in the report.

## ATT&CK telemetry scraper

The project also includes a STIX-based ATT&CK scraper. It downloads a pinned Enterprise ATT&CK release, extracts the chain `Technique -> Detection Strategy -> Analytic -> Data Component -> Log Source`, maps known log-source names to the planner's normalized telemetry IDs, and writes a reproducible report. The scraper uses official MITRE ATT&CK STIX data rather than brittle HTML parsing.

### 1. Scrape the default ATT&CK release

```bash
python -m scraper.attack_scraper --version 19.2
```

By default it downloads Enterprise ATT&CK v19.2 and stores the downloaded STIX bundle and generated outputs under `data/generated/`.

### 2. Scrape only the techniques used by the demo

```bash
python -m scraper.attack_scraper \
  --version 19.2 \
  --techniques T1059.001,T1110,T1021.001,T1046,T1105,T1071.004
```

### 3. Make the scraped data the planner's active KB

```bash
python -m scraper.attack_scraper \
  --version 19.2 \
  --techniques T1059.001,T1110,T1021.001,T1046,T1105,T1071.004 \
  --apply
```

`--apply` updates `data/techniques.yml` only for telemetry sources that are present in `data/source_mapping.yml` and creates a backup at `data/techniques.yml.bak`.

### Where results are saved

```text
data/generated/
├── enterprise-attack-19.2.json   # downloaded ATT&CK STIX bundle
├── techniques_scraped.yml        # normalized technique -> telemetry mapping
├── telemetry_records.json        # one record per extracted ATT&CK telemetry mapping
└── scrape_report.json            # counts, version, unknown log sources, paths
```

The exact paths are printed by the command after a successful run. Unknown ATT&CK log-source names are reported in `scrape_report.json`; they are not silently invented as planner sources.

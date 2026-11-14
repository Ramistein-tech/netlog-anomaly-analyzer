# NetLog Anomaly Analyzer — Concept, User & Developer Guide

> **Privacy-First Security Telemetry & Behavioral Log Analytics Engine**  
> Designed in compliance with **DSGVO / GDPR Art. 32** for auditing heterogeneous web infrastructures (**Nginx/Apache** & **FastAPI/Uvicorn**).

---

## 1. Project Concept & Engineering Vision

Modern web applications generate massive volumes of unstructured access logs containing valuable security telemetry alongside sensitive personally identifiable information (**PII**), specifically client IP addresses. Security and data teams face three core engineering challenges:

1. **The Privacy vs. Observability Dilemma (DSGVO / GDPR):** Storing raw IP addresses violates data minimization principles, whereas naive anonymization (e.g., IP truncation or unsalted SHA-256 hashing) either destroys session correlation or remains vulnerable to rainbow-table reversal across the 32-bit IPv4 space.
2. **Heterogeneous Infrastructure:** Production stacks frequently combine traditional reverse proxies (**Nginx / Apache**) with modern Python ASGI microservices (**FastAPI / Uvicorn**), each emitting distinct log schemas and dynamic TCP source ports.
3. **Alert Fatigue from Naive Thresholds:** Pure volumetric anomaly detectors miss low-and-slow targeted attacks, while raw HTTP error ratios generate false positives whenever a legitimate user makes a single typo (`HTTP 404`).

**NetLog Anomaly Analyzer** solves these challenges through a modular, zero-PII-persistence **ETL pipeline** (*Extract, Transform, Load*) that pseudonymizes client identities at ingestion time and combines time-series statistical deviation (**Z-Score**) with minimum-volume-gated behavioral heuristics.

---

## 2. System Architecture & Data Pipeline

```text
+-----------------------------------------------------------------------------------+
|                        RAW SERVER ACCESS LOGS (Unstructured)                      |
|   • Nginx / Apache (Combined Log Format)                                          |
|   • FastAPI / Uvicorn (Timestamped & Standard ASGI Output)                        |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [STAGE 1] MULTI-FORMAT INGESTION & EPHEMERAL PORT STRIPPING (src/parser.py)      |
|   • Pre-compiled RegEx fallback chain (O(n) linear scan)                          |
|   • Strips dynamic TCP source ports ('IP:Port' -> 'IP')                           |
|   • Isolates malformed lines & computes IngestionStats (Data Lineage)             |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [STAGE 2] CRYPTOGRAPHIC PSEUDONYMIZATION (src/anonymizer.py)                     |
|   • Keyed HMAC-SHA256 hashing: IP + Secret Salt -> 'client_<16-hex-digest>'       |
|   • Raw IPv4 strings are discarded immediately; never stored in DataFrames        |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [STAGE 3] HYBRID ANOMALY DETECTION ENGINE (src/analyzer.py)                      |
|   • Tumbling time-window aggregation ('30s', '1min', '5min') via pandas.Grouper   |
|   • Population-level Z-Score deviation across request volumes                     |
|   • Behavioral HTTP heuristics: Auth (401/403), Quota (429), Recon (404/405)      |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [STAGE 4] STRUCTURED AUDIT & BI REPORTING (src/reporter.py)                      |
|   • output/security_audit_report.json  (Full metadata, data quality & incidents)  |
|   • output/detected_anomalies.csv      (BI / SQL / Jupyter-ready tabular export)  |
+-----------------------------------------------------------------------------------+
```

---

## 3. User Guide (Operations & CLI Reference)

### 3.1 Environment Setup
```bash
git clone [https://github.com/Ramistein-tech/netlog-anomaly-analyzer.git](https://github.com/Ramistein-tech/netlog-anomaly-analyzer.git)
cd netlog-anomaly-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3.2 Command-Line Interface (CLI) Reference

| Flag | Description | Default | Tuning Guidance |
| :--- | :--- | :--- | :--- |
| `-h`, `--help` | Display CLI help menu and exit. | — | Quick syntax verification. |
| `--generate` | Generate a synthetic CLF dataset with 3 injected ground-truth attack profiles. | `False` | Use for demos, benchmarking, and pipeline validation. |
| `--analyze` | Execute ingestion, pseudonymization, anomaly detection, and report export. | `False` | Required for all analysis runs. |
| `--log-file <PATH>` | Target raw log file (`Nginx/Apache` or `FastAPI/Uvicorn`). | `data/sample_access.log` | Point to production or exported container logs. |
| `--output-dir <DIR>` | Destination directory for exported `JSON` and `CSV` reports. | `output/` | Isolate outputs across separate audit runs. |
| `--window <OFFSET>` | Time-series aggregation interval (`30s`, `1min`, `5min`). | `1min` | Narrow (`30s`) for burst attacks; widen (`5min`) for slow scans. |
| `--threshold <FLOAT>` | Minimum Z-Score threshold for volumetric traffic spikes. | `3.0` | Lower to `2.0–2.5` for higher sensitivity; raise to `4.0` to suppress noise. |

### 3.3 Operational Workflows

1. **End-to-End Synthetic Demonstration:**
   ```bash
   python main.py --generate --analyze
   ```

2. **Auditing Production Logs with High Sensitivity (`30s` Window):**
   ```bash
   python main.py --analyze --log-file data/server_access.log --window 30s --threshold 2.5
   ```

3. **Authorized Multi-Day Correlation via Persistent Secret Salt:**
   By default, the engine generates a cryptographically random ephemeral salt per execution to prevent cross-session tracking. For authorized multi-day incident correlation, supply a managed secret key via `LOG_ANALYZER_SALT`:
   ```bash
   LOG_ANALYZER_SALT="Org_Audit_Key_2026" python main.py --analyze --log-file data/day1.log
   LOG_ANALYZER_SALT="Org_Audit_Key_2026" python main.py --analyze --log-file data/day2.log
   ```

### 3.4 Threat Classification Taxonomy

| Classification | HTTP Signals | Heuristic & Statistical Rule | Attack Vector Description |
| :--- | :--- | :--- | :--- |
| **`CREDENTIAL_BRUTE_FORCE`** | `401`, `403` | `auth_errors >= 5` and $\ge 50\%$ of client window requests | Automated password spraying or credential stuffing against login endpoints. |
| **`RATE_LIMIT_ABUSE`** | `429` | `rate_limit_errors >= 5` and $\ge 50\%$ of client window requests | Persistent API quota exhaustion or automated scraping against rate-limited endpoints (e.g., `SlowAPI`). |
| **`DIRECTORY_ENUMERATION`** | `404`, `405` | `recon_errors >= 5` and $\ge 50\%$ of client window requests | Automated path fuzzing, hidden admin discovery, or vulnerability probing. |
| **`VOLUMETRIC_TRAFFIC_SPIKE`** | Any (`2xx`–`5xx`) | Request volume `z_score >= threshold` (default `3.0`) | Sudden high-frequency request surges, DoS bursts, or anomalous bot traffic. |

---

## 4. Developer Guide (Architecture & Extension)

### 4.1 Codebase Organization
* **`main.py`**: CLI argument parser, cryptographic salt lifecycle manager, and pipeline orchestrator.
* **`src/anonymizer.py`**: Implements `generate_ephemeral_salt()` and `pseudonymize_ip()` using Python's standard `hmac` and `hashlib` libraries.
* **`src/parser.py`**: Multi-format RegEx ingestion (`COMBINED_LOG_REGEX`, `UVICORN_TIMESTAMPED_REGEX`, `UVICORN_STANDARD_REGEX`), port stripping, UTC timestamp normalization, and `IngestionStats`.
* **`src/analyzer.py`**: Tumbling window grouping (`pd.Grouper`), Z-Score computation, boolean detection masks, and priority-ordered incident classification.
* **`src/log_generator.py`**: Deterministic synthetic log generator (`random.Random(seed)`) for reproducible testing.
* **`src/reporter.py`**: Serializes audit summaries to `JSON` and tabular anomaly records to `CSV`.
* **`tests/test_analyzer.py`**: Automated `pytest` suite covering cryptographic invariants, multi-format parsing, port stripping, and all four threat classes.

### 4.2 Extending the Detection Engine

#### Adding a New Threat Category (Example: Server Error Flood `HTTP 5xx`)
1. Open **`src/analyzer.py`** and add an indicator column inside `analyze_traffic_anomalies()`:
   ```python
   working_df["is_server_error"] = (working_df["status"] >= 500).astype("int32")
   ```
2. Aggregate the column in `.agg(...)` (`server_errors=("is_server_error", "sum")`) and update `_classify_incident(row)`:
   ```python
   if row["server_errors"] >= 5 and (row["server_errors"] / total_reqs) >= 0.5:
       return "SERVER_ERROR_SPIKE"
   ```

#### Supporting an Additional Log Format
1. Define a pre-compiled regular expression `CUSTOM_LOG_REGEX = re.compile(...)` in **`src/parser.py`**.
2. Add a matching block inside `_extract_line_record()` before `return None` to integrate it into the deterministic fallback chain.

### 4.3 Quality Assurance & Contribution Workflow
All modifications must pass the automated test suite prior to committing:
```bash
pytest -v
git status
git add src/ tests/ docs/
git commit -m "feat: describe architectural improvement"
git push
```
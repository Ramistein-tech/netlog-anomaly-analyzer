# 🛡️ NetLog Anomaly Analyzer (`netlog-anomaly-analyzer`)

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![DSGVO / GDPR Compliant](https://img.shields.io/badge/Privacy-DSGVO%20%2F%20HMAC--SHA256-green.svg)](#privacy-by-design-dsgvo--gdpr)
[![Code Quality: Pytest](https://img.shields.io/badge/Tests-Pytest%20Verified-brightgreen.svg)](#testing)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **DE:** Eine DSGVO-konforme Python-Datenpipeline zur Bereinigung, Pseudonymisierung und statistischen Anomalieerkennung in Webserver-Zugriffsprotokollen.  
> **EN:** A GDPR/DSGVO-compliant Python data engineering pipeline for cleaning, pseudonymizing, and detecting statistical security anomalies in web server access logs.

---

## 🎯 Project Overview & Motivation

Modern enterprise applications generate massive volumes of semi-structured access logs. Extracting actionable security and operational insights from these logs requires bridging **Data Analytics** (schema validation, time-series aggregation, statistical outlier detection) with **Information Security & Data Privacy** (DSGVO-compliant pseudonymization and threat classification).

This project implements a modular, production-oriented CLI pipeline that:
1. **Ingests & Cleans** raw Nginx/Apache Combined Log Format streams via pre-compiled Regular Expressions while tracking data quality metrics.
2. **Pseudonymizes PII at Ingestion** using keyed `HMAC-SHA256` hashing (preventing rainbow-table reversal of the 32-bit IPv4 space).
3. **Detects & Classifies Anomalies** across tumbling time windows (`1min`, `5min`) by combining **Z-Score volumetric outlier analysis** with **HTTP error-ratio heuristics** (`401 Unauthorized`, `403 Forbidden`, `404 Not Found`).
4. **Exports BI-Ready Artifacts** (`JSON` audit logs with data lineage metadata + `CSV` incident tables for SQL/PostgreSQL or BI dashboards).

---

## 🏗️ System Architecture

```text
Raw Server Logs (.log)
       │
       ▼
┌─────────────────────────────────────────┐
│  1. Ingestion & Data Cleaning           │  ──► Tracks Data Quality (Valid vs. Malformed)
│     (src/parser.py - Pre-compiled RegEx)│
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  2. Privacy-by-Design Layer             │  ──► HMAC-SHA256 Salted Pseudonymization
│     (src/anonymizer.py - DSGVO Art. 32) │      (Raw IPs never enter DataFrames)
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  3. Statistical & Behavioral Engine     │  ──► Tumbling Time-Window Aggregation
│     (src/analyzer.py - Pandas & Z-Score)│      Classifies Brute-Force, Recon & Spikes
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  4. Structured Reporting & Audit Export │  ──► security_audit_report.json
│     (src/reporter.py)                   │      detected_anomalies.csv
└─────────────────────────────────────────┘
---

## Detailed Documentation

See the **[User & Developer Technical Guide](docs/USER_AND_DEVELOPER_GUIDE.md)** for architecture diagrams, CLI workflows, and extension guides.

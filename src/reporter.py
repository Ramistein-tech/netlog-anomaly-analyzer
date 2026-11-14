"""
Module: reporter.py
Purpose: Exports structured analytical summaries and detected security incidents into
         machine-readable JSON and CSV formats for downstream BI dashboards or SIEM ingestion.

Architectural Rationale:
    Separating presentation/serialization from core statistical logic adheres to the Single
    Responsibility Principle (SRP). Exporting standardized JSON audit metadata alongside
    flat CSV tables allows seamless integration with PostgreSQL COPY pipelines, PowerBI,
    or automated alerting webhooks.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from src.parser import IngestionStats


def export_reports(
    anomalies_df: pd.DataFrame,
    stats: IngestionStats,
    output_dir: Path,
    window: str,
    z_threshold: float,
) -> tuple[Path, Path]:
    """
    Write detected anomaly records and ingestion audit metadata to JSON and CSV files.

    Args:
        anomalies_df (pd.DataFrame): Filtered DataFrame of detected security incidents.
        stats (IngestionStats): Data quality metrics from the ingestion stage.
        output_dir (Path): Directory where report artifacts will be saved.
        window (str): Time window parameter used during analysis.
        z_threshold (float): Statistical threshold parameter used during analysis.

    Returns:
        tuple[Path, Path]: Paths to the generated JSON audit report and CSV incident table.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path: Path = output_dir / "security_audit_report.json"
    csv_path: Path = output_dir / "detected_anomalies.csv"

    # Prepare serializable records (convert pandas Timestamps to ISO-8601 strings)
    serializable_df = anomalies_df.copy()
    if not serializable_df.empty and "timestamp" in serializable_df.columns:
        serializable_df["timestamp"] = serializable_df["timestamp"].dt.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    # Export flat CSV table for spreadsheet inspection or SQL database ingestion
    serializable_df.to_csv(csv_path, index=False, encoding="utf-8")

    # Construct structured JSON audit payload containing governance and lineage metadata
    report_payload: dict[str, object] = {
        "report_metadata": {
            "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "gdpr_compliance_mode": "HMAC-SHA256-PSEUDONYMIZED",
            "analysis_parameters": {
                "time_window": window,
                "z_score_threshold": z_threshold,
            },
        },
        "data_quality_metrics": {
            "total_lines_read": stats.total_lines,
            "valid_records_parsed": stats.parsed_lines,
            "malformed_lines_dropped": stats.malformed_lines,
            "parse_success_rate_percent": stats.parse_success_rate,
        },
        "summary": {
            "total_anomalies_detected": len(serializable_df),
            "unique_flagged_clients": (
                int(serializable_df["client_id"].nunique())
                if not serializable_df.empty
                else 0
            ),
        },
        "incidents": serializable_df.to_dict(orient="records"),
    }

    with json_path.open("w", encoding="utf-8") as json_file:
        json.dump(report_payload, json_file, indent=2, ensure_ascii=False)

    return json_path, csv_path

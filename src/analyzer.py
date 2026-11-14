"""
Module: analyzer.py
Purpose: Performs time-series aggregation and hybrid anomaly detection (statistical Z-Score
         combined with behavioral HTTP error heuristics) on pseudonymized web access logs.
"""

import numpy as np
import pandas as pd


def _classify_incident(row: pd.Series) -> str:
    """Classify a flagged anomalous client-window into an actionable security threat category."""
    total_reqs: float = float(row["request_count"])
    if total_reqs <= 0:
        return "VOLUMETRIC_TRAFFIC_SPIKE"

    if row["auth_errors"] >= 5 and (row["auth_errors"] / total_reqs) >= 0.5:
        return "CREDENTIAL_BRUTE_FORCE"

    if row["rate_limit_errors"] >= 5 and (row["rate_limit_errors"] / total_reqs) >= 0.5:
        return "RATE_LIMIT_ABUSE"

    if row["recon_errors"] >= 5 and (row["recon_errors"] / total_reqs) >= 0.5:
        return "DIRECTORY_ENUMERATION"

    return "VOLUMETRIC_TRAFFIC_SPIKE"


def _assign_severity(row: pd.Series) -> str:
    """Determine incident severity level ('HIGH' or 'MEDIUM') from statistical and error signals."""
    if (
        row["z_score"] >= 5.0
        or row["error_ratio"] >= 0.8
        or row["request_count"] >= 50
        or row["rate_limit_errors"] >= 15
    ):
        return "HIGH"
    return "MEDIUM"


def analyze_traffic_anomalies(
    df: pd.DataFrame,
    window: str = "1min",
    z_threshold: float = 3.0,
    error_ratio_threshold: float = 0.65,
    min_requests_for_error_alert: int = 10,
    min_rate_limit_errors: int = 5,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Aggregate pseudonymized log events into discrete time windows and detect anomalous clients."""
    expected_columns = [
        "timestamp",
        "client_id",
        "request_count",
        "auth_errors",
        "recon_errors",
        "rate_limit_errors",
        "total_errors",
        "unique_endpoints",
        "total_bytes",
        "z_score",
        "error_ratio",
        "threat_classification",
        "severity",
    ]

    if df.empty:
        empty_df = pd.DataFrame(columns=expected_columns)
        return empty_df, empty_df.copy()

    working_df = df.copy()
    working_df["is_auth_error"] = working_df["status"].isin([401, 403]).astype("int32")
    working_df["is_recon_error"] = working_df["status"].isin([404, 405]).astype("int32")
    working_df["is_rate_limit_error"] = (working_df["status"] == 429).astype("int32")
    working_df["is_any_error"] = (working_df["status"] >= 400).astype("int32")

    grouped = (
        working_df.groupby([pd.Grouper(key="timestamp", freq=window), "client_id"], observed=True)
        .agg(
            request_count=("status", "count"),
            auth_errors=("is_auth_error", "sum"),
            recon_errors=("is_recon_error", "sum"),
            rate_limit_errors=("is_rate_limit_error", "sum"),
            total_errors=("is_any_error", "sum"),
            unique_endpoints=("endpoint", "nunique"),
            total_bytes=("bytes", "sum"),
        )
        .reset_index()
    )

    mean_requests: float = float(grouped["request_count"].mean())
    std_requests: float = float(grouped["request_count"].std(ddof=0))

    if std_requests > 0.0:
        grouped["z_score"] = ((grouped["request_count"] - mean_requests) / std_requests).round(3)
    else:
        grouped["z_score"] = 0.0

    grouped["error_ratio"] = np.where(
        grouped["request_count"] > 0,
        (grouped["total_errors"] / grouped["request_count"]).round(3),
        0.0,
    )

    volumetric_mask = grouped["z_score"] >= z_threshold
    behavioral_error_mask = (grouped["request_count"] >= min_requests_for_error_alert) & (
        grouped["error_ratio"] >= error_ratio_threshold
    )
    rate_limit_mask = (grouped["rate_limit_errors"] >= min_rate_limit_errors) & (
        (grouped["rate_limit_errors"] / grouped["request_count"]) >= 0.5
    )

    anomaly_mask = volumetric_mask | behavioral_error_mask | rate_limit_mask
    anomalies = grouped[anomaly_mask].copy()

    if anomalies.empty:
        grouped["threat_classification"] = "NORMAL"
        grouped["severity"] = "NONE"
        empty_anomalies = pd.DataFrame(columns=expected_columns)
        return grouped, empty_anomalies

    anomalies["threat_classification"] = anomalies.apply(_classify_incident, axis=1)
    anomalies["severity"] = anomalies.apply(_assign_severity, axis=1)

    grouped["threat_classification"] = "NORMAL"
    grouped["severity"] = "NONE"
    grouped.loc[anomaly_mask, "threat_classification"] = anomalies["threat_classification"]
    grouped.loc[anomaly_mask, "severity"] = anomalies["severity"]

    anomalies = anomalies.sort_values(
        by=["z_score", "rate_limit_errors"], ascending=False
    ).reset_index(drop=True)

    return grouped, anomalies

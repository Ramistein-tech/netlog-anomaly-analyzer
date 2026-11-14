"""
Module: analyzer.py
Purpose: Performs time-series aggregation and statistical anomaly detection over structured
         HTTP access logs to identify volumetric spikes and targeted attack patterns.

Architectural Rationale:
    Pure threshold rules (e.g., "flag > 100 requests") fail across environments with varying
    baseline traffic volumes. Conversely, pure statistical outliers miss low-volume targeted
    attacks (such as slow credential stuffing). Therefore, this engine combines two layers:
      1. Statistical Z-Score Detection: Measures how many standard deviations a client's
         request volume deviates from the cohort mean within a tumbling time window.
      2. Behavioral Heuristic Scoring: Evaluates authentication error rates (HTTP 401),
         resource probing rates (HTTP 403/404), and endpoint diversity to classify the
         exact threat vector.
"""

import pandas as pd


def analyze_traffic_anomalies(
    df: pd.DataFrame,
    window: str = "1min",
    z_threshold: float = 3.0,
    error_ratio_threshold: float = 0.65,
    min_requests_for_error_alert: int = 10,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Aggregate traffic into tumbling time windows per client and isolate anomalous behavior.

    Args:
        df (pd.DataFrame): Clean, pseudonymized access log DataFrame from parser.py.
        window (str): Pandas frequency alias defining the aggregation bucket (e.g., '1min', '5min').
        z_threshold (float): Minimum Z-Score required to classify a volume burst as anomalous.
        error_ratio_threshold (float): Minimum ratio of HTTP 401/403/404 errors (0.0 to 1.0)
                                       to trigger a behavioral intrusion alert.
        min_requests_for_error_alert (int): Minimum request floor preventing false positives from
                                            a single user mistyping a URL once (1/1 = 100% error).

    Returns:
        tuple[pd.DataFrame, pd.DataFrame]:
            - window_metrics: Complete aggregated time-series metrics for all clients.
            - detected_anomalies: Filtered subset of windows flagged as security incidents.
    """
    if df.empty:
        return pd.DataFrame(), pd.DataFrame()

    working_df = df.copy()

    # Create binary indicator columns for vectorized group aggregation
    working_df["is_auth_error"] = (working_df["status"] == 401).astype(int)
    working_df["is_recon_error"] = working_df["status"].isin([403, 404]).astype(int)
    working_df["is_any_error"] = working_df["status"].isin([401, 403, 404]).astype(int)

    # Group events by tumbling time window and pseudonymized client identifier
    window_metrics: pd.DataFrame = (
        working_df.set_index("timestamp")
        .groupby([pd.Grouper(freq=window), "client_id"])
        .agg(
            request_count=("status", "count"),
            auth_errors=("is_auth_error", "sum"),
            recon_errors=("is_recon_error", "sum"),
            total_errors=("is_any_error", "sum"),
            unique_endpoints=("endpoint", "nunique"),
            total_bytes=("bytes", "sum"),
        )
        .reset_index()
    )

    if window_metrics.empty:
        return window_metrics, pd.DataFrame()

    # Calculate cohort-wide mean and population standard deviation (ddof=0)
    mean_requests: float = float(window_metrics["request_count"].mean())
    std_requests: float = float(window_metrics["request_count"].std(ddof=0))

    # Guard against division by zero when all clients exhibit identical request counts
    if std_requests == 0.0:
        window_metrics["z_score"] = 0.0
    else:
        window_metrics["z_score"] = (
            (window_metrics["request_count"] - mean_requests) / std_requests
        ).round(3)

    # Compute proportion of failed HTTP responses per client window
    window_metrics["error_ratio"] = (
        window_metrics["total_errors"] / window_metrics["request_count"]
    ).round(3)

    # Evaluate statistical and behavioral detection conditions
    is_volume_spike = window_metrics["z_score"] >= z_threshold
    is_high_error_burst = (window_metrics["error_ratio"] >= error_ratio_threshold) & (
        window_metrics["request_count"] >= min_requests_for_error_alert
    )

    detected_anomalies = window_metrics[is_volume_spike | is_high_error_burst].copy()

    if not detected_anomalies.empty:
        detected_anomalies["threat_classification"] = detected_anomalies.apply(
            _classify_incident, axis=1
        )
        detected_anomalies["severity"] = detected_anomalies.apply(
            _assign_severity, axis=1
        )
        detected_anomalies = detected_anomalies.sort_values(
            by=["z_score", "error_ratio"], ascending=[False, False]
        ).reset_index(drop=True)

    return window_metrics, detected_anomalies


def _classify_incident(row: pd.Series) -> str:
    """
    Assign a semantic security category to an anomalous client window based on error signatures.

    Args:
        row (pd.Series): A single aggregated row from the detected_anomalies DataFrame.

    Returns:
        str: Classification label ('CREDENTIAL_BRUTE_FORCE', 'DIRECTORY_ENUMERATION',
             or 'VOLUMETRIC_TRAFFIC_SPIKE').
    """
    # Predominantly HTTP 401 responses indicate automated password guessing
    if row["auth_errors"] >= 5 and (row["auth_errors"] / row["request_count"]) >= 0.5:
        return "CREDENTIAL_BRUTE_FORCE"

    # Predominantly HTTP 403/404 across distinct paths indicates automated directory probing
    if row["recon_errors"] >= 5 and (row["recon_errors"] / row["request_count"]) >= 0.5:
        return "DIRECTORY_ENUMERATION"

    return "VOLUMETRIC_TRAFFIC_SPIKE"


def _assign_severity(row: pd.Series) -> str:
    """
    Compute operational triage severity ('HIGH' vs. 'MEDIUM') for SOC or BI alerting.

    Args:
        row (pd.Series): A single aggregated row from the detected_anomalies DataFrame.

    Returns:
        str: Severity level string.
    """
    if row["z_score"] >= 5.0 or row["request_count"] >= 50:
        return "HIGH"
    return "MEDIUM"

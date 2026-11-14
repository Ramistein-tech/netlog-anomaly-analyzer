"""
Module: main.py
Purpose: Command-Line Interface (CLI) orchestrating the end-to-end log generation,
         DSGVO-compliant ingestion, statistical anomaly detection, and report export pipeline.

Usage Examples:
    1. Generate synthetic logs and immediately run anomaly detection:
       python main.py --generate --analyze

    2. Analyze an existing server log file with custom statistical sensitivity:
       python main.py --analyze --log-file data/access.log --window 1min --threshold 2.5
"""

import argparse
import os
import sys
from pathlib import Path

from src.analyzer import analyze_traffic_anomalies
from src.anonymizer import generate_ephemeral_salt
from src.log_generator import generate_synthetic_logs
from src.parser import parse_access_log
from src.reporter import export_reports


def build_cli_parser() -> argparse.ArgumentParser:
    """
    Configure command-line flags and parameter defaults for the pipeline.

    Returns:
        argparse.ArgumentParser: Configured CLI argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="netlog-anomaly-analyzer",
        description="DSGVO-compliant HTTP Access Log Parser & Statistical Anomaly Detection Engine.",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate a synthetic access log dataset with injected attack signatures.",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run the ingestion, pseudonymization, and anomaly detection pipeline.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("data/sample_access.log"),
        help="Path to the target access log file (default: data/sample_access.log).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for exported JSON and CSV reports (default: output/).",
    )
    parser.add_argument(
        "--window",
        type=str,
        default="1min",
        help="Time-series aggregation window (e.g., '30s', '1min', '5min'). Default: '1min'.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=3.0,
        help="Z-Score threshold for volumetric traffic spike detection (default: 3.0).",
    )
    return parser


def resolve_secret_salt() -> bytes:
    """
    Retrieve a persistent salt from the environment variable 'LOG_ANALYZER_SALT' if set,
    otherwise generate an ephemeral cryptographically secure session salt.

    Returns:
        bytes: Secret key for HMAC-SHA256 pseudonymization.
    """
    env_salt: str | None = os.environ.get("LOG_ANALYZER_SALT")
    if env_salt:
        return env_salt.encode("utf-8")
    return generate_ephemeral_salt()


def main() -> int:
    """
    Execute the requested CLI workflow and print structured terminal diagnostics.

    Returns:
        int: POSIX exit status code (0 for success, 1 for operational error).
    """
    parser = build_cli_parser()
    args = parser.parse_args()

    # Require at least one operational action flag
    if not args.generate and not args.analyze:
        parser.print_help()
        return 1

    if args.generate:
        print(f"[1/3] Generating synthetic server logs at: {args.log_file}")
        ground_truth = generate_synthetic_logs(output_path=args.log_file)
        print(f"      Injected {len(ground_truth)} ground-truth attack profiles.")

    if args.analyze:
        print(f"[2/3] Parsing and pseudonymizing logs from: {args.log_file}")
        secret_salt = resolve_secret_salt()

        try:
            df, stats = parse_access_log(
                filepath=args.log_file, secret_salt=secret_salt
            )
        except FileNotFoundError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1

        print(
            f"      Ingestion Summary -> Total: {stats.total_lines} | "
            f"Valid: {stats.parsed_lines} | Malformed: {stats.malformed_lines} "
            f"({stats.parse_success_rate}% quality)"
        )

        print(
            f"[3/3] Running statistical anomaly detection (window={args.window}, Z>={args.threshold})"
        )
        _, anomalies = analyze_traffic_anomalies(
            df=df,
            window=args.window,
            z_threshold=args.threshold,
        )

        json_report, csv_report = export_reports(
            anomalies_df=anomalies,
            stats=stats,
            output_dir=args.output_dir,
            window=args.window,
            z_threshold=args.threshold,
        )

        print(f"\n=== Detected Security Anomalies ({len(anomalies)}) ===")
        if anomalies.empty:
            print("No anomalous traffic patterns exceeded the configured thresholds.")
        else:
            print(anomalies.to_string(index=False))

        print(
            f"\nReports exported successfully:\n  - JSON: {json_report}\n  - CSV:  {csv_report}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Module: parser.py
Purpose: Extracts structured tabular records from unstructured raw web server logs using
         pre-compiled Regular Expressions and enforces immediate IP pseudonymization.

Architectural Rationale:
    In enterprise data analytics pipelines, raw ingestion layers must decouple schema
    validation from downstream statistical modeling. This module:
      1. Uses a pre-compiled named-group RegEx pattern for O(n) single-pass line parsing.
      2. Applies DSGVO-compliant pseudonymization immediately at ingestion time so raw IPs
         never persist in memory structures or downstream DataFrames.
      3. Tracks parsing quality metrics (total lines, valid records, malformed lines) to
         provide full data-lineage transparency.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

from src.anonymizer import pseudonymize_ip

# Pre-compiled Regular Expression matching Nginx/Apache Combined Log Format.
# Named capture groups (?P<name>...) improve maintainability and self-documentation.
COMBINED_LOG_REGEX: re.Pattern[str] = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+HTTP/[\d.]+"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?$'
)


@dataclass(frozen=True)
class IngestionStats:
    """
    Immutable data quality summary produced during raw log ingestion.

    Attributes:
        total_lines (int): Total non-empty lines read from the source file.
        parsed_lines (int): Number of lines matching the expected CLF schema.
        malformed_lines (int): Number of corrupted or unparseable lines skipped.
        parse_success_rate (float): Percentage of valid records (0.0 to 100.0).
    """

    total_lines: int
    parsed_lines: int
    malformed_lines: int

    @property
    def parse_success_rate(self) -> float:
        """Calculate the ratio of successfully parsed log lines as a percentage."""
        if self.total_lines == 0:
            return 0.0
        return round((self.parsed_lines / self.total_lines) * 100.0, 2)


def parse_access_log(
    filepath: Path, secret_salt: bytes
) -> tuple[pd.DataFrame, IngestionStats]:
    """
    Parse a raw web server log file into a clean, typed, and pseudonymized pandas DataFrame.

    Args:
        filepath (Path): Path to the raw server access log file.
        secret_salt (bytes): Cryptographic key passed to the pseudonymization engine.

    Returns:
        tuple[pd.DataFrame, IngestionStats]:
            - A structured DataFrame sorted chronologically by UTC timestamp.
            - An IngestionStats object summarizing schema validation quality.

    Raises:
        FileNotFoundError: If the specified log file does not exist on disk.
    """
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found at specified path: {filepath}")

    structured_records: list[dict[str, object]] = []
    total_lines: int = 0
    malformed_lines: int = 0

    with filepath.open("r", encoding="utf-8", errors="replace") as stream:
        for raw_line in stream:
            stripped_line: str = raw_line.strip()
            if not stripped_line:
                continue

            total_lines += 1
            match: re.Match[str] | None = COMBINED_LOG_REGEX.match(stripped_line)

            if match is None:
                # Track malformed entries instead of crashing the batch ingestion pipeline
                malformed_lines += 1
                continue

            fields: dict[str, str] = match.groupdict()

            try:
                # Parse CLF timestamp string into a timezone-aware Python datetime object
                parsed_ts: datetime = datetime.strptime(
                    fields["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
                )
                # Convert '-' byte indicator (common in HTTP 304 responses) to integer 0
                raw_bytes: str = fields["bytes"]
                byte_count: int = 0 if raw_bytes == "-" else int(raw_bytes)

                structured_records.append(
                    {
                        "client_id": pseudonymize_ip(fields["ip"], secret_salt),
                        "timestamp": parsed_ts,
                        "method": fields["method"],
                        "endpoint": fields["endpoint"],
                        "status": int(fields["status"]),
                        "bytes": byte_count,
                        "user_agent": fields.get("user_agent") or "UNKNOWN",
                    }
                )
            except ValueError:
                # Catch edge cases such as invalid calendar dates (e.g., Feb 30)
                malformed_lines += 1
                continue

    stats = IngestionStats(
        total_lines=total_lines,
        parsed_lines=len(structured_records),
        malformed_lines=malformed_lines,
    )

    if not structured_records:
        empty_df = pd.DataFrame(
            columns=[
                "client_id",
                "timestamp",
                "method",
                "endpoint",
                "status",
                "bytes",
                "user_agent",
            ]
        )
        return empty_df, stats

    df = pd.DataFrame(structured_records)

    # Enforce strict UTC normalization and explicit dtypes for downstream time-series grouping
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["status"] = df["status"].astype("int16")
    df["bytes"] = df["bytes"].astype("int64")
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    return df, stats

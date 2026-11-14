"""
Module: parser.py
Purpose: Extracts structured tabular records from unstructured raw web server logs using
         pre-compiled Regular Expressions and enforces immediate IP pseudonymization.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import pandas as pd

from src.anonymizer import pseudonymize_ip


# 1. Primary RegEx: Nginx / Apache Combined Log Format
COMBINED_LOG_REGEX: re.Pattern[str] = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?$'
)

# 2. Secondary RegEx (A): FastAPI / Uvicorn access logs with leading timestamp
UVICORN_TIMESTAMPED_REGEX: re.Pattern[str] = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?:-\s+\S+\s+-\s+)?'
    r'(?:INFO|WARNING|ERROR|DEBUG):?\s+'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+-\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})(?:\s+.*)?$'
)

# 3. Secondary RegEx (B): Default FastAPI / Uvicorn access logs without timestamp prefix
UVICORN_STANDARD_REGEX: re.Pattern[str] = re.compile(
    r'^(?:INFO|WARNING|ERROR|DEBUG):\s+'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+-\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})(?:\s+.*)?$'
)


@dataclass(frozen=True)
class IngestionStats:
    """Immutable data quality and format-distribution summary produced during log ingestion."""
    total_lines: int
    parsed_lines: int
    malformed_lines: int
    clf_lines: int = 0
    uvicorn_lines: int = 0

    @property
    def parse_success_rate(self) -> float:
        """Calculate the ratio of successfully parsed log lines as a percentage."""
        if self.total_lines == 0:
            return 0.0
        return round((self.parsed_lines / self.total_lines) * 100.0, 2)


def _parse_uvicorn_timestamp(raw_ts: str) -> datetime:
    """Normalize Python logging / ISO-8601 timestamp strings into UTC-aware datetime objects."""
    normalized_str: str = raw_ts.strip().replace(",", ".")
    if normalized_str.endswith("Z"):
        normalized_str = normalized_str[:-1] + "+00:00"

    parsed_dt: datetime = datetime.fromisoformat(normalized_str)
    if parsed_dt.tzinfo is None:
        return parsed_dt.replace(tzinfo=timezone.utc)
    return parsed_dt.astimezone(timezone.utc)


def _extract_line_record(
    line: str,
    secret_salt: bytes,
    default_timestamp: datetime,
) -> tuple[dict[str, object], str] | None:
    """Attempt to parse a single raw log line across supported schemas in priority order."""
    clf_match: re.Match[str] | None = COMBINED_LOG_REGEX.match(line)
    if clf_match is not None:
        fields = clf_match.groupdict()
        parsed_ts = datetime.strptime(fields["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        raw_bytes = fields["bytes"]
        byte_count = 0 if raw_bytes == "-" else int(raw_bytes)

        return (
            {
                "client_id": pseudonymize_ip(fields["ip"], secret_salt),
                "timestamp": parsed_ts,
                "method": fields["method"],
                "endpoint": fields["endpoint"],
                "status": int(fields["status"]),
                "bytes": byte_count,
                "user_agent": fields.get("user_agent") or "UNKNOWN",
            },
            "CLF",
        )

    uv_ts_match: re.Match[str] | None = UVICORN_TIMESTAMPED_REGEX.match(line)
    if uv_ts_match is not None:
        fields = uv_ts_match.groupdict()
        parsed_ts = _parse_uvicorn_timestamp(fields["timestamp"])

        return (
            {
                "client_id": pseudonymize_ip(fields["ip"], secret_salt),
                "timestamp": parsed_ts,
                "method": fields["method"],
                "endpoint": fields["endpoint"],
                "status": int(fields["status"]),
                "bytes": 0,
                "user_agent": "Uvicorn/ASGI",
            },
            "UVICORN",
        )

    uv_std_match: re.Match[str] | None = UVICORN_STANDARD_REGEX.match(line)
    if uv_std_match is not None:
        fields = uv_std_match.groupdict()

        return (
            {
                "client_id": pseudonymize_ip(fields["ip"], secret_salt),
                "timestamp": default_timestamp,
                "method": fields["method"],
                "endpoint": fields["endpoint"],
                "status": int(fields["status"]),
                "bytes": 0,
                "user_agent": "Uvicorn/ASGI",
            },
            "UVICORN",
        )

    return None


def parse_access_log(
    filepath: Path,
    secret_salt: bytes,
    fallback_timestamp: datetime | None = None,
) -> tuple[pd.DataFrame, IngestionStats]:
    """Parse a raw web server log file (Nginx/Apache or FastAPI/Uvicorn) into a clean DataFrame."""
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found at specified path: {filepath}")

    batch_default_ts: datetime = fallback_timestamp or datetime.now(timezone.utc)
    if batch_default_ts.tzinfo is None:
        batch_default_ts = batch_default_ts.replace(tzinfo=timezone.utc)

    structured_records: list[dict[str, object]] = []
    total_lines: int = 0
    malformed_lines: int = 0
    clf_count: int = 0
    uvicorn_count: int = 0

    with filepath.open("r", encoding="utf-8", errors="replace") as stream:
        for raw_line in stream:
            stripped_line: str = raw_line.strip()
            if not stripped_line:
                continue

            total_lines += 1

            try:
                extraction = _extract_line_record(
                    line=stripped_line,
                    secret_salt=secret_salt,
                    default_timestamp=batch_default_ts,
                )
            except ValueError:
                malformed_lines += 1
                continue

            if extraction is None:
                malformed_lines += 1
                continue

            record, format_tag = extraction
            structured_records.append(record)

            if format_tag == "CLF":
                clf_count += 1
            elif format_tag == "UVICORN":
                uvicorn_count += 1

    stats = IngestionStats(
        total_lines=total_lines,
        parsed_lines=len(structured_records),
        malformed_lines=malformed_lines,
        clf_lines=clf_count,
        uvicorn_lines=uvicorn_count,
    )

    if not structured_records:
        empty_df = pd.DataFrame(
            columns=["client_id", "timestamp", "method", "endpoint", "status", "bytes", "user_agent"]
        )
        return empty_df, stats

    df = pd.DataFrame(structured_records)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["status"] = df["status"].astype("int16")
    df["bytes"] = df["bytes"].astype("int64")
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    return df, stats

"""
Module: test_analyzer.py
Purpose: Automated unit test suite verifying cryptographic pseudonymization invariants,
         multi-format RegEx log parsing (Nginx/Apache & FastAPI/Uvicorn), and hybrid
         statistical/behavioral anomaly detection (Brute-Force, Recon, Volumetric, Rate-Limit).
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.analyzer import analyze_traffic_anomalies
from src.anonymizer import generate_ephemeral_salt, pseudonymize_ip
from src.log_generator import generate_synthetic_logs
from src.parser import parse_access_log


def test_pseudonymization_is_deterministic_and_salted() -> None:
    """Verify identical IPs produce identical hashes under the same salt, but distinct under different salts."""
    salt_a = b"secret_salt_alpha_1234567890"
    salt_b = b"secret_salt_bravo_0987654321"
    target_ip = "203.0.113.42"

    token_a1 = pseudonymize_ip(target_ip, salt_a)
    token_a2 = pseudonymize_ip(target_ip, salt_a)
    token_b = pseudonymize_ip(target_ip, salt_b)

    assert token_a1 == token_a2
    assert token_a1 != token_b
    assert target_ip not in token_a1
    assert token_a1.startswith("client_")


def test_pseudonymization_rejects_invalid_inputs() -> None:
    """Verify strict input validation against empty IPs or missing cryptographic salts."""
    with pytest.raises(ValueError):
        pseudonymize_ip("", b"valid_salt")

    with pytest.raises(ValueError):
        pseudonymize_ip("192.168.1.1", b"")


def test_end_to_end_synthetic_detection(tmp_path: Path) -> None:
    """Verify the complete pipeline from log generation through parsing to attack classification."""
    log_path = tmp_path / "test_access.log"
    salt = generate_ephemeral_salt()

    ground_truth = generate_synthetic_logs(output_path=log_path, normal_events=800, seed=101)
    assert len(ground_truth) == 3

    df, stats = parse_access_log(filepath=log_path, secret_salt=salt)
    assert stats.malformed_lines == 2
    assert stats.parsed_lines == 800 + 65 + 55 + 95
    assert stats.clf_lines == stats.parsed_lines
    assert stats.uvicorn_lines == 0
    assert "client_id" in df.columns

    _, anomalies = analyze_traffic_anomalies(df=df, window="1min", z_threshold=3.0)
    assert not anomalies.empty

    detected_classes = set(anomalies["threat_classification"].unique())
    assert "CREDENTIAL_BRUTE_FORCE" in detected_classes
    assert "DIRECTORY_ENUMERATION" in detected_classes
    assert "VOLUMETRIC_TRAFFIC_SPIKE" in detected_classes


def test_fastapi_uvicorn_log_parsing_and_port_stripping(tmp_path: Path) -> None:
    """Verify FastAPI/Uvicorn parsing, ephemeral TCP source port stripping, and mixed CLF/Uvicorn logs."""
    log_path = tmp_path / "uvicorn_mixed.log"
    salt = b"unit_test_uvicorn_salt_2026"
    fixed_fallback_ts = datetime(2026, 11, 14, 18, 30, 0, tzinfo=timezone.utc)

    sample_lines = [
        '10.0.0.12 - - [14/Nov/2026:18:30:01 +0000] "GET /health HTTP/1.1" 200 42 "-" "curl/8.10"',
        '2026-11-14 18:30:05,120 INFO:     198.51.100.88:51001 - "POST /api/v1/login HTTP/1.1" 401 Unauthorized',
        'INFO:     198.51.100.88:51002 - "POST /api/v1/login HTTP/1.1" 401 Unauthorized',
        'INFO:     198.51.100.88:51003 - "POST /api/v1/login HTTP/1.1" 401 Unauthorized',
        'INVALID_UVICORN_GARBAGE_LINE',
    ]
    log_path.write_text("\n".join(sample_lines) + "\n", encoding="utf-8")

    df, stats = parse_access_log(
        filepath=log_path,
        secret_salt=salt,
        fallback_timestamp=fixed_fallback_ts,
    )

    assert stats.total_lines == 5
    assert stats.parsed_lines == 4
    assert stats.malformed_lines == 1
    assert stats.clf_lines == 1
    assert stats.uvicorn_lines == 3

    expected_attacker_token = pseudonymize_ip("198.51.100.88", salt)
    uvicorn_rows = df[df["user_agent"] == "Uvicorn/ASGI"]
    assert len(uvicorn_rows) == 3
    assert set(uvicorn_rows["client_id"].unique()) == {expected_attacker_token}


def test_uvicorn_end_to_end_anomaly_detection(tmp_path: Path) -> None:
    """Verify that a brute-force burst in FastAPI/Uvicorn logs triggers CREDENTIAL_BRUTE_FORCE."""
    log_path = tmp_path / "uvicorn_attack.log"
    salt = generate_ephemeral_salt()

    lines: list[str] = []
    for i in range(1, 11):
        lines.append(
            f'2026-11-14 19:00:10,000 INFO:     10.10.0.{i}:4000{i} - "GET /api/v1/nlp/status HTTP/1.1" 200 OK'
        )
    for port_offset in range(25):
        lines.append(
            f'2026-11-14 19:00:{15 + port_offset:02d},500 INFO:     203.0.113.99:{52000 + port_offset} '
            f'- "POST /api/v1/auth/token HTTP/1.1" 401 Unauthorized'
        )

    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    df, stats = parse_access_log(filepath=log_path, secret_salt=salt)
    assert stats.uvicorn_lines == 35
    assert stats.malformed_lines == 0

    _, anomalies = analyze_traffic_anomalies(df=df, window="1min", z_threshold=2.5)
    assert len(anomalies) == 1
    assert anomalies.iloc[0]["threat_classification"] == "CREDENTIAL_BRUTE_FORCE"
    assert anomalies.iloc[0]["request_count"] == 25


def test_rate_limit_abuse_detection_429(tmp_path: Path) -> None:
    """Verify that repeated HTTP 429 Too Many Requests responses are classified as RATE_LIMIT_ABUSE."""
    log_path = tmp_path / "rate_limit_abuse.log"
    salt = b"unit_test_rate_limit_salt_2026"

    lines: list[str] = []
    for idx in range(1, 8):
        lines.append(
            f'2026-11-14 19:10:0{idx},100 INFO:     10.20.0.{idx}:3100{idx} - "POST /api/v1/tokenize HTTP/1.1" 200 OK'
        )
        lines.append(
            f'2026-11-14 19:10:1{idx},200 INFO:     10.20.0.{idx}:3101{idx} - "POST /api/v1/tokenize HTTP/1.1" 200 OK'
        )

    # Regular user hitting the 5/min quota twice (should NOT trigger an alert)
    for req_idx in range(7):
        status_text = "200 OK" if req_idx < 5 else "429 Too Many Requests"
        lines.append(
            f'2026-11-14 19:10:{10 + req_idx:02d},150 INFO:     10.20.0.50:{41000 + req_idx} '
            f'- "POST /api/v1/tokenize HTTP/1.1" {status_text}'
        )

    # Abusive client triggering 10 HTTP 429 rejections after 5 allowed requests
    for req_idx in range(15):
        status_text = "200 OK" if req_idx < 5 else "429 Too Many Requests"
        lines.append(
            f'2026-11-14 19:10:{20 + req_idx:02d},300 INFO:     198.51.100.200:{60000 + req_idx} '
            f'- "POST /api/v1/tokenize HTTP/1.1" {status_text}'
        )

    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    df, stats = parse_access_log(filepath=log_path, secret_salt=salt)
    assert stats.parsed_lines == 36
    assert stats.malformed_lines == 0

    _, anomalies = analyze_traffic_anomalies(df=df, window="1min", z_threshold=3.0)
    assert len(anomalies) == 1

    incident = anomalies.iloc[0]
    assert incident["client_id"] == pseudonymize_ip("198.51.100.200", salt)
    assert incident["request_count"] == 15
    assert incident["rate_limit_errors"] == 10
    assert incident["threat_classification"] == "RATE_LIMIT_ABUSE"
    assert incident["severity"] == "MEDIUM"

"""
Module: test_analyzer.py
Purpose: Automated unit test suite verifying cryptographic pseudonymization invariants,
         RegEx log parsing resilience, and statistical anomaly detection accuracy.
"""

from pathlib import Path

import pytest

from src.analyzer import analyze_traffic_anomalies
from src.anonymizer import generate_ephemeral_salt, pseudonymize_ip
from src.log_generator import generate_synthetic_logs
from src.parser import parse_access_log


def test_pseudonymization_is_deterministic_and_salted() -> None:
    """Verify that identical IPs produce identical hashes under the same salt,
    but completely different hashes under distinct salts (preventing rainbow-table attacks)."""
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

    # Generate dataset with 3 known ground-truth attackers
    ground_truth = generate_synthetic_logs(
        output_path=log_path, normal_events=800, seed=101
    )
    assert len(ground_truth) == 3

    # Parse logs and verify malformed lines are gracefully isolated
    df, stats = parse_access_log(filepath=log_path, secret_salt=salt)
    assert stats.malformed_lines == 2
    assert stats.parsed_lines == 800 + 65 + 55 + 95
    assert "client_id" in df.columns

    # Run anomaly detection and confirm all 3 injected threat categories are identified
    _, anomalies = analyze_traffic_anomalies(df=df, window="1min", z_threshold=3.0)
    assert not anomalies.empty

    detected_classes = set(anomalies["threat_classification"].unique())
    assert "CREDENTIAL_BRUTE_FORCE" in detected_classes
    assert "DIRECTORY_ENUMERATION" in detected_classes
    assert "VOLUMETRIC_TRAFFIC_SPIKE" in detected_classes

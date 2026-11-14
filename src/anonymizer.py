"""
Module: anonymizer.py
Purpose: Implements cryptographic pseudonymization for IPv4/IPv6 addresses in compliance
         with the European General Data Protection Regulation (GDPR / DSGVO Art. 4(5) & Art. 32).

Architectural Rationale:
    Raw IP addresses constitute Personally Identifiable Information (PII) under EU law.
    Standard unsalted hashing (e.g., plain SHA-256) is insufficient for IPv4 addresses because
    the entire 32-bit address space (~4.29 billion addresses) can be reversed via precomputed
    rainbow tables in seconds. By using Keyed-Hash Message Authentication Code (HMAC-SHA256)
    with a cryptographically secure secret salt, we achieve:
      1. Irreversibility without access to the secret salt.
      2. Deterministic mapping within a single analytical session (enabling behavioral aggregation
         per client without exposing the underlying identity).
"""

import hashlib
import hmac
import os


def generate_ephemeral_salt(num_bytes: int = 32) -> bytes:
    """
    Generate a cryptographically secure random byte sequence for session-level HMAC keying.

    Args:
        num_bytes (int): Length of the secret key in bytes. Defaults to 32 bytes (256 bits),
                         matching the internal block security of SHA-256.

    Returns:
        bytes: Cryptographically secure random bytes sourced from the OS entropy pool (/dev/urandom).
    """
    return os.urandom(num_bytes)


def pseudonymize_ip(ip_address: str, secret_salt: bytes) -> str:
    """
    Transform a raw IP address into a fixed-length, non-reversible pseudonymous identifier.

    Args:
        ip_address (str): The raw client IP address extracted from the server access log
                          (e.g., '192.168.1.42').
        secret_salt (bytes): Secret cryptographic key used to seed the HMAC function.

    Returns:
        str: A prefixed 16-character hexadecimal identifier (e.g., 'client_9f8a2b1c4d7e6031').

    Raises:
        ValueError: If the IP address is empty or the secret salt is not provided as bytes.
    """
    # Validate inputs strictly to prevent silent fallback to unkeyed or empty hashes
    if not ip_address or not isinstance(ip_address, str):
        raise ValueError("Invalid IP address provided for pseudonymization.")
    if not secret_salt or not isinstance(secret_salt, bytes):
        raise ValueError("A non-empty byte-string secret_salt is required for HMAC.")

    # Normalize whitespace to ensure identical IPs always produce identical HMAC digests
    normalized_ip: bytes = ip_address.strip().encode("utf-8")

    # Compute the full 256-bit HMAC-SHA256 digest using constant-time cryptographic primitives
    full_digest: str = hmac.new(
        key=secret_salt,
        msg=normalized_ip,
        digestmod=hashlib.sha256,
    ).hexdigest()

    # Truncate to 16 hex characters (64 bits) for readable reporting while keeping
    # collision probability negligible for standard log batch sizes
    return f"client_{full_digest[:16]}"

"""
Module: log_generator.py
Purpose: Generates realistic synthetic web server access logs (Nginx/Apache Combined Log Format)
         containing both baseline legitimate user traffic and injected cyberattack patterns.

Architectural Rationale:
    Testing anomaly detection algorithms requires reproducible ground-truth datasets without
    exposing real production infrastructure logs. This generator simulates:
      - Normal User Behavior: Distributed HTTP 200/304 requests across public endpoints.
      - Attack Scenario A (Credential Brute-Force): High-frequency POST requests targeting
        '/api/v1/auth/login' resulting in HTTP 401 Unauthorized responses.
      - Attack Scenario B (Directory Enumeration / Recon): Rapid sequential GET probes
        against sensitive configuration endpoints ('/.env', '/admin', '/.git/config')
        resulting in HTTP 403/404 responses.
      - Attack Scenario C (Volumetric Traffic Spike / DoS Probe): Sudden burst of requests
        exceeding baseline statistical variance within a 1-minute window.
"""

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Baseline realistic endpoints accessed by regular web application users
NORMAL_ENDPOINTS: list[str] = [
    "/",
    "/index.html",
    "/about",
    "/products",
    "/products/analytics-suite",
    "/api/v1/projects",
    "/api/v1/status",
    "/assets/css/main.css",
    "/assets/js/app.bundle.js",
    "/documentation",
]

# Sensitive endpoints typically targeted during automated vulnerability scanning
PROBE_ENDPOINTS: list[str] = [
    "/.env",
    "/.git/config",
    "/admin",
    "/admin/login",
    "/wp-login.php",
    "/phpmyadmin/",
    "/api/v1/internal/debug",
    "/server-status",
    "/backup.sql.gz",
    "/config.php.bak",
]

# Realistic User-Agent strings distinguishing standard browsers from automated CLI tools
BROWSER_AGENTS: list[str] = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/605.1.15",
]

SCANNER_AGENTS: list[str] = [
    "python-requests/2.32.3",
    "Gobuster/3.6",
    "curl/8.10.1",
]


def _format_log_entry(
    ip: str,
    timestamp: datetime,
    method: str,
    endpoint: str,
    status: int,
    response_bytes: int,
    user_agent: str,
) -> str:
    """
    Format individual event attributes into a standard Combined Log Format line.

    Args:
        ip (str): Source IPv4 address.
        timestamp (datetime): UTC-aware datetime object of the HTTP request.
        method (str): HTTP verb (GET, POST, etc.).
        endpoint (str): Requested URI path.
        status (int): HTTP response status code (e.g., 200, 401, 404).
        response_bytes (int): Size of the HTTP response payload in bytes.
        user_agent (str): HTTP User-Agent header string.

    Returns:
        str: Formatted single log line terminated without a trailing newline.
    """
    # Standard CLF timestamp format: [14/Nov/2026:16:00:00 +0000]
    formatted_ts: str = timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")
    return (
        f'{ip} - - [{formatted_ts}] "{method} {endpoint} HTTP/1.1" '
        f'{status} {response_bytes} "-" "{user_agent}"'
    )


def generate_synthetic_logs(
    output_path: Path,
    normal_events: int = 1200,
    seed: int = 42,
) -> dict[str, str]:
    """
    Generate a complete synthetic log file with deterministic ground-truth attack actors.

    Args:
        output_path (Path): Destination file path where the generated .log file will be written.
        normal_events (int): Number of legitimate baseline requests to simulate across 15 minutes.
        seed (int): Random seed ensuring reproducible benchmark datasets across runs.

    Returns:
        dict[str, str]: Ground-truth mapping of simulated attacker IPs to their attack categories,
                        useful for validation and auditing.
    """
    rng = random.Random(seed)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Establish a fixed reference start time in UTC
    base_time = datetime(2026, 11, 14, 14, 0, 0, tzinfo=UTC)
    log_entries: list[tuple[datetime, str]] = []

    # 1. Generate a pool of 45 legitimate client IP addresses
    legitimate_ips: list[str] = [f"10.24.10.{i}" for i in range(10, 55)]

    for _ in range(normal_events):
        # Spread normal requests across a 15-minute (900-second) observation window
        offset_seconds: int = rng.randint(0, 899)
        event_time: datetime = base_time + timedelta(seconds=offset_seconds)
        client_ip: str = rng.choice(legitimate_ips)
        endpoint: str = rng.choice(NORMAL_ENDPOINTS)
        status: int = rng.choices([200, 304, 404], weights=[0.88, 0.09, 0.03])[0]
        payload_size: int = rng.randint(512, 65536)
        agent: str = rng.choice(BROWSER_AGENTS)

        line = _format_log_entry(
            client_ip, event_time, "GET", endpoint, status, payload_size, agent
        )
        log_entries.append((event_time, line))

    # 2. Inject Attack Scenario A: Credential Brute-Force (Minute 05:00 - 05:45)
    brute_force_ip = "185.220.101.45"
    for i in range(65):
        event_time = base_time + timedelta(minutes=5, seconds=rng.randint(0, 45))
        line = _format_log_entry(
            ip=brute_force_ip,
            timestamp=event_time,
            method="POST",
            endpoint="/api/v1/auth/login",
            status=401,
            response_bytes=248,
            user_agent="python-requests/2.32.3",
        )
        log_entries.append((event_time, line))

    # 3. Inject Attack Scenario B: Directory Enumeration / Recon Scan (Minute 09:10 - 09:50)
    scanner_ip = "45.155.205.99"
    for i in range(55):
        event_time = base_time + timedelta(minutes=9, seconds=rng.randint(10, 50))
        probe_target = rng.choice(PROBE_ENDPOINTS)
        status_code = 403 if ".git" in probe_target or ".env" in probe_target else 404
        line = _format_log_entry(
            ip=scanner_ip,
            timestamp=event_time,
            method="GET",
            endpoint=probe_target,
            status=status_code,
            response_bytes=192,
            user_agent="Gobuster/3.6",
        )
        log_entries.append((event_time, line))

    # 4. Inject Attack Scenario C: Volumetric API Flood (Minute 12:00 - 12:40)
    flood_ip = "91.132.147.12"
    for i in range(95):
        event_time = base_time + timedelta(minutes=12, seconds=rng.randint(0, 40))
        line = _format_log_entry(
            ip=flood_ip,
            timestamp=event_time,
            method="GET",
            endpoint="/api/v1/projects",
            status=200,
            response_bytes=4096,
            user_agent="curl/8.10.1",
        )
        log_entries.append((event_time, line))

    # Inject 5 intentionally malformed log lines to test parser resilience & data quality metrics
    malformed_samples: list[tuple[datetime, str]] = [
        (base_time + timedelta(minutes=2), "CORRUPTED_RAW_LINE_WITHOUT_CLF_STRUCTURE"),
        (
            base_time + timedelta(minutes=7),
            '999.999.999.999 - - [INVALID_DATE] "BAD" 000 -',
        ),
    ]
    log_entries.extend(malformed_samples)

    # Sort chronologically to mirror real append-only server log files
    log_entries.sort(key=lambda item: item[0])

    with output_path.open("w", encoding="utf-8") as log_file:
        for _, formatted_line in log_entries:
            log_file.write(formatted_line + "\n")

    return {
        brute_force_ip: "CREDENTIAL_BRUTE_FORCE",
        scanner_ip: "DIRECTORY_ENUMERATION",
        flood_ip: "VOLUMETRIC_TRAFFIC_SPIKE",
    }

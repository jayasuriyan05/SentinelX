from datetime import datetime


# ============================================================
# SENSITIVE FILE / PATH KEYWORDS
# ============================================================

SENSITIVE_PATHS = [
    "password",
    "credential",
    "secret",
    "admin",
    "system32",
    "sam",
    "ntds.dit",
    "ssh",
    ".env"
]


# ============================================================
# FILE ACCESS DETECTION
# ============================================================

def detect_file_access(events):

    if not events:
        return None

    latest_event = events[-1]

    event_type = getattr(
        latest_event,
        "event_type",
        ""
    )

    if event_type not in [
        "FILE_ACCESS",
        "SUSPICIOUS_FILE_ACCESS"
    ]:
        return None

    details = getattr(
        latest_event,
        "details",
        ""
    ) or ""

    details_lower = str(details).lower()

    matched_paths = [
        path
        for path in SENSITIVE_PATHS
        if path.lower() in details_lower
    ]

    source_ip = getattr(
        latest_event,
        "source_ip",
        "Unknown"
    )

    hostname = getattr(
        latest_event,
        "hostname",
        "Unknown"
    )

    # --------------------------------------------------------
    # SUSPICIOUS FILE ACCESS
    # --------------------------------------------------------

    if matched_paths:

        return {
            "alert_type": "SUSPICIOUS_FILE_ACCESS",
            "severity": "HIGH",
            "description": (
                "Suspicious access to sensitive file detected "
                f"from {source_ip}. "
                f"Matched: {', '.join(matched_paths)}"
            ),
            "mitre_technique": "T1005",
            "risk_score": 75,
            "source_ip": source_ip,
            "hostname": hostname,
            "timestamp": datetime.now(),
            "matched_paths": matched_paths
        }

    # --------------------------------------------------------
    # NORMAL FILE ACCESS
    # --------------------------------------------------------

    return {
        "alert_type": "FILE_ACCESS",
        "severity": "MEDIUM",
        "description": (
            f"File access activity detected from {source_ip}"
        ),
        "mitre_technique": "T1005",
        "risk_score": 40,
        "source_ip": source_ip,
        "hostname": hostname,
        "timestamp": datetime.now()
    }


# ============================================================
# DIRECT FILE PATH DETECTION
# ============================================================

def detect_suspicious_file_access(file_path):

    if not file_path:
        return None

    path_lower = str(file_path).lower()

    matched_paths = [
        path
        for path in SENSITIVE_PATHS
        if path.lower() in path_lower
    ]

    if not matched_paths:
        return None

    return {
        "alert_type": "SUSPICIOUS_FILE_ACCESS",
        "severity": "HIGH",
        "description": (
            f"Suspicious file access detected: {file_path}"
        ),
        "mitre_technique": "T1005",
        "risk_score": 75,
        "matched_paths": matched_paths,
        "timestamp": datetime.now()
    }

from datetime import datetime


BRUTE_FORCE_THRESHOLD = 5


def detect_bruteforce(events):
    """
    Detect multiple failed login attempts from the same source IP.
    """

    if not events:
        return None

    failed_events = [
        event
        for event in events
        if getattr(event, "event_type", "") == "FAILED_LOGIN"
    ]

    if len(failed_events) >= BRUTE_FORCE_THRESHOLD:
        source_ip = getattr(
            failed_events[-1],
            "source_ip",
            "Unknown"
        )

        hostname = getattr(
            failed_events[-1],
            "hostname",
            "Unknown"
        )

        return {
            "alert_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "description": (
                f"Multiple failed login attempts detected "
                f"from {source_ip}"
            ),
            "mitre_technique": "T1110",
            "risk_score": 80,
            "source_ip": source_ip,
            "hostname": hostname,
            "timestamp": datetime.now()
        }

    return None


def detect_brute_force(events):
    """
    Alias for compatibility with different function names.
    """

    return detect_bruteforce(events)

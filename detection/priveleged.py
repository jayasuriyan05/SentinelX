from datetime import datetime


# ============================================================
# PRIVILEGED EVENT TYPES
# ============================================================

PRIVILEGED_EVENT_TYPES = [
    "PRIVILEGED_ACTIVITY",
    "ADMIN_ACTIVITY",
    "PRIVILEGE_ESCALATION"
]


# ============================================================
# PRIVILEGED ACTIVITY DETECTION
# ============================================================

def detect_privileged_activity(events):

    if not events:
        return None

    privileged_events = [
        event
        for event in events
        if getattr(event, "event_type", "")
        in PRIVILEGED_EVENT_TYPES
    ]

    if not privileged_events:
        return None

    latest_event = privileged_events[-1]

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

    username = getattr(
        latest_event,
        "username",
        "Unknown"
    )

    return {
        "alert_type": "PRIVILEGED_ACTIVITY",
        "severity": "HIGH",
        "description": (
            f"Privileged activity detected for user "
            f"{username} from {source_ip}"
        ),
        "mitre_technique": "T1078",
        "risk_score": 75,
        "source_ip": source_ip,
        "hostname": hostname,
        "timestamp": datetime.now()
    }


# ============================================================
# ALIAS
# ============================================================

def detect_privileged(events):
    return detect_privileged_activity(events)

from datetime import datetime


def detect_portscan(events):
    """
    Detect possible port scanning activity.
    """

    if not events:
        return None

    port_scan_events = [
        event
        for event in events
        if getattr(event, "event_type", "") == "PORT_SCAN"
    ]

    if not port_scan_events:
        return None

    latest_event = port_scan_events[-1]

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

    return {
        "alert_type": "PORT_SCAN",
        "severity": "HIGH",
        "description": (
            f"Possible port scanning activity detected "
            f"from {source_ip}"
        ),
        "mitre_technique": "T1046",
        "risk_score": 70,
        "source_ip": source_ip,
        "hostname": hostname,
        "timestamp": datetime.now()
    }


def detect_port_scan(events):
    """
    Alias for compatibility.
    """

    return detect_portscan(events)

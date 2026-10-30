from datetime import datetime


def correlate_attack_chain(events):
    """
    Correlate multiple security events into a single attack chain.
    """

    if not events:
        return None

    event_types = [
        getattr(event, "event_type", "")
        for event in events
    ]

    attack_steps = []

    if "FAILED_LOGIN" in event_types:
        attack_steps.append("Brute Force / Failed Login Attempts")

    if "SUCCESSFUL_LOGIN" in event_types:
        attack_steps.append("Successful Login")

    if "POWERSHELL" in event_types:
        attack_steps.append("PowerShell Activity")

    if "SUSPICIOUS_POWERSHELL" in event_types:
        attack_steps.append("Suspicious PowerShell Activity")

    if "PRIVILEGED_ACTIVITY" in event_types:
        attack_steps.append("Privileged Activity")

    if "FILE_ACCESS" in event_types:
        attack_steps.append("File Access")

    if "SUSPICIOUS_FILE_ACCESS" in event_types:
        attack_steps.append("Suspicious File Access")

    if "PORT_SCAN" in event_types:
        attack_steps.append("Port Scanning")

    if not attack_steps:
        return None

    source_ip = getattr(
        events[-1],
        "source_ip",
        "Unknown"
    )

    hostname = getattr(
        events[-1],
        "hostname",
        "Unknown"
    )

    # Calculate risk based on the number of attack stages.
    risk_score = min(
        100,
        len(attack_steps) * 20
    )

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "title": "Correlated Attack Chain Detected",
        "description": (
            "Multiple related security activities were "
            "correlated into a possible attack chain: "
            + " -> ".join(attack_steps)
        ),
        "severity": severity,
        "risk_score": risk_score,
        "status": "Open",
        "source_ip": source_ip,
        "hostname": hostname,
        "attack_steps": attack_steps,
        "timestamp": datetime.now()
    }


def correlate_events(events):
    """
    Alias for compatibility.
    """

    return correlate_attack_chain(events)

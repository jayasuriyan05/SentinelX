from datetime import datetime


SUSPICIOUS_PATTERNS = [
    "-encodedcommand",
    "-enc",
    "invoke-expression",
    "iex",
    "downloadstring",
    "frombase64string",
    "invoke-webrequest",
    "iwr",
    "start-process",
    "bypass",
    "executionpolicy",
]


def detect_suspicious_powershell(command):
    """
    Detect suspicious PowerShell command patterns.

    This function only analyzes the command as text.
    It does not execute the command.
    """

    if not command:
        return None

    command_lower = command.lower()

    matched_patterns = [
        pattern
        for pattern in SUSPICIOUS_PATTERNS
        if pattern in command_lower
    ]

    if not matched_patterns:
        return None

    return {
        "alert_type": "SUSPICIOUS_POWERSHELL",
        "severity": "HIGH",
        "description": (
            "Suspicious PowerShell activity detected. "
            f"Matched pattern(s): {', '.join(matched_patterns)}"
        ),
        "mitre_technique": "T1059.001",
        "risk_score": 75,
        "timestamp": datetime.now(),
        "matched_patterns": matched_patterns,
    }


def detect_powershell(command):
    """
    Alias for compatibility.
    """

    return detect_suspicious_powershell(command)

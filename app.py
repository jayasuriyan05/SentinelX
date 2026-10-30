from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    redirect,
    url_for,
    session
)

from datetime import datetime
from collections import Counter
import os
import sys
import io

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ============================================================
# DATABASE
# ============================================================

from database.db import db, SecurityEvent, Alert, Incident


# ============================================================
# DETECTION MODULES
# ============================================================

from detection.bruteforce import detect_bruteforce
from detection.portscan import detect_portscan
from detection.powershell import detect_suspicious_powershell
from detection.file_access import detect_suspicious_file_access
from detection.privileged import detect_privileged_activity

from correlation.engine import correlate_attack_chain


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = "sentinelx-demo-secret-key"

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(BASE_DIR, "sentinel.db")
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

with app.app_context():
    db.create_all()


# ============================================================
# DEMO SETTINGS
# ============================================================

DEFAULT_ATTACKER_IP = "192.168.1.50"
DEFAULT_TARGET_IP = "192.168.1.100"
DEFAULT_USERNAME = "administrator"
DEFAULT_HOSTNAME = "WIN-VICTIM"

# Demo login credentials
LOGIN_USERNAME = "admin"
LOGIN_PASSWORD = "sentinelx"

# Login lockout threshold
LOGIN_LOCKOUT_THRESHOLD = 5

# Stores login attempts for the current Flask application
login_attempts = {}

# Existing simulation counter
failed_login_counter = {}


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

MITRE_MAPPING = {
    "BRUTE_FORCE": "T1110",
    "ACCOUNT_LOCKOUT": "T1110",
    "POWERSHELL": "T1059.001",
    "SUSPICIOUS_POWERSHELL": "T1059.001",
    "PRIVILEGED_ACTIVITY": "T1078",
    "ADMIN_ACTIVITY": "T1078",
    "PRIVILEGE_ESCALATION": "T1078",
    "FILE_ACCESS": "T1005",
    "SUSPICIOUS_FILE_ACCESS": "T1005",
    "PORT_SCAN": "T1046",
}


# ============================================================
# AUTHENTICATION HELPER
# ============================================================

def login_required():
    return session.get("logged_in") is True


def get_client_identifier():
    """
    Identifies the login source for the demo lockout.
    Uses the client IP address.
    """
    return request.remote_addr or "127.0.0.1"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_mitre_mapping(alert_type):
    return MITRE_MAPPING.get(alert_type, "N/A")


def severity_value(severity):
    values = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    return values.get(str(severity).upper(), 0)


def create_event(
    event_type,
    source_ip=None,
    destination_ip=None,
    username=None,
    hostname=None,
    details=None
):
    event = SecurityEvent(
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        hostname=hostname,
        details=details,
        timestamp=datetime.now()
    )

    db.session.add(event)
    db.session.commit()

    return event


def create_alert(
    alert_type,
    severity="MEDIUM",
    description="",
    mitre_technique=None,
    risk_score=0,
    status="New",
    source_ip=None,
    hostname=None
):
    if mitre_technique is None:
        mitre_technique = get_mitre_mapping(alert_type)

    alert = Alert(
        alert_type=alert_type,
        severity=severity,
        description=description,
        mitre_technique=mitre_technique,
        risk_score=risk_score,
        status=status,
        source_ip=source_ip,
        hostname=hostname,
        timestamp=datetime.now()
    )

    db.session.add(alert)
    db.session.commit()

    return alert


def create_incident(
    title,
    description,
    severity="HIGH",
    risk_score=0,
    status="Open",
    source_ip=None,
    hostname=None
):
    incident = Incident(
        title=title,
        description=description,
        severity=severity,
        risk_score=risk_score,
        status=status,
        source_ip=source_ip,
        hostname=hostname,
        timestamp=datetime.now()
    )

    db.session.add(incident)
    db.session.commit()

    return incident


def serialize_event(event):
    return {
        "id": event.id,
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "username": event.username,
        "hostname": event.hostname,
        "details": event.details,
        "timestamp": (
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if event.timestamp else ""
        )
    }


def serialize_alert(alert):
    return {
        "id": alert.id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "description": alert.description,
        "mitre_technique": alert.mitre_technique,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "source_ip": alert.source_ip,
        "hostname": alert.hostname,
        "timestamp": (
            alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if alert.timestamp else ""
        )
    }


def serialize_incident(incident):
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "source_ip": incident.source_ip,
        "hostname": incident.hostname,
        "timestamp": (
            incident.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if incident.timestamp else ""
        )
    }


# ============================================================
# LOGIN PAGE
# ============================================================

@app.route("/")
def index():

    if login_required():
        return redirect(url_for("attack_simulation"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    client_id = get_client_identifier()

    # --------------------------------------------------------
    # CHECK LOCKOUT
    # --------------------------------------------------------

    current_attempts = login_attempts.get(client_id, 0)

    if current_attempts >= LOGIN_LOCKOUT_THRESHOLD:

        return render_template(
            "login.html",
            error="Account locked due to multiple failed login attempts.",
            locked=True,
            attempts=current_attempts,
            lockout_threshold=LOGIN_LOCKOUT_THRESHOLD
        )


    # --------------------------------------------------------
    # LOGIN REQUEST
    # --------------------------------------------------------

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()


        # ----------------------------------------------------
        # SUCCESSFUL LOGIN
        # ----------------------------------------------------

        if (
            username == LOGIN_USERNAME
            and password == LOGIN_PASSWORD
        ):

            # Reset attempts after successful login
            login_attempts[client_id] = 0

            session.clear()

            session["logged_in"] = True
            session["username"] = username

            # LOGIN -> ATTACK SIMULATION
            return redirect(
                url_for("attack_simulation")
            )


        # ----------------------------------------------------
        # FAILED LOGIN
        # ----------------------------------------------------

        login_attempts[client_id] = (
            login_attempts.get(client_id, 0) + 1
        )

        current_attempts = login_attempts[client_id]

        # ----------------------------------------------------
        # ACCOUNT LOCKOUT
        # ----------------------------------------------------

        if current_attempts >= LOGIN_LOCKOUT_THRESHOLD:

            # Create security event
            create_event(
                event_type="FAILED_LOGIN",
                source_ip=client_id,
                username=username or "unknown",
                hostname="SENTINELX-LOGIN",
                details=(
                    f"Login attempt #{current_attempts} "
                    "caused account lockout."
                )
            )

            # Create account lockout alert
            existing_lockout = Alert.query.filter_by(
                alert_type="ACCOUNT_LOCKOUT",
                source_ip=client_id,
                hostname="SENTINELX-LOGIN",
                status="New"
            ).first()

            if not existing_lockout:

                create_alert(
                    alert_type="ACCOUNT_LOCKOUT",
                    severity="HIGH",
                    description=(
                        f"Account lockout triggered after "
                        f"{current_attempts} failed login attempts."
                    ),
                    mitre_technique="T1110",
                    risk_score=80,
                    source_ip=client_id,
                    hostname="SENTINELX-LOGIN"
                )

            return render_template(
                "login.html",
                error=(
                    "ACCOUNT LOCKED — Too many failed "
                    "login attempts."
                ),
                locked=True,
                attempts=current_attempts,
                lockout_threshold=LOGIN_LOCKOUT_THRESHOLD
            )


        # ----------------------------------------------------
        # NORMAL FAILED LOGIN
        # ----------------------------------------------------

        remaining = (
            LOGIN_LOCKOUT_THRESHOLD - current_attempts
        )

        return render_template(
            "login.html",
            error=(
                f"Invalid username or password. "
                f"{remaining} attempt(s) remaining."
            ),
            locked=False,
            attempts=current_attempts,
            lockout_threshold=LOGIN_LOCKOUT_THRESHOLD
        )


    # --------------------------------------------------------
    # GET LOGIN PAGE
    # --------------------------------------------------------

    return render_template(
        "login.html",
        locked=False,
        attempts=current_attempts,
        lockout_threshold=LOGIN_LOCKOUT_THRESHOLD
    )


# ============================================================
# DEMO RESET LOGIN LOCKOUT
# ============================================================

@app.route("/reset-login-lockout", methods=["GET", "POST"])
def reset_login_lockout():

    client_id = get_client_identifier()

    login_attempts[client_id] = 0

    return redirect(
        url_for("login")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect(url_for("login"))

    total_events = SecurityEvent.query.count()
    total_alerts = Alert.query.count()
    total_incidents = Incident.query.count()

    critical_alerts = Alert.query.filter_by(
        severity="CRITICAL"
    ).count()

    high_alerts = Alert.query.filter_by(
        severity="HIGH"
    ).count()

    new_alerts = Alert.query.filter_by(
        status="New"
    ).count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    recent_alerts = (
        Alert.query
        .order_by(Alert.timestamp.desc())
        .limit(5)
        .all()
    )

    severity_data = Counter()

    for alert in Alert.query.all():
        severity_data[alert.severity] += 1

    alert_type_data = Counter()

    for alert in Alert.query.all():
        alert_type_data[alert.alert_type] += 1

    mitre_data = Counter()

    for alert in Alert.query.all():

        technique = (
            alert.mitre_technique
            or get_mitre_mapping(alert.alert_type)
        )

        if technique != "N/A":
            mitre_data[technique] += 1

    event_timeline = []

    events = (
        SecurityEvent.query
        .order_by(SecurityEvent.timestamp.asc())
        .limit(50)
        .all()
    )

    for event in events:

        event_timeline.append({
            "timestamp": (
                event.timestamp.strftime("%H:%M:%S")
                if event.timestamp else ""
            ),
            "event_type": event.event_type
        })

    incident_risk = [
        incident.risk_score
        for incident in Incident.query.all()
    ]

    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        new_alerts=new_alerts,
        open_incidents=open_incidents,
        recent_alerts=recent_alerts,
        severity_data=dict(severity_data),
        alert_type_data=dict(alert_type_data),
        mitre_data=dict(mitre_data),
        event_timeline=event_timeline,
        incident_risk=incident_risk
    )


# ============================================================
# LIVE LOGS
# ============================================================

@app.route("/live-logs")
def live_logs():

    if not login_required():
        return redirect(url_for("login"))

    events = (
        SecurityEvent.query
        .order_by(SecurityEvent.timestamp.desc())
        .all()
    )

    return render_template(
        "live_logs.html",
        events=events
    )


# ============================================================
# ALERTS
# ============================================================

@app.route("/alerts")
def alerts():

    if not login_required():
        return redirect(url_for("login"))

    alerts_list = (
        Alert.query
        .order_by(Alert.timestamp.desc())
        .all()
    )

    return render_template(
        "alerts.html",
        alerts=alerts_list
    )


# ============================================================
# INCIDENTS
# ============================================================

@app.route("/incidents")
def incidents():

    if not login_required():
        return redirect(url_for("login"))

    incidents_list = (
        Incident.query
        .order_by(Incident.timestamp.desc())
        .all()
    )

    return render_template(
        "incidents.html",
        incidents=incidents_list
    )


# ============================================================
# ATTACK STORIES
# ============================================================

@app.route("/attack-stories")
def attack_stories():

    if not login_required():
        return redirect(url_for("login"))

    incidents_list = (
        Incident.query
        .order_by(Incident.timestamp.desc())
        .all()
    )

    return render_template(
        "attack_stories.html",
        incidents=incidents_list
    )


# ============================================================
# MITRE ATT&CK
# ============================================================

@app.route("/mitre")
def mitre():

    if not login_required():
        return redirect(url_for("login"))

    alerts_list = (
        Alert.query
        .order_by(Alert.timestamp.desc())
        .all()
    )

    mitre_counts = Counter()

    for alert in alerts_list:

        technique = (
            alert.mitre_technique
            or get_mitre_mapping(alert.alert_type)
        )

        if technique != "N/A":
            mitre_counts[technique] += 1

    return render_template(
        "mitre.html",
        alerts=alerts_list,
        mitre_counts=dict(mitre_counts),
        mitre_mapping=MITRE_MAPPING
    )


# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
def reports():

    if not login_required():
        return redirect(url_for("login"))

    incidents_list = (
        Incident.query
        .order_by(Incident.timestamp.desc())
        .all()
    )

    return render_template(
        "reports.html",
        incidents=incidents_list
    )


# ============================================================
# ATTACK SIMULATION PAGE
# ============================================================

@app.route("/attack-simulation")
def attack_simulation():

    if not login_required():
        return redirect(url_for("login"))

    return render_template(
        "attack_simulation.html",
        attacker_ip=DEFAULT_ATTACKER_IP,
        target_ip=DEFAULT_TARGET_IP,
        username=DEFAULT_USERNAME
    )


# ============================================================
# ADMIN PAGE
# ============================================================

@app.route("/admin")
def admin():

    if not login_required():
        return redirect(url_for("login"))

    return render_template(
        "admin.html",
        attacker_ip=DEFAULT_ATTACKER_IP,
        target_ip=DEFAULT_TARGET_IP,
        username=DEFAULT_USERNAME
    )


# ============================================================
# DEMO LOGIN SIMULATION
# ============================================================

@app.route("/demo/login", methods=["POST"])
def demo_login():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or request.form

    source_ip = data.get(
        "source_ip",
        DEFAULT_ATTACKER_IP
    )

    username = data.get(
        "username",
        DEFAULT_USERNAME
    )

    login_status = data.get(
        "status",
        data.get("login_type", "failed")
    )

    login_status = str(login_status).lower()

    hostname = DEFAULT_HOSTNAME

    if login_status in [
        "success",
        "successful",
        "successful_login"
    ]:

        event = create_event(
            event_type="SUCCESSFUL_LOGIN",
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            details="Successful login detected in SentinelX simulation."
        )

        return jsonify({
            "success": True,
            "message": "Successful login event created.",
            "event": serialize_event(event)
        })

    failed_login_counter[source_ip] = (
        failed_login_counter.get(source_ip, 0) + 1
    )

    count = failed_login_counter[source_ip]

    event = create_event(
        event_type="FAILED_LOGIN",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details=f"Failed login attempt #{count}"
    )

    response = {
        "success": True,
        "message": f"Failed login attempt #{count} recorded.",
        "event": serialize_event(event),
        "alert": None,
        "lockout": None
    }

    recent_events = (
        SecurityEvent.query
        .filter_by(
            source_ip=source_ip,
            username=username,
            event_type="FAILED_LOGIN"
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    detection = detect_bruteforce(recent_events)

    if detection:

        existing = Alert.query.filter_by(
            alert_type="BRUTE_FORCE",
            source_ip=source_ip,
            status="New"
        ).first()

        if not existing:

            alert = create_alert(
                alert_type=detection["alert_type"],
                severity=detection["severity"],
                description=detection["description"],
                mitre_technique=detection["mitre_technique"],
                risk_score=detection["risk_score"],
                source_ip=source_ip,
                hostname=hostname
            )

            response["alert"] = serialize_alert(alert)

    if count >= 5:

        existing_lockout = Alert.query.filter_by(
            alert_type="ACCOUNT_LOCKOUT",
            source_ip=source_ip,
            status="New"
        ).first()

        if not existing_lockout:

            lockout_alert = create_alert(
                alert_type="ACCOUNT_LOCKOUT",
                severity="HIGH",
                description=(
                    f"Account lockout threshold reached after "
                    f"{count} failed login attempts for {username}."
                ),
                mitre_technique="T1110",
                risk_score=80,
                source_ip=source_ip,
                hostname=hostname
            )

            response["lockout"] = serialize_alert(
                lockout_alert
            )

        else:

            response["lockout"] = serialize_alert(
                existing_lockout
            )

    return jsonify(response)


# ============================================================
# RESET SIMULATION LOCKOUT
# ============================================================

@app.route("/demo/reset-lockout", methods=["POST", "GET"])
def reset_lockout():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or request.form

    source_ip = data.get(
        "source_ip",
        DEFAULT_ATTACKER_IP
    )

    failed_login_counter[source_ip] = 0

    return jsonify({
        "success": True,
        "message": f"Lockout counter reset for {source_ip}."
    })


# ============================================================
# DEMO POWERSHELL
# ============================================================

@app.route("/demo/powershell", methods=["POST"])
def demo_powershell():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or request.form

    source_ip = data.get(
        "source_ip",
        DEFAULT_ATTACKER_IP
    )

    username = data.get(
        "username",
        DEFAULT_USERNAME
    )

    command = data.get(
        "command",
        "powershell.exe -EncodedCommand SQBFAFgA"
    )

    hostname = DEFAULT_HOSTNAME

    event = create_event(
        event_type="POWERSHELL",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details=command
    )

    detection = detect_suspicious_powershell(command)

    alert_data = None

    if detection:

        alert = create_alert(
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            description=detection["description"],
            mitre_technique=detection["mitre_technique"],
            risk_score=detection["risk_score"],
            source_ip=source_ip,
            hostname=hostname
        )

        alert_data = serialize_alert(alert)

    return jsonify({
        "success": True,
        "message": "PowerShell telemetry recorded.",
        "event": serialize_event(event),
        "alert": alert_data
    })


# ============================================================
# DEMO PRIVILEGED ACTIVITY
# ============================================================

@app.route("/demo/privileged", methods=["POST"])
def demo_privileged():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or request.form

    source_ip = data.get(
        "source_ip",
        DEFAULT_ATTACKER_IP
    )

    username = data.get(
        "username",
        DEFAULT_USERNAME
    )

    details = data.get(
        "details",
        "Administrative privilege activity detected."
    )

    hostname = DEFAULT_HOSTNAME

    event = create_event(
        event_type="PRIVILEGED_ACTIVITY",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details=details
    )

    recent_events = (
        SecurityEvent.query
        .filter_by(
            event_type="PRIVILEGED_ACTIVITY"
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    detection = detect_privileged_activity(recent_events)

    alert_data = None

    if detection:

        alert = create_alert(
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            description=detection["description"],
            mitre_technique=detection["mitre_technique"],
            risk_score=detection["risk_score"],
            source_ip=source_ip,
            hostname=hostname
        )

        alert_data = serialize_alert(alert)

    file_event = create_event(
        event_type="FILE_ACCESS",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details="C:\\Windows\\System32\\config\\SAM"
    )

    return jsonify({
        "success": True,
        "message": "Privileged activity recorded.",
        "event": serialize_event(event),
        "file_event": serialize_event(file_event),
        "alert": alert_data
    })


# ============================================================
# DEMO FILE ACCESS
# ============================================================

@app.route("/demo/file-access", methods=["POST"])
def demo_file_access():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or request.form

    source_ip = data.get(
        "source_ip",
        DEFAULT_ATTACKER_IP
    )

    username = data.get(
        "username",
        DEFAULT_USERNAME
    )

    file_path = data.get(
        "file_path",
        "C:\\Windows\\System32\\config\\SAM"
    )

    hostname = DEFAULT_HOSTNAME

    event = create_event(
        event_type="FILE_ACCESS",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details=file_path
    )

    detection = detect_suspicious_file_access(file_path)

    alert_data = None

    if detection:

        alert = create_alert(
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            description=detection["description"],
            mitre_technique=detection["mitre_technique"],
            risk_score=detection["risk_score"],
            source_ip=source_ip,
            hostname=hostname
        )

        alert_data = serialize_alert(alert)

    return jsonify({
        "success": True,
        "message": "File access telemetry recorded.",
        "event": serialize_event(event),
        "alert": alert_data
    })


# ============================================================
# DEMO PORT SCAN
# ============================================================

@app.route("/demo/port-scan", methods=["POST"])
def demo_port_scan():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or request.form

    source_ip = data.get(
        "source_ip",
        DEFAULT_ATTACKER_IP
    )

    target_ip = data.get(
        "target_ip",
        DEFAULT_TARGET_IP
    )

    hostname = DEFAULT_HOSTNAME

    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        443,
        445,
        3389
    ]

    created_events = []

    for port in ports:

        event = create_event(
            event_type="PORT_SCAN",
            source_ip=source_ip,
            destination_ip=target_ip,
            hostname=hostname,
            details=f"Connection attempt to port {port}"
        )

        created_events.append(
            serialize_event(event)
        )

    scan_events = (
        SecurityEvent.query
        .filter_by(
            source_ip=source_ip,
            event_type="PORT_SCAN"
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    detection = detect_portscan(scan_events)

    alert_data = None

    if detection:

        alert = create_alert(
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            description=detection["description"],
            mitre_technique=detection["mitre_technique"],
            risk_score=detection["risk_score"],
            source_ip=source_ip,
            hostname=hostname
        )

        alert_data = serialize_alert(alert)

    return jsonify({
        "success": True,
        "message": "Port scan simulation completed.",
        "events": created_events,
        "alert": alert_data
    })


# ============================================================
# FULL ATTACK CHAIN
# ============================================================

@app.route("/demo/run-full-chain", methods=["POST", "GET"])
def run_full_chain():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    source_ip = DEFAULT_ATTACKER_IP
    target_ip = DEFAULT_TARGET_IP
    username = DEFAULT_USERNAME
    hostname = DEFAULT_HOSTNAME

    # 1. FAILED LOGINS

    for attempt in range(1, 6):

        create_event(
            event_type="FAILED_LOGIN",
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            details=f"Failed login attempt #{attempt}"
        )

    # 2. BRUTE FORCE

    failed_events = (
        SecurityEvent.query
        .filter_by(
            source_ip=source_ip,
            username=username,
            event_type="FAILED_LOGIN"
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    brute_detection = detect_bruteforce(
        failed_events
    )

    if brute_detection:

        create_alert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            description=brute_detection["description"],
            mitre_technique="T1110",
            risk_score=80,
            source_ip=source_ip,
            hostname=hostname
        )

    # 3. ACCOUNT LOCKOUT

    create_alert(
        alert_type="ACCOUNT_LOCKOUT",
        severity="HIGH",
        description=(
            f"Account lockout threshold reached for "
            f"user {username}."
        ),
        mitre_technique="T1110",
        risk_score=80,
        source_ip=source_ip,
        hostname=hostname
    )

    # 4. SUCCESSFUL LOGIN

    create_event(
        event_type="SUCCESSFUL_LOGIN",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details="Successful login after multiple failed attempts."
    )

    # 5. POWERSHELL

    powershell_command = (
        "powershell.exe "
        "-EncodedCommand "
        "SQBFAFgA"
    )

    create_event(
        event_type="POWERSHELL",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details=powershell_command
    )

    powershell_detection = detect_suspicious_powershell(
        powershell_command
    )

    if powershell_detection:

        create_alert(
            alert_type="SUSPICIOUS_POWERSHELL",
            severity="HIGH",
            description=powershell_detection["description"],
            mitre_technique="T1059.001",
            risk_score=75,
            source_ip=source_ip,
            hostname=hostname
        )

    # 6. PRIVILEGED ACTIVITY

    create_event(
        event_type="PRIVILEGED_ACTIVITY",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details="Administrative privilege activity detected."
    )

    privileged_events = (
        SecurityEvent.query
        .filter_by(
            event_type="PRIVILEGED_ACTIVITY"
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    privileged_detection = detect_privileged_activity(
        privileged_events
    )

    if privileged_detection:

        create_alert(
            alert_type="PRIVILEGED_ACTIVITY",
            severity="HIGH",
            description=privileged_detection["description"],
            mitre_technique="T1078",
            risk_score=75,
            source_ip=source_ip,
            hostname=hostname
        )

    # 7. FILE ACCESS

    sensitive_file = (
        "C:\\Windows\\System32\\config\\SAM"
    )

    create_event(
        event_type="FILE_ACCESS",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        details=sensitive_file
    )

    file_detection = detect_suspicious_file_access(
        sensitive_file
    )

    if file_detection:

        create_alert(
            alert_type="SUSPICIOUS_FILE_ACCESS",
            severity="HIGH",
            description=file_detection["description"],
            mitre_technique="T1005",
            risk_score=75,
            source_ip=source_ip,
            hostname=hostname
        )

    # 8. CORRELATION

    chain_events = (
        SecurityEvent.query
        .filter_by(
            source_ip=source_ip,
            username=username
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    correlation_result = correlate_attack_chain(
        chain_events
    )

    # 9. INCIDENT

    if correlation_result:

        incident = create_incident(
            title=correlation_result["title"],
            description=correlation_result["description"],
            severity=correlation_result["severity"],
            risk_score=max(
                90,
                correlation_result["risk_score"]
            ),
            status="Open",
            source_ip=source_ip,
            hostname=hostname
        )

    else:

        incident = create_incident(
            title="Correlated Attack Chain Detected",
            description=(
                "Multiple related security activities were "
                "detected from the same source and correlated "
                "into a possible attack chain."
            ),
            severity="HIGH",
            risk_score=90,
            status="Open",
            source_ip=source_ip,
            hostname=hostname
        )

    return jsonify({
        "success": True,
        "message": "Full attack chain simulation completed.",
        "incident": serialize_incident(incident),
        "attack_chain": [
            "Failed Login Attempts",
            "Brute Force Detection",
            "Account Lockout",
            "Successful Login",
            "Suspicious PowerShell",
            "Privileged Activity",
            "Sensitive File Access",
            "Attack Correlation",
            "Incident Creation"
        ]
    })


# ============================================================
# SIMULATE BRUTE FORCE
# ============================================================

@app.route("/simulate-bruteforce", methods=["GET", "POST"])
def simulate_bruteforce():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    source_ip = DEFAULT_ATTACKER_IP
    username = DEFAULT_USERNAME
    hostname = DEFAULT_HOSTNAME

    for attempt in range(1, 6):

        create_event(
            event_type="FAILED_LOGIN",
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            details=f"Simulated failed login #{attempt}"
        )

    events = (
        SecurityEvent.query
        .filter_by(
            source_ip=source_ip,
            username=username,
            event_type="FAILED_LOGIN"
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    detection = detect_bruteforce(events)

    alert = None

    if detection:

        alert = create_alert(
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            description=detection["description"],
            mitre_technique=detection["mitre_technique"],
            risk_score=detection["risk_score"],
            source_ip=source_ip,
            hostname=hostname
        )

    return jsonify({
        "success": True,
        "message": "Brute force simulation completed.",
        "alert": serialize_alert(alert) if alert else None
    })


# ============================================================
# SIMULATE FULL ATTACK
# ============================================================

@app.route("/simulate-full-attack", methods=["GET", "POST"])
def simulate_full_attack():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    return run_full_chain()


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@app.route("/generate-report/<int:incident_id>")
def generate_report(incident_id):

    if not login_required():
        return redirect(url_for("login"))

    incident = db.session.get(
        Incident,
        incident_id
    )

    if not incident:
        return jsonify({
            "success": False,
            "message": "Incident not found."
        }), 404

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "SentinelX Security Incident Report",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            f"<b>Incident ID:</b> {incident.id}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Title:</b> {incident.title}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Severity:</b> {incident.severity}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {incident.risk_score}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Status:</b> {incident.status}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Source IP:</b> "
            f"{incident.source_ip or 'Unknown'}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Hostname:</b> "
            f"{incident.hostname or 'Unknown'}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Timestamp:</b> "
            f"{incident.timestamp.strftime('%Y-%m-%d %H:%M:%S') if incident.timestamp else ''}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<b>Description</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            incident.description or "No description available.",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<b>SentinelX Analysis</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            (
                "SentinelX correlated multiple security events "
                "and generated this incident for investigation. "
                "The platform uses rule-based detection, event "
                "correlation and MITRE ATT&CK mapping to support "
                "SOC-style security analysis."
            ),
            styles["Normal"]
        )
    )

    document.build(story)

    buffer.seek(0)

    filename = (
        f"sentinelx_incident_{incident.id}.pdf"
    )

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


# ============================================================
# DASHBOARD API
# ============================================================

@app.route("/api/dashboard")
def api_dashboard():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    total_events = SecurityEvent.query.count()
    total_alerts = Alert.query.count()
    total_incidents = Incident.query.count()

    critical_alerts = Alert.query.filter_by(
        severity="CRITICAL"
    ).count()

    high_alerts = Alert.query.filter_by(
        severity="HIGH"
    ).count()

    new_alerts = Alert.query.filter_by(
        status="New"
    ).count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    severity_data = Counter(
        alert.severity
        for alert in Alert.query.all()
    )

    alert_type_data = Counter(
        alert.alert_type
        for alert in Alert.query.all()
    )

    mitre_data = Counter()

    for alert in Alert.query.all():

        technique = (
            alert.mitre_technique
            or get_mitre_mapping(alert.alert_type)
        )

        if technique != "N/A":
            mitre_data[technique] += 1

    recent_alerts = (
        Alert.query
        .order_by(Alert.timestamp.desc())
        .limit(5)
        .all()
    )

    return jsonify({
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "new_alerts": new_alerts,
        "open_incidents": open_incidents,
        "severity_data": dict(severity_data),
        "alert_type_data": dict(alert_type_data),
        "mitre_data": dict(mitre_data),
        "recent_alerts": [
            serialize_alert(alert)
            for alert in recent_alerts
        ]
    })


# ============================================================
# EVENTS API
# ============================================================

@app.route("/api/events")
def api_events():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    events = (
        SecurityEvent.query
        .order_by(SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )

    return jsonify([
        serialize_event(event)
        for event in events
    ])


# ============================================================
# ALERTS API
# ============================================================

@app.route("/api/alerts")
def api_alerts():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    alerts_list = (
        Alert.query
        .order_by(Alert.timestamp.desc())
        .limit(100)
        .all()
    )

    return jsonify([
        serialize_alert(alert)
        for alert in alerts_list
    ])


# ============================================================
# INCIDENTS API
# ============================================================

@app.route("/api/incidents")
def api_incidents():

    if not login_required():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    incidents_list = (
        Incident.query
        .order_by(Incident.timestamp.desc())
        .limit(100)
        .all()
    )

    return jsonify([
        serialize_incident(incident)
        for incident in incidents_list
    ])


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "application": "SentinelX",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({
        "success": False,
        "error": "Page not found"
    }), 404


@app.errorhandler(500)
def internal_server_error(error):

    db.session.rollback()

    return jsonify({
        "success": False,
        "error": "Internal server error",
        "details": str(error)
    }), 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SentinelX SOC Dashboard")
    print("Explainable Security Monitoring and Attack Detection Platform")
    print("=" * 60)
    print()
    print("Login: http://127.0.0.1:5000/")
    print("Dashboard: http://127.0.0.1:5000/dashboard")
    print("Attack Simulation: http://127.0.0.1:5000/attack-simulation")
    print("Admin: http://127.0.0.1:5000/admin")
    print()
    print("Demo Login:")
    print("Username: admin")
    print("Password: sentinelx")
    print()
    print("Login Lockout Threshold: 5 failed attempts")
    print()
    print("Starting SentinelX...")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
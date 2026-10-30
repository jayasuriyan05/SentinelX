from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


# ============================================================
# DATABASE OBJECT
# ============================================================

db = SQLAlchemy()


# ============================================================
# SECURITY EVENT MODEL
# ============================================================

class SecurityEvent(db.Model):

    __tablename__ = "security_events"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    event_type = db.Column(
        db.String(100),
        nullable=False
    )

    source_ip = db.Column(
        db.String(50)
    )

    destination_ip = db.Column(
        db.String(50)
    )

    username = db.Column(
        db.String(100)
    )

    hostname = db.Column(
        db.String(100)
    )

    details = db.Column(
        db.Text
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now
    )


# ============================================================
# ALERT MODEL
# ============================================================

class Alert(db.Model):

    __tablename__ = "alerts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    alert_type = db.Column(
        db.String(100),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        default="MEDIUM"
    )

    description = db.Column(
        db.Text
    )

    mitre_technique = db.Column(
        db.String(50)
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    status = db.Column(
        db.String(30),
        default="New"
    )

    source_ip = db.Column(
        db.String(50)
    )

    hostname = db.Column(
        db.String(100)
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now
    )


# ============================================================
# INCIDENT MODEL
# ============================================================

class Incident(db.Model):

    __tablename__ = "incidents"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text
    )

    severity = db.Column(
        db.String(20),
        default="MEDIUM"
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    status = db.Column(
        db.String(30),
        default="Open"
    )

    source_ip = db.Column(
        db.String(50)
    )

    hostname = db.Column(
        db.String(100)
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now
    )

"""
database.py
===========
SQLAlchemy ORM models for the CRP AES-256 Cryptography web application.

Three tables are used:
  User          — Registered user accounts. Passwords are stored as
                  SHA-256+salt hashes. Emails are stored as AES-256
                  ciphertext (never as plaintext on disk).

  ProtectedNote — User-created notes whose content is AES-256 encrypted
                  before being written to the database. This is the primary
                  demonstration model showing real-world encrypted storage.

  LoginLog      — Audit trail of every login attempt (successful or not),
                  including IP address and timestamp. Demonstrates that a
                  real system should keep records for security monitoring.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'

    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

    # Password stored as "<hex_salt>$<hex_sha256_digest>" — never plaintext
    password_hash = db.Column(db.String(200), nullable=False)

    # Email stored as AES-256 ciphertext; key stored separately in aes_key
    encrypted_email = db.Column(db.String(500), nullable=True)
    aes_key         = db.Column(db.String(64),  nullable=True)

    # Brute-force protection fields
    failed_attempts = db.Column(db.Integer,  default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)

    # OTP fields — hash stored (not raw OTP), same format as password_hash
    otp_hash   = db.Column(db.String(200), nullable=True)
    otp_expiry = db.Column(db.DateTime,    nullable=True)

    # One user → many notes (cascade delete ensures notes are removed with user)
    notes = db.relationship('ProtectedNote', backref='owner', lazy=True,
                            cascade='all, delete-orphan')


# ---------------------------------------------------------------------------
# ProtectedNote model
# ---------------------------------------------------------------------------

class ProtectedNote(db.Model):
    """
    Stores user-created notes whose content is encrypted with the AES-256
    cipher before being written to the database.

    This is the PRIMARY demonstration model for the project:
      - Only 'ciphertext' is ever persisted to disk.
      - 'aes_key' is stored alongside so the note can be decrypted
        when the authenticated owner views their vault.
      - Plaintext is reconstructed on-the-fly at read time — it is never
        stored, never logged, and never written to the filesystem.
    """
    __tablename__ = 'protected_note'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    label      = db.Column(db.String(120), nullable=False)     # Note title
    ciphertext = db.Column(db.Text,        nullable=False)     # What is in the DB
    aes_key    = db.Column(db.String(64),  nullable=False)     # Encryption key
    created_at   = db.Column(db.DateTime,
                             default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# LoginLog model
# ---------------------------------------------------------------------------

class LoginLog(db.Model):
    """
    Audit log — records every login attempt made to the system.

    Academic purpose:
        This table demonstrates that production security systems maintain
        audit trails. An administrator can query this table to detect:
          - Repeated failed attempts (brute-force attack indicators)
          - Unusual login times or IP addresses
          - Account compromise patterns

    In this project it is populated by auth.py on every login attempt,
        both successful and failed.
    """
    __tablename__ = 'login_log'

    id         = db.Column(db.Integer,  primary_key=True)
    user_id    = db.Column(db.Integer,  db.ForeignKey('user.id'), nullable=False)
    timestamp  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    successful = db.Column(db.Boolean,  default=False)
    ip_address = db.Column(db.String(45), nullable=True)   # Supports IPv6 (max 45 chars)

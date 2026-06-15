"""
auth.py
=======
Authentication Blueprint — handles all user account and login operations.

Authentication flow (multi-step, explained for viva):
─────────────────────────────────────────────────────
Step 1 — SIGNUP   : User registers → password hashed with SHA-256+salt →
                    email encrypted with AES-256 CBC → both stored in DB.
Step 2 — LOGIN    : User submits credentials → password hash verified →
                    on success, a 6-digit OTP is generated and hashed →
                    OTP hash stored in DB → raw OTP printed to console.
Step 3 — OTP      : User enters the OTP they saw on the console →
                    OTP verified against its stored hash → session created.
Step 4 — SESSION  : Flask signed-cookie session stores user_id + username →
                    all protected routes check for 'user_id' in session.
Step 5 — LOGOUT   : session.clear() removes the session cookie.

Security features demonstrated:
  - SHA-256 + random salt password hashing  (crypto_utils.hash_password)
  - Constant-time comparison                (crypto_utils.verify_password)
  - Brute-force lockout after 3 failures
  - OTP expiry (10 minutes)
  - AES-256 CBC encrypted email storage

Session management : Flask built-in sessions (signed cookies)
Password hashing   : hashlib SHA-256 + salt  (Python stdlib only)
Data encryption    : AES-256 CBC (aes256.py — manually implemented)
"""

from flask import (Blueprint, request, render_template, redirect, url_for,
                   session, flash)
from database import db, User, LoginLog
from crypto_utils import (check_password_strength, is_password_acceptable,
                           hash_password, verify_password,
                           encrypt_data)
import aes256
from datetime import datetime, timedelta
import random
import re
import string

auth_bp = Blueprint('auth', __name__)

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------
MAX_FAILED_ATTEMPTS      = 3    # Lock account after this many wrong attempts
LOCKOUT_DURATION_MINUTES = 15   # How long the account stays locked
OTP_VALIDITY_MINUTES     = 10   # OTP expires after this many minutes


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------




def generate_and_store_otp(user: User) -> str:
    """
    Create a fresh 6-digit OTP, hash it (same method as passwords), and
    store the hash on the user record with an expiry timestamp.

    Why hash the OTP?
        If the database were compromised, an attacker should not be able to
        read the OTP and immediately use it. Hashing the OTP provides the
        same DB-at-rest protection as hashing passwords.

    The raw OTP is printed to the console — in a real system this would be
    sent by email or SMS. Printing to console is sufficient for an academic demo.

    Returns the raw OTP string (so it can be printed; never stored raw in DB).
    """
    otp = str(random.randint(100_000, 999_999))      # 6-digit random number

    # Store the hash of the OTP (not the OTP itself) in the database
    user.otp_hash   = hash_password(otp)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=OTP_VALIDITY_MINUTES)
    db.session.commit()

    # Simulate OTP delivery — print to terminal for academic demonstration
    print("\n" + "=" * 50, flush=True)
    print(f"  OTP for '{user.username}': {otp}", flush=True)
    print("=" * 50 + "\n", flush=True)
    return otp


# ---------------------------------------------------------------------------
# Route: Sign Up
# ---------------------------------------------------------------------------

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    GET  : Render the signup form.
    POST : Validate input → hash password → encrypt email → create user record.

    Validation steps:
        1. All fields present
        2. Email domain is gmail.com or bmsce.ac.in
        3. Password meets strength requirements (Medium or Strong)
        4. Username is not already taken
    """
    if request.method == 'GET':
        return render_template('signup.html')

    # Collect and sanitise form inputs
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    email    = request.form.get('email',    '').strip()

    # Step 1 — All fields required
    if not username or not password or not email:
        flash("All fields are required.", "error")
        return render_template('signup.html')

    # Step 2 — Restrict accepted email domains (academic requirement)
    email_regex = r"^[a-zA-Z0-9._%+\-]+@(gmail\.com|bmsce\.ac\.in)$"
    if not re.match(email_regex, email):
        flash("Only gmail.com and bmsce.ac.in email addresses are allowed.", "error")
        return render_template('signup.html')

    # Step 3 — Enforce password strength
    if not is_password_acceptable(password):
        _, feedback = check_password_strength(password)
        flash(f"Weak password: {feedback}", "error")
        return render_template('signup.html')

    # Step 4 — Username uniqueness check
    if User.query.filter_by(username=username).first():
        flash("Username already exists.", "error")
        return render_template('signup.html')

    # Hash the password with SHA-256 + random salt (see crypto_utils.py)
    hashed_pw = hash_password(password)

    # Encrypt the email using AES-256 CBC before storing in the database
    aes_key         = aes256.generate_aes_key()   # 256-bit key (64 hex chars)
    encrypted_email = encrypt_data(email, aes_key)

    new_user = User(
        username        = username,
        password_hash   = hashed_pw,
        encrypted_email = encrypted_email,
        aes_key         = aes_key,
    )
    db.session.add(new_user)
    db.session.commit()

    print(f"[SIGNUP] User '{username}' registered. "
          f"Email AES-256 encrypted, key='{aes_key[:16]}…'", flush=True)

    flash("Account created successfully! Please log in.", "success")
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# Route: Log In (Step 1 of 2 — password check)
# ---------------------------------------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET  : Render the login form.
    POST : Check username/password → if correct, generate OTP → redirect to OTP page.

    On failure:
        - Increment failed_attempts counter on the user record.
        - Lock the account for LOCKOUT_DURATION_MINUTES after MAX_FAILED_ATTEMPTS.
        - Show how many attempts remain before lock.

    Note: We do NOT tell the user whether the username or the password was wrong
    ('Invalid credentials' is intentionally vague) to prevent username enumeration.
    """
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        flash("Username and password are required.", "error")
        return render_template('login.html')

    user = User.query.filter_by(username=username).first()
    if not user:
        # Vague message to prevent username enumeration
        flash("Invalid credentials.", "error")
        return render_template('login.html')

    # Check if the account is currently locked
    now = datetime.utcnow()
    if user.locked_until and user.locked_until > now:
        flash(f"Account locked. Try again after "
              f"{user.locked_until.strftime('%H:%M:%S')} UTC.", "error")
        return render_template('login.html')

    # Verify password using constant-time comparison (timing-attack safe)
    is_valid = verify_password(password, user.password_hash)

    # Record this login attempt in the audit log (LoginLog table)
    log = LoginLog(user_id=user.id, successful=is_valid,
                   ip_address=request.remote_addr, timestamp=now)
    db.session.add(log)

    if is_valid:
        # Password correct — move to OTP step
        generate_and_store_otp(user)
        session['pending_username'] = username   # remember who is mid-login
        flash("Password correct. Check the console for your OTP.", "info")
        return redirect(url_for('auth.otp'))
    else:
        # Wrong password — increment failure counter
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            flash(f"Too many failed attempts. Account locked for "
                  f"{LOCKOUT_DURATION_MINUTES} minutes.", "error")
        else:
            remaining = MAX_FAILED_ATTEMPTS - user.failed_attempts
            flash(f"Invalid credentials. {remaining} attempt(s) remaining.", "error")
        db.session.commit()
        return render_template('login.html')


# ---------------------------------------------------------------------------
# Route: OTP Verification (Step 2 of 2)
# ---------------------------------------------------------------------------

@auth_bp.route('/otp', methods=['GET', 'POST'])
def otp():
    """
    GET  : Show the OTP entry form (only accessible if a pending_username is set).
    POST : Verify the entered OTP against the stored hash.
           On success → clear OTP fields → create full session → redirect to vault.
           On failure → increment failed_attempts (same lockout policy as login).

    The pending_username in session acts as a temporary 'half-authenticated' state.
    The user is NOT fully logged in until both password AND OTP are verified.
    """
    pending = session.get('pending_username')
    if not pending:
        # No active login attempt — cannot access OTP page directly
        return redirect(url_for('auth.login'))

    if request.method == 'GET':
        return render_template('otp.html', username=pending)

    otp_input = request.form.get('otp', '').strip()
    user      = User.query.filter_by(username=pending).first()

    if not user:
        session.pop('pending_username', None)
        return redirect(url_for('auth.login'))

    now = datetime.utcnow()

    # Lockout check (possible if failed_attempts accumulated during OTP step)
    if user.locked_until and user.locked_until > now:
        flash("Account is locked.", "error")
        return render_template('otp.html', username=pending)

    # Check OTP expiry — OTP is only valid for OTP_VALIDITY_MINUTES
    if not user.otp_hash or not user.otp_expiry or user.otp_expiry < now:
        flash("OTP has expired. Please log in again.", "error")
        session.pop('pending_username', None)
        return redirect(url_for('auth.login'))

    # Verify OTP (hashed the same way as passwords — constant-time comparison)
    if verify_password(otp_input, user.otp_hash):
        # OTP correct — create authenticated session
        user.failed_attempts = 0
        user.locked_until    = None
        user.otp_hash        = None    # Clear OTP — it's single-use
        user.otp_expiry      = None
        db.session.commit()

        session.pop('pending_username', None)
        session['user_id']  = user.id
        session['username'] = user.username

        flash(f"Welcome, {user.username}!", "success")
        return redirect(url_for('main.protected_data'))
    else:
        # Wrong OTP — apply the same lockout logic as failed password attempts
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            flash("Too many failed attempts. Account locked.", "error")
            db.session.commit()
            session.pop('pending_username', None)
            return redirect(url_for('auth.login'))
        db.session.commit()
        flash("Incorrect OTP. Please try again.", "error")
        return render_template('otp.html', username=pending)


# ---------------------------------------------------------------------------
# Route: Resend OTP
# ---------------------------------------------------------------------------

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    """
    Generate and print a fresh OTP for the pending user (invalidates the old one).
    Only works during an active login session (pending_username must be set).
    """
    pending = session.get('pending_username')
    if not pending:
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(username=pending).first()
    if user:
        generate_and_store_otp(user)
        flash("A new OTP has been printed to the console.", "info")
    return redirect(url_for('auth.otp'))


# ---------------------------------------------------------------------------
# Route: Logout
# ---------------------------------------------------------------------------

@auth_bp.route('/logout')
def logout():
    """
    Clear the entire Flask session (removes user_id, username, etc.) and
    redirect to the login page. The signed session cookie is invalidated.
    """
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('auth.login'))

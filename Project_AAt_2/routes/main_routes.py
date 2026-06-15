"""
routes/main_routes.py
=====================
Blueprint for all HTML page routes in the application.

Routes registered here:
  GET  /                      — Landing / home page
  GET  /aes-demo              — Interactive step-by-step AES-256 demo
  GET  /protected-data        — View AES-256 encrypted notes vault (login required)
  POST /protected-data/add    — AES-256 encrypt and save a new note (login required)
  POST /protected-data/delete/<id>  — Delete a note (login required)
  GET  /aes-internals         — AES-256 internals explorer (SubBytes, ShiftRows, MixColumns, Key Schedule)
"""

from flask import (Blueprint, render_template, redirect, url_for,
                   session, flash, request)
from database import db, User, ProtectedNote
from crypto_utils import encrypt_data, decrypt_data
import aes256

main_bp = Blueprint('main', __name__)


# ---------------------------------------------------------------------------
# Login-required decorator
# ---------------------------------------------------------------------------

def login_required(f):
    """
    Decorator that protects a route by requiring an active user session.

    How it works:
        - Flask session is a signed cookie containing 'user_id' after login.
        - If 'user_id' is absent, the user is not authenticated — redirect to login.
        - functools.wraps preserves the original function name (required for
          Flask's route registration to work correctly with decorated functions).
    """
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access that page.", "error")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Home page
# ---------------------------------------------------------------------------

@main_bp.route('/')
def index():
    """Render the landing page with project overview and feature cards."""
    return render_template('index.html',
                           logged_in='user_id' in session,
                           username=session.get('username'))


# ---------------------------------------------------------------------------
# Cryptanalysis page
# ---------------------------------------------------------------------------

@main_bp.route('/aes-internals')
def aes_internals():
    """
    Render the AES-256 internals explorer page.
    This page is publicly accessible — no login required — so that students
    and evaluators can explore SubBytes, ShiftRows, MixColumns, and Key Expansion.
    """
    return render_template('aes_internals.html',
                           logged_in='user_id' in session,
                           username=session.get('username'))



# ---------------------------------------------------------------------------
# Protected Data Vault — view encrypted notes
# ---------------------------------------------------------------------------

@main_bp.route('/protected-data', methods=['GET'])
@login_required
def protected_data():
    """
    Display all AES-256-encrypted notes belonging to the logged-in user.

    For each note:
        1. Retrieve the ciphertext and AES key from the database.
        2. Decrypt the ciphertext using AES-256 CBC.
        3. Pass both the ciphertext (what the DB holds) and plaintext
           (decrypted for display) to the template.

    This side-by-side display is the core academic demonstration: showing
    that only ciphertext exists in the database, and plaintext is
    reconstructed on-the-fly only for the authenticated owner.
    """
    user  = User.query.get(session['user_id'])
    notes = (ProtectedNote.query
             .filter_by(user_id=user.id)
             .order_by(ProtectedNote.created_at.desc())
             .all())

    note_data = []
    for note in notes:
        try:
            plaintext = decrypt_data(note.ciphertext, note.aes_key)
        except Exception:
            plaintext = "[Decryption failed]"

        note_data.append({
            'id'        : note.id,
            'label'     : note.label,
            'ciphertext': note.ciphertext,   # what is stored in the DB
            'key'       : note.aes_key,
            'plaintext' : plaintext,          # decrypted only for display
            'created_at': note.created_at,
        })

    return render_template('protected_data.html', notes=note_data, user=user)


# ---------------------------------------------------------------------------
# Protected Data Vault — add a new encrypted note
# ---------------------------------------------------------------------------

@main_bp.route('/protected-data/add', methods=['POST'])
@login_required
def add_protected_note():
    """
    AES-256 encrypt a user-supplied note and save only the ciphertext to the database.

    Key selection logic:
        - Always generate a fresh 256-bit AES key per note (cryptographically random).
        - If the user provides a key in the form, it is IGNORED — AES requires
          a 64-hex-char key, not a user-supplied string, for security.
        - The generated key is stored alongside the ciphertext so the note
          can be decrypted on authenticated read requests.
    """
    label     = request.form.get('label',     '').strip()
    plaintext = request.form.get('plaintext', '').strip()

    if not label or not plaintext:
        flash("Label and note content are required.", "error")
        return redirect(url_for('main.protected_data'))

    # Always generate a fresh 256-bit AES key for each new note
    aes_key = aes256.generate_aes_key()   # 64-char hex string

    # Encrypt the note content — ONLY ciphertext enters the database
    ciphertext = encrypt_data(plaintext, aes_key)

    note = ProtectedNote(
        user_id    = session['user_id'],
        label      = label,
        ciphertext = ciphertext,
        aes_key    = aes_key,
    )
    db.session.add(note)
    db.session.commit()

    print(f"[NOTE SAVED] Label='{label}' | AES-key='{aes_key[:16]}…' | "
          f"Plaintext='{plaintext}' | CT='{ciphertext[:40]}…'", flush=True)

    flash(f"Note AES-256 encrypted and stored! Ciphertext: {ciphertext[:40]}…", "success")
    return redirect(url_for('main.protected_data'))


# ---------------------------------------------------------------------------
# Protected Data Vault — delete a note
# ---------------------------------------------------------------------------

@main_bp.route('/protected-data/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    """
    Delete the specified note if it belongs to the currently logged-in user.
    The user_id check prevents one user from deleting another user's notes
    (an Insecure Direct Object Reference vulnerability if omitted).
    """
    note = ProtectedNote.query.filter_by(
        id=note_id, user_id=session['user_id']).first()
    if note:
        db.session.delete(note)
        db.session.commit()
        flash("Note deleted.", "success")
    return redirect(url_for('main.protected_data'))


# ---------------------------------------------------------------------------
# Crypto Demo — interactive step-by-step AES-256 demonstration
# ---------------------------------------------------------------------------

@main_bp.route('/aes-demo')
def aes_demo():
    """
    Render the interactive AES-256 demonstration page.
    This page is publicly accessible — no login required — so that evaluators can
    test the manual block transformations directly.
    """
    return render_template('aes_demo.html',
                           logged_in='user_id' in session,
                           username=session.get('username'))

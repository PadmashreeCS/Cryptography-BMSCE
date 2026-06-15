"""
app.py
======
Flask application factory for the CRP Cryptography Web Application.

How to run:
    python app.py
Then open: http://127.0.0.1:5000

Architecture:
    - Blueprints : auth_bp (login/signup/OTP), main_bp (pages + API routes)
    - Database   : SQLite via Flask-SQLAlchemy (models in database.py)
    - Data Enc   : AES-256 CBC implemented from scratch in aes256.py
    - Demo Enc   : AES-256 CBC in aes256.py (AES Demo + Internals)
    - Hashing    : SHA-256 + salt in crypto_utils.py (Python stdlib only)
"""

import os
from flask import Flask
from database import db, User, ProtectedNote
from auth import auth_bp
import aes256
from routes.main_routes import main_bp
from routes.aes_routes import aes_bp
from crypto_utils import hash_password, encrypt_data
from dotenv import load_dotenv

load_dotenv()


def create_app():
    """
    Application factory — creates and configures the Flask app.

    Using a factory function (instead of a module-level `app = Flask(...)`)
    is a Flask best practice: it makes the app easier to test and allows
    multiple configurations (dev/test/prod) without changing source code.
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    # SQLite database stored in the 'instance/' folder (Flask default location)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URI', 'sqlite:///crp_app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Secret key signs the session cookie so it cannot be forged by the client.
    # Change this to a long random string in any production deployment.
    app.config['SECRET_KEY'] = os.environ.get(
        'FLASK_SECRET_KEY', 'crp-aes256-secret-2024-change-in-prod')

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)

    # ------------------------------------------------------------------
    # Blueprints
    # auth_bp   : /login, /signup, /otp, /resend-otp, /logout
    # main_bp   : /, /aes-demo, /protected-data, /aes-internals
    # aes_bp    : /api/aes/encrypt, /api/aes/decrypt, /api/aes/trace/...
    # ------------------------------------------------------------------
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(aes_bp)

    # ------------------------------------------------------------------
    # Database initialisation
    # ------------------------------------------------------------------
    with app.app_context():
        from sqlalchemy.exc import OperationalError
        try:
            db.create_all()
            User.query.first()   # smoke-test: will raise if schema is wrong
        except OperationalError as e:
            # Schema mismatch (e.g. after a model change) — rebuild cleanly.
            # WARNING: This drops all existing data. For production use
            # Alembic migrations instead.
            print(f"\n[DB] Schema mismatch — rebuilding database: {e}")
            db.drop_all()
            db.create_all()

        _seed_sample_data()

        print("\n" + "=" * 60)
        print("  AES-256 Cryptography Web App — CRP Project")
        print("  Open: http://127.0.0.1:5000")
        print("=" * 60 + "\n")

    return app


# ---------------------------------------------------------------------------
# Database seed — populate demo accounts and notes on first run
# ---------------------------------------------------------------------------

def _seed_sample_data():
    """
    Populate the database with demo users and sample encrypted notes if it is
    empty. This runs once on first startup so the faculty evaluator can log in
    immediately using the printed credentials without needing to sign up first.
    """
    if User.query.count() > 0:
        return   # Already seeded — nothing to do

    print("[SEED] Database empty — creating sample users and notes (AES-256 encrypted)...")

    # ---- Admin user ----
    admin_key = aes256.generate_aes_key()          # random 256-bit AES key (64 hex chars)
    admin_enc = encrypt_data("admin@bmsce.ac.in", admin_key)
    admin = User(
        username        = "admin",
        password_hash   = hash_password("Admin@123!"),
        encrypted_email = admin_enc,
        aes_key         = admin_key,
    )

    # ---- Student user ----
    stu_key = aes256.generate_aes_key()
    stu_enc = encrypt_data("student@gmail.com", stu_key)
    student = User(
        username        = "student",
        password_hash   = hash_password("Student@123!"),
        encrypted_email = stu_enc,
        aes_key         = stu_key,
    )

    db.session.add_all([admin, student])
    db.session.flush()   # assign IDs before creating related notes

    # ---- Sample AES-256 encrypted notes for the admin account ----
    notes_raw = [
        ("Secret Project Code",  "OPERATION FALCON"),
        ("Bank Account Number",  "ACC1234567890"),
        ("Research Key Finding", "AES-256 CBC is a symmetric block cipher"),
    ]
    for label, plaintext in notes_raw:
        note_key = aes256.generate_aes_key()   # fresh 256-bit AES key per note
        ct = encrypt_data(plaintext, note_key)
        db.session.add(ProtectedNote(
            user_id    = admin.id,
            label      = label,
            ciphertext = ct,
            aes_key    = note_key,
        ))
        print(f"  [NOTE] '{label}' | AES-key='{note_key[:16]}…' | "
              f"plaintext='{plaintext}' -> ct='{ct[:40]}…'")

    db.session.commit()

    print(f"\n  Admin   : username='admin'   password='Admin@123!'")
    print(f"            AES email key='{admin_key[:16]}…'")
    print(f"  Student : username='student' password='Student@123!'")
    print(f"            AES email key='{stu_key[:16]}…'")
    print("[SEED] Done.\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    application = create_app()
    application.run(debug=True, host='127.0.0.1', port=5000)

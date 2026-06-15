"""
verify_migration.py
===================
Quick verification script to confirm AES-256 migration is complete and working.
Run: python verify_migration.py
"""
import sys
sys.path.insert(0, '.')

print("=" * 55)
print("  AES-256 Migration Verification")
print("=" * 55)

# ─── Test 1: aes256 round-trip ───────────────────────────────
import aes256
key = aes256.generate_aes_key()
assert len(key) == 64, f"Key length wrong: {len(key)}"
ct = aes256.encrypt_cbc("Hello AES-256!", key)
pt = aes256.decrypt_cbc(ct, key)
assert pt == "Hello AES-256!", f"Round-trip failed: {pt}"
print("\n[PASS] aes256 encrypt/decrypt round-trip")

# ─── Test 2: crypto_utils wrapping ───────────────────────────
from crypto_utils import encrypt_data, decrypt_data
ct2 = encrypt_data("Secret Note Content", key)
pt2 = decrypt_data(ct2, key)
assert pt2 == "Secret Note Content", f"crypto_utils round-trip failed: {pt2}"
print("[PASS] crypto_utils encrypt_data/decrypt_data")

# ─── Test 3: Auth module imports cleanly ─────────────────────
from auth import auth_bp
import auth as auth_mod
import inspect
src = inspect.getsource(auth_mod.signup)
assert "aes256.generate_aes_key" in src, "signup() still using old key!"
print("[PASS] auth.signup uses aes256.generate_aes_key()")

# ─── Test 4: main_routes uses AES keys for notes ─────────────
import routes.main_routes as mr
src2 = inspect.getsource(mr.add_protected_note)
assert "aes256.generate_aes_key" in src2, "add_protected_note still using old key!"
print("[PASS] routes/main_routes.add_protected_note uses aes256.generate_aes_key()")

# ─── Test 5: App factory creates and seeds correctly ─────────
from app import create_app
app = create_app()
print("\n[PASS] Flask app factory created successfully")

# ─── Test 6: Database seeded with AES-256 keys ───────────────
with app.app_context():
    from database import User, ProtectedNote
    users = User.query.all()
    print(f"\n[DB] {len(users)} user(s) in database:")
    for u in users:
        key_len = len(u.aes_key) if u.aes_key else 0
        assert key_len == 64, f"User '{u.username}' key is {key_len} chars, expected 64!"
        decrypted_email = decrypt_data(u.encrypted_email, u.aes_key) if u.encrypted_email else "(none)"
        print(f"     username='{u.username}'  key_len={key_len}  email='{decrypted_email}'  [PASS]")

    notes = ProtectedNote.query.all()
    print(f"\n[DB] {len(notes)} encrypted note(s):")
    for n in notes:
        key_len = len(n.aes_key) if n.aes_key else 0
        assert key_len == 64, f"Note '{n.label}' key is {key_len} chars, expected 64!"
        plaintext = decrypt_data(n.ciphertext, n.aes_key)
        print(f"     label='{n.label}'  key_len={key_len}  plaintext='{plaintext}'  [PASS]")

print("\n" + "=" * 55)
print("  ALL TESTS PASSED — Migration is complete!")
print("=" * 55)
print("\nRun the app with:  python app.py")

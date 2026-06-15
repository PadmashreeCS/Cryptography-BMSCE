"""
crypto_utils.py
===============
Pure-Python cryptography utility functions for the CRP academic project.

Two responsibilities:
  1. Password handling  — SHA-256 + random salt hashing (Python stdlib only)
  2. Data encryption    — AES-256 CBC wrapper (calls aes256.py)

Design decision — NO external crypto libraries:
  This project deliberately avoids bcrypt, PyJWT, pycryptodome, and the
  `cryptography` package so that every security operation is visible and
  explainable in code. The trade-off (SHA-256 is faster to brute-force than
  bcrypt) is acceptable for an academic demonstration.
"""

import hashlib
import hmac       # Used for constant-time password comparison (timing-attack defence)
import os
import re
import aes256     # Our manually implemented AES-256 cipher engine


# ---------------------------------------------------------------------------
# Password strength checking
# ---------------------------------------------------------------------------

def check_password_strength(password: str):
    """
    Evaluate a password and return (strength_label, feedback_message).

    Strength criteria:
        - At least 8 characters long
        - Contains uppercase letter
        - Contains lowercase letter
        - Contains a digit
        - Contains a special character (non-alphanumeric)

    Scoring:
        0–1 criteria met → 'Weak'
        2–3 criteria met → 'Medium'
        All 4 criteria  → 'Strong'
    """
    if len(password) < 8:
        return "Weak", "Password must be at least 8 characters long."

    has_upper   = re.search(r'[A-Z]', password)
    has_lower   = re.search(r'[a-z]', password)
    has_digit   = re.search(r'\d', password)
    has_special = re.search(r'[\W_]', password)

    # Count how many criteria are met (True → 1, False/None → 0)
    score = sum(bool(x) for x in (has_upper, has_lower, has_digit, has_special))

    if score < 2:
        return "Weak", "Password is too simple. Use a mix of character types."
    elif score == 4:
        return "Strong", "Excellent password strength."
    else:
        return "Medium", "Good, but could be stronger by adding missing character types."


def is_password_acceptable(password: str) -> bool:
    """Return True if the password is Medium or Strong (not Weak)."""
    strength, _ = check_password_strength(password)
    return strength in ("Medium", "Strong")


# ---------------------------------------------------------------------------
# Password hashing — stdlib hashlib (SHA-256 + random salt)
#
# Storage format in the database:  "<hex_salt>$<hex_digest>"
# Example: "a3f09c1b...16bytes...$e7d2c8a9...32bytes..."
#
# Why salt?
#   Without a salt, two users with the same password produce the same hash.
#   An attacker who steals the DB can use a precomputed "rainbow table" to
#   reverse hashes instantly. A unique random salt per password defeats this —
#   even identical passwords produce completely different stored hashes.
#
# Why SHA-256?
#   SHA-256 is a one-way cryptographic hash function from Python's stdlib.
#   We use it here because it requires no external libraries, making the
#   implementation fully transparent for academic review.
#   (In production, bcrypt or Argon2 would be preferred as they are slower
#    by design, making brute-force attacks more costly.)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using SHA-256 with a randomly generated 16-byte
    salt. Returns a single string  "<hex_salt>$<hex_digest>"  safe to store in DB.

    Steps:
        1. Generate 16 cryptographically random bytes  (os.urandom)
        2. Prepend the salt bytes to the password bytes before hashing
           (salt + password, not password + salt, to prevent length-extension)
        3. Compute SHA-256 digest → 32-byte (64 hex-char) hash
        4. Return "salt_hex$digest_hex" as a single storable string
    """
    salt   = os.urandom(16)                                   # 16 truly random bytes
    digest = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt.hex() + '$' + digest                          # Combine for DB storage


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a hash produced by hash_password().

    Steps:
        1. Split the stored string back into salt (hex) and expected digest.
        2. Re-hash the supplied password using the same salt.
        3. Compare the freshly computed digest to the stored digest.

    Why hmac.compare_digest?
        A naive `computed == stored` comparison short-circuits as soon as it
        finds a differing byte. An attacker can measure response time to guess
        which bytes are correct (a 'timing attack'). hmac.compare_digest always
        takes the same amount of time regardless of where the strings differ,
        making timing attacks impossible.

    Returns True if the password matches, False otherwise (including on error).
    """
    try:
        salt_hex, stored_digest = stored_hash.split('$', 1)
        salt     = bytes.fromhex(salt_hex)
        computed = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        # Constant-time comparison — resists timing attacks
        return hmac.compare_digest(computed, stored_digest)
    except Exception:
        # Any malformed input (wrong format, bad hex, etc.) → return False safely
        return False


# ---------------------------------------------------------------------------
# Data encryption / decryption — AES-256 CBC
#
# This is the PRIMARY encryption engine used for all protected data in the DB.
# Plaintext is AES-encrypted before being written; ciphertext is decrypted only
# on authenticated read requests. Plaintext is NEVER stored on disk.
#
# Storage format: "<iv_hex>|<ciphertext_hex>"   (produced by aes256.encrypt_cbc)
# The IV is a random 16 bytes prepended to each ciphertext — it is public but
# unique per encryption, ensuring the same plaintext + key → different ciphertext
# every time (semantic security).
# ---------------------------------------------------------------------------

def encrypt_data(plaintext: str, key_hex: str) -> str:
    """
    Encrypt sensitive user data using the manually implemented AES-256 CBC cipher.
    The resulting hex string is what gets stored in the database.

    Parameters:
        plaintext : Any UTF-8 string (email, note content, etc.)
        key_hex   : 64-char hex string — the 256-bit AES key for this record
    """
    if not plaintext:
        return ""
    return aes256.encrypt_cbc(plaintext, key_hex)


def decrypt_data(ciphertext_hex: str, key_hex: str) -> str:
    """
    Decrypt data that was encrypted with encrypt_data() using the same key.
    Only called for authenticated users viewing their own records.

    Parameters:
        ciphertext_hex : "<iv_hex>|<ct_hex>" as returned by encrypt_data()
        key_hex        : 64-char hex string — must match the key used to encrypt
    """
    if not ciphertext_hex:
        return ""
    return aes256.decrypt_cbc(ciphertext_hex, key_hex)

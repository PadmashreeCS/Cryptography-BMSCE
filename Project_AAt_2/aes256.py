"""
aes256.py
=========
Manually implemented AES-256 (Advanced Encryption Standard) cipher engine.

This module is written from scratch for academic study — NO external libraries
are used. Every mathematical operation is derived from the AES specification
(FIPS PUB 197) and explained in-line so it can be understood and explained
during a viva examination.

AES Overview (for viva):
─────────────────────────
AES is a symmetric block cipher that operates on a fixed 128-bit (16-byte)
block of data at a time. The key can be 128, 192, or 256 bits. This
implementation uses AES-256, which requires a 32-byte (256-bit) key and
performs 14 rounds of transformation.

Each round applies four operations in sequence:
  1. SubBytes   — Non-linear substitution via a fixed lookup table (S-Box)
  2. ShiftRows  — Cyclic shift of rows in the 4×4 state matrix
  3. MixColumns — Column-wise mixing using Galois Field GF(2⁸) multiplication
  4. AddRoundKey — XOR the state with the round-specific subkey

Mode of Operation: CBC (Cipher Block Chaining)
  - A random 16-byte IV (Initialisation Vector) is XOR-ed with each plaintext
    block before encryption.
  - This ensures identical plaintext blocks produce different ciphertext blocks.
  - The IV is not secret — it is prepended to the ciphertext output.

Storage format: "<iv_hex>|<ciphertext_hex>"

Author note: All look-up tables below are derived from AES standard.
"""

import os


# ============================================================================
# AES CONSTANTS — S-Box, Inverse S-Box, Rcon
# ============================================================================

# The AES S-Box: a 256-entry substitution table derived from the multiplicative
# inverse in GF(2⁸) followed by an affine transformation.
# During SubBytes, each byte in the state is replaced by the corresponding
# entry: new_byte = SBOX[old_byte].
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse S-Box: used in InvSubBytes during decryption.
# SBOX_INV[SBOX[b]] == b for every byte b.
SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i

# Round Constant (Rcon) table used in key expansion.
# Rcon[i] = [x^(i-1), 0x00, 0x00, 0x00] in GF(2⁸), where x = 0x02.
# Only the first word (first byte) varies; the rest are always 0x00.
RCON = [
    0x00,  # placeholder — Rcon index starts at 1
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d,       # enough for AES-256 (needs 7 rcon values)
]


# ============================================================================
# GALOIS FIELD GF(2⁸) ARITHMETIC
# ============================================================================

def _xtime(b: int) -> int:
    """
    Multiply a byte 'b' by 2 in GF(2⁸).

    In GF(2⁸), multiplication by 2 (the polynomial x) is a left shift by 1
    bit. If the high bit was set, we XOR with 0x1b to reduce modulo the
    irreducible polynomial x⁸ + x⁴ + x³ + x + 1 (= 0x11b).

    This operation is the fundamental building block of MixColumns.
    """
    # Left-shift by 1; if bit-7 was 1, XOR with 0x1b to stay in GF(2⁸)
    return ((b << 1) ^ 0x1b) & 0xff if (b & 0x80) else (b << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    """
    Multiply two bytes in GF(2⁸) using the 'peasant's algorithm' (also called
    Russian peasant multiplication or binary method).

    How it works:
      - If the lowest bit of b is 1, XOR the current 'a' into the result.
      - Multiply 'a' by 2 (using _xtime), and right-shift b by 1.
      - Repeat until b == 0.

    This is equivalent to polynomial multiplication modulo the AES irreducible
    polynomial. Used exclusively in MixColumns.
    """
    result = 0
    for _ in range(8):
        if b & 1:                  # if current bit of b is set, add 'a'
            result ^= a
        a = _xtime(a)              # a = a * 2 in GF(2⁸)
        b >>= 1                    # move to next bit of b
    return result


# ============================================================================
# STATE MATRIX HELPERS
# ============================================================================

def _bytes_to_state(block: bytes) -> list:
    """
    Convert 16 bytes into a 4×4 state matrix (column-major order).

    AES defines the state as a 4-row, 4-column matrix of bytes.
    Bytes are filled column by column:
      state[row][col] = block[row + 4*col]

    Example for block = [b0, b1, ..., b15]:
      state = [[b0,  b4,  b8,  b12],
               [b1,  b5,  b9,  b13],
               [b2,  b6,  b10, b14],
               [b3,  b7,  b11, b15]]
    """
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list) -> bytes:
    """
    Flatten a 4×4 state matrix back to 16 bytes (column-major order).
    This is the inverse of _bytes_to_state.
    """
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ============================================================================
# AES ROUND OPERATIONS
# ============================================================================

def sub_bytes(state: list) -> list:
    """
    SubBytes — Non-linear byte substitution.

    Every byte in the 4×4 state is independently replaced by the corresponding
    value in the AES S-Box. This provides the non-linearity (confusion) that
    makes AES resistant to algebraic attacks.

    For viva: The S-Box value for any byte b is computed as:
        1. Find the multiplicative inverse of b in GF(2⁸).
        2. Apply an affine transformation over GF(2).
    We use the pre-computed lookup table SBOX[] for efficiency.
    """
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: list) -> list:
    """
    InvSubBytes — Inverse of SubBytes, used during decryption.
    Applies the inverse S-Box (SBOX_INV) to each byte of the state.
    """
    return [[SBOX_INV[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: list) -> list:
    """
    ShiftRows — Cyclic shift of each row.

    The four rows of the state are shifted left by 0, 1, 2, and 3 bytes:
      Row 0: no shift      [a, b, c, d] → [a, b, c, d]
      Row 1: shift left 1  [a, b, c, d] → [b, c, d, a]
      Row 2: shift left 2  [a, b, c, d] → [c, d, a, b]
      Row 3: shift left 3  [a, b, c, d] → [d, a, b, c]

    Together with MixColumns, ShiftRows ensures that bytes from every column
    are spread across all columns after a few rounds (diffusion).
    """
    new_state = [row[:] for row in state]
    for r in range(1, 4):
        new_state[r] = state[r][r:] + state[r][:r]   # rotate left by r
    return new_state


def inv_shift_rows(state: list) -> list:
    """
    InvShiftRows — Reverse of ShiftRows, used during decryption.
    Rows are shifted RIGHT by 0, 1, 2, and 3 positions.
    """
    new_state = [row[:] for row in state]
    for r in range(1, 4):
        new_state[r] = state[r][4 - r:] + state[r][:4 - r]   # rotate right by r
    return new_state


def mix_columns(state: list) -> list:
    """
    MixColumns — Linear mixing of each column.

    Each column of the state is treated as a polynomial over GF(2⁸) and
    multiplied with a fixed matrix:

      [2  3  1  1]   [s0]   [c0]
      [1  2  3  1] × [s1] = [c1]
      [1  1  2  3]   [s2]   [c2]
      [3  1  1  2]   [s3]   [c3]

    The multiplications 2× and 3× are in GF(2⁸). Addition is XOR.
    This operation provides diffusion — each output byte depends on all 4
    input bytes of the column.

    For viva: 3×b in GF(2⁸) = _xtime(b) XOR b  (i.e., 2b + b in GF(2⁸))
    """
    new_state = [row[:] for row in state]
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]
        # GF(2⁸) arithmetic — addition is XOR, multiplication via _xtime/_gmul
        new_state[0][c] = _xtime(s0) ^ (_xtime(s1) ^ s1) ^ s2 ^ s3
        new_state[1][c] = s0 ^ _xtime(s1) ^ (_xtime(s2) ^ s2) ^ s3
        new_state[2][c] = s0 ^ s1 ^ _xtime(s2) ^ (_xtime(s3) ^ s3)
        new_state[3][c] = (_xtime(s0) ^ s0) ^ s1 ^ s2 ^ _xtime(s3)
    return new_state


def inv_mix_columns(state: list) -> list:
    """
    InvMixColumns — Inverse of MixColumns, used during decryption.

    Multiplied with the inverse matrix:
      [14  11  13   9]
      [ 9  14  11  13]
      [13   9  14  11]
      [11  13   9  14]

    The coefficients (14, 11, 13, 9) are hex (0x0e, 0x0b, 0x0d, 0x09) and
    are used as multipliers in GF(2⁸) via _gmul().
    """
    new_state = [row[:] for row in state]
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]
        new_state[0][c] = _gmul(s0, 0x0e) ^ _gmul(s1, 0x0b) ^ _gmul(s2, 0x0d) ^ _gmul(s3, 0x09)
        new_state[1][c] = _gmul(s0, 0x09) ^ _gmul(s1, 0x0e) ^ _gmul(s2, 0x0b) ^ _gmul(s3, 0x0d)
        new_state[2][c] = _gmul(s0, 0x0d) ^ _gmul(s1, 0x09) ^ _gmul(s2, 0x0e) ^ _gmul(s3, 0x0b)
        new_state[3][c] = _gmul(s0, 0x0b) ^ _gmul(s1, 0x0d) ^ _gmul(s2, 0x09) ^ _gmul(s3, 0x0e)
    return new_state


def add_round_key(state: list, round_key: list) -> list:
    """
    AddRoundKey — XOR the state with the current round key.

    The round key is a 4×4 matrix derived from the original key via key
    expansion. XOR is its own inverse, so the same operation is used for
    both encryption and decryption (just use the corresponding round key).

    For viva: This is the ONLY step that involves the key — it is what makes
    AES a keyed cipher (rather than just a permutation).
    """
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# ============================================================================
# KEY EXPANSION (AES-256 KEY SCHEDULE)
# ============================================================================

def key_expansion(key_bytes: bytes) -> list:
    """
    Key Expansion — derive 15 round keys (480 bytes) from the 32-byte key.

    AES-256 uses 14 rounds, requiring 15 round keys (one initial + 14).
    Each round key is 128 bits (16 bytes) = one 4×4 state matrix.

    The key schedule operates on 32-bit 'words' (4 bytes each):
      - The original 32-byte key provides the first 8 words: W[0]..W[7].
      - Subsequent words are generated as follows:
          For i ≥ 8:
            temp = W[i-1]
            if i % 8 == 0:
                temp = SubWord(RotWord(temp)) XOR Rcon[i/8]
            elif i % 8 == 4:
                temp = SubWord(temp)          ← AES-256 extra SubWord step
            W[i] = W[i-8] XOR temp

    RotWord: circular left-rotate a 4-byte word by one byte.
    SubWord: apply SBOX to each byte of the word.

    Returns a list of 15 round keys, each as a 4×4 list of ints.
    """
    assert len(key_bytes) == 32, "AES-256 requires exactly a 32-byte key"

    Nk = 8    # Number of 32-bit words in the key  (256 / 32 = 8)
    Nr = 14   # Number of rounds for AES-256
    Nb = 4    # Number of 32-bit words in a state block (always 4 for AES)

    # Initialise W with the key bytes as words (each word = list of 4 bytes)
    W = []
    for i in range(Nk):
        W.append(list(key_bytes[4 * i: 4 * i + 4]))

    # Expand to (Nr + 1) * Nb = 15 * 4 = 60 words
    for i in range(Nk, Nb * (Nr + 1)):
        temp = W[i - 1][:]          # Copy last word

        if i % Nk == 0:
            # RotWord: [a, b, c, d] → [b, c, d, a]
            temp = temp[1:] + temp[:1]
            # SubWord: apply S-Box to each byte
            temp = [SBOX[b] for b in temp]
            # XOR with round constant (only first byte of Rcon)
            temp[0] ^= RCON[i // Nk]

        elif i % Nk == 4:
            # AES-256 only: extra SubWord step at positions 4, 12, 20, …
            temp = [SBOX[b] for b in temp]

        # New word = word 8 positions back XOR temp
        W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])

    # Convert flat word list into 15 round keys, each as 4×4 state matrix
    round_keys = []
    for rk_idx in range(Nr + 1):
        # Round key rk_idx uses words W[rk_idx*4 .. rk_idx*4+3]
        rk_words = W[rk_idx * 4: rk_idx * 4 + 4]
        # Build column-major 4×4 matrix: rk[row][col] = word_col[row]
        rk_matrix = [[rk_words[c][r] for c in range(4)] for r in range(4)]
        round_keys.append(rk_matrix)

    return round_keys


# ============================================================================
# BLOCK-LEVEL ENCRYPT / DECRYPT
# ============================================================================

def encrypt_block(plaintext_block: bytes, round_keys: list) -> bytes:
    """
    Encrypt a single 16-byte block using AES-256.

    AES-256 Encryption Algorithm (14 rounds):
    ──────────────────────────────────────────
    1. Initial Round Key Addition (Round 0):
         state = plaintext XOR round_key[0]

    2. Rounds 1 – 13 (Main Rounds):
         SubBytes → ShiftRows → MixColumns → AddRoundKey

    3. Final Round (Round 14) — MixColumns is OMITTED:
         SubBytes → ShiftRows → AddRoundKey

    The omission of MixColumns in the final round is by design in the AES
    specification — it keeps encryption and decryption structurally symmetric.

    Returns 16 encrypted bytes.
    """
    state = _bytes_to_state(plaintext_block)

    # ── Initial round: just XOR with round key 0 ─────────────────────────
    state = add_round_key(state, round_keys[0])

    # ── Main rounds 1..13 ────────────────────────────────────────────────
    for round_num in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])

    # ── Final round 14: NO MixColumns ────────────────────────────────────
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[14])

    return _state_to_bytes(state)


def decrypt_block(ciphertext_block: bytes, round_keys: list) -> bytes:
    """
    Decrypt a single 16-byte block using AES-256.

    AES-256 Decryption Algorithm (Equivalent Inverse Cipher):
    ──────────────────────────────────────────────────────────
    Apply the inverse operations in reverse order:

    1. Initial: state = ciphertext XOR round_key[14]
    2. Rounds 13..1:
         InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
    3. Final Round 0:
         InvShiftRows → InvSubBytes → AddRoundKey (no InvMixColumns)

    Returns 16 decrypted bytes.
    """
    state = _bytes_to_state(ciphertext_block)

    # ── Initial step: XOR with last round key ────────────────────────────
    state = add_round_key(state, round_keys[14])

    # ── Inverse main rounds 13..1 ────────────────────────────────────────
    for round_num in range(13, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)

    # ── Final inverse round (round 0): no InvMixColumns ──────────────────
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# ============================================================================
# PKCS#7 PADDING
# ============================================================================

def pad(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding to make data length a multiple of 16 bytes.

    PKCS#7 rule: append N bytes each with value N, where N = 16 - (len % 16).
    If data is already a multiple of 16, append a full 16-byte padding block
    (so padding is always present and always removable unambiguously).

    Example: "HELLO" (5 bytes) → "HELLO" + b'\\x0b' * 11  (total 16 bytes)
    """
    pad_len = 16 - (len(data) % 16)   # 1..16
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from decrypted bytes.

    The last byte tells us how many padding bytes were appended.
    Validates that all padding bytes have the correct value.

    Raises ValueError if padding is malformed (indicates wrong key / corruption).
    """
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    # Verify all padding bytes are consistent
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PKCS#7 padding verification failed (wrong key?)")
    return data[:-pad_len]


# ============================================================================
# CBC MODE — FULL ENCRYPT / DECRYPT
# ============================================================================

def encrypt_cbc(plaintext: str, key_hex: str) -> str:
    """
    Encrypt a UTF-8 plaintext string with AES-256 in CBC mode.

    Parameters:
        plaintext : The string to encrypt (any UTF-8 text).
        key_hex   : 64-character hex string representing the 32-byte AES key.

    Steps:
        1. Decode the hex key to 32 bytes.
        2. Generate a random 16-byte IV (Initialisation Vector).
        3. Encode plaintext to UTF-8 bytes and apply PKCS#7 padding.
        4. Expand the key into 15 round keys.
        5. For each 16-byte plaintext block:
               cipherblock = encrypt_block(plainblock XOR prev_cipherblock, rk)
           The first block XORs with the IV.
        6. Return "<iv_hex>|<ciphertext_hex>"

    The IV is public (not secret) but must be unique per encryption.
    """
    if not plaintext:
        return ""

    key_bytes  = bytes.fromhex(key_hex)         # 32-byte AES-256 key
    iv         = os.urandom(16)                 # Fresh random IV per encryption
    round_keys = key_expansion(key_bytes)       # Derive 15 round keys

    data       = pad(plaintext.encode('utf-8')) # Pad to 16-byte boundary
    prev_block = iv                             # CBC chain starts with IV
    ciphertext = bytearray()

    # Process one 16-byte block at a time
    for block_start in range(0, len(data), 16):
        block      = data[block_start: block_start + 16]
        xored      = bytes(b ^ p for b, p in zip(block, prev_block))  # CBC XOR
        encrypted  = encrypt_block(xored, round_keys)
        ciphertext.extend(encrypted)
        prev_block = encrypted   # Each ciphertext block chains the next

    # Return IV prepended to ciphertext, both as hex, separated by |
    return iv.hex() + '|' + ciphertext.hex()


def decrypt_cbc(ciphertext_hex: str, key_hex: str) -> str:
    """
    Decrypt a hex-encoded AES-256 CBC ciphertext string.

    Parameters:
        ciphertext_hex : "<iv_hex>|<ct_hex>" as returned by encrypt_cbc().
        key_hex        : 64-character hex string (the same key used to encrypt).

    Steps:
        1. Split the string to extract IV and ciphertext bytes.
        2. Decode the hex key to 32 bytes.
        3. Expand the key to round keys.
        4. For each 16-byte ciphertext block:
               plainblock = decrypt_block(cipherblock) XOR prev_cipherblock
           The first block XORs with the IV.
        5. Remove PKCS#7 padding and decode UTF-8.

    Raises ValueError on wrong key, corrupted ciphertext, or bad padding.
    """
    if not ciphertext_hex:
        return ""

    try:
        iv_hex, ct_hex = ciphertext_hex.split('|', 1)
        iv         = bytes.fromhex(iv_hex)
        ct_bytes   = bytes.fromhex(ct_hex)
        key_bytes  = bytes.fromhex(key_hex)
    except Exception as exc:
        raise ValueError(f"Malformed ciphertext or key: {exc}") from exc

    round_keys = key_expansion(key_bytes)
    prev_block = iv
    plaintext  = bytearray()

    for block_start in range(0, len(ct_bytes), 16):
        block     = ct_bytes[block_start: block_start + 16]
        decrypted = decrypt_block(block, round_keys)
        xored     = bytes(b ^ p for b, p in zip(decrypted, prev_block))  # CBC XOR
        plaintext.extend(xored)
        prev_block = block   # Next block XORs with this ciphertext block

    return unpad(bytes(plaintext)).decode('utf-8')


# ============================================================================
# KEY GENERATION
# ============================================================================

def generate_aes_key() -> str:
    """
    Generate a cryptographically random 256-bit AES key.

    Uses os.urandom(32) — 32 bytes = 256 bits — which reads from the
    operating system's cryptographically secure random number generator
    (e.g., /dev/urandom on Linux, CryptGenRandom on Windows).

    Returns the key as a 64-character lowercase hex string for easy storage
    in the database.
    """
    return os.urandom(32).hex()


# ============================================================================
# ROUND TRACE — For the AES Demo Page
# ============================================================================

def get_round_trace(plaintext: str, key_hex: str) -> dict:
    """
    Produce a round-by-round trace of AES-256 encryption for educational display.

    This function encrypts only the FIRST 16-byte block of the padded plaintext
    and captures the state matrix after each operation in each round.

    Returns a dict suitable for JSON serialisation:
    {
        'key'       : '...64 hex chars...',
        'plaintext' : '...hex...',
        'iv'        : '...hex...',
        'rounds'    : [
            {
                'round_num'   : 0,
                'label'       : 'Initial Round Key Addition',
                'state_before': [[...4×4 ints...]],
                'state_after' : [[...4×4 ints...]],
            },
            {
                'round_num'   : 1,
                'label'       : 'Round 1',
                'after_sub'   : [...],
                'after_shift' : [...],
                'after_mix'   : [...],
                'after_rk'    : [...],
            },
            ...
        ],
        'ciphertext' : '...hex...',
    }
    """
    key_bytes  = bytes.fromhex(key_hex)
    round_keys = key_expansion(key_bytes)

    # Pad and take the first 16-byte block only
    iv         = os.urandom(16)
    data       = pad(plaintext.encode('utf-8'))
    first_block = data[:16]

    # CBC XOR with IV for the first block
    plain_block = bytes(b ^ p for b, p in zip(first_block, iv))

    def state_to_hex_grid(state):
        """Return state as a list of 4 rows, each a list of 2-char hex strings."""
        return [[f"{state[r][c]:02x}" for c in range(4)] for r in range(4)]

    rounds_trace = []
    state = _bytes_to_state(plain_block)

    # ── Round 0: AddRoundKey only ─────────────────────────────────────────
    before = state_to_hex_grid(state)
    state  = add_round_key(state, round_keys[0])
    rounds_trace.append({
        'round_num'   : 0,
        'label'       : 'Initial AddRoundKey (Round 0)',
        'operation'   : 'AddRoundKey',
        'state_before': before,
        'state_after' : state_to_hex_grid(state),
        'round_key'   : state_to_hex_grid(round_keys[0]),
    })

    # ── Rounds 1–13 ───────────────────────────────────────────────────────
    for rnd in range(1, 14):
        after_sub   = sub_bytes(state);          state = after_sub
        after_shift = shift_rows(state);         state = after_shift
        after_mix   = mix_columns(state);        state = after_mix
        state       = add_round_key(state, round_keys[rnd])

        rounds_trace.append({
            'round_num'  : rnd,
            'label'      : f'Round {rnd}',
            'after_sub'  : state_to_hex_grid(after_sub),
            'after_shift': state_to_hex_grid(after_shift),
            'after_mix'  : state_to_hex_grid(after_mix),
            'after_rk'   : state_to_hex_grid(state),
            'round_key'  : state_to_hex_grid(round_keys[rnd]),
        })

    # ── Round 14 (final): no MixColumns ──────────────────────────────────
    after_sub   = sub_bytes(state);          state = after_sub
    after_shift = shift_rows(state);         state = after_shift
    state       = add_round_key(state, round_keys[14])
    rounds_trace.append({
        'round_num'  : 14,
        'label'      : 'Round 14 (Final — no MixColumns)',
        'after_sub'  : state_to_hex_grid(after_sub),
        'after_shift': state_to_hex_grid(after_shift),
        'after_mix'  : None,    # Omitted in final round
        'after_rk'   : state_to_hex_grid(state),
        'round_key'  : state_to_hex_grid(round_keys[14]),
    })

    ciphertext = _state_to_bytes(state).hex()

    return {
        'key'        : key_hex,
        'plaintext'  : plain_block.hex(),
        'iv'         : iv.hex(),
        'num_rounds' : 14,
        'rounds'     : rounds_trace,
        'ciphertext' : ciphertext,
    }


# ============================================================================
# SUBBYTES STEP TRACE — For the AES Internals Explorer
# ============================================================================

def trace_sub_bytes(state_hex_flat: str) -> dict:
    """
    Given a 32-hex-char (16-byte) flat state, apply SubBytes and return
    before/after for each byte position — used by the Internals Explorer.
    """
    raw = bytes.fromhex(state_hex_flat.replace(' ', ''))[:16]
    before = list(raw)
    after  = [SBOX[b] for b in before]
    return {
        'before': [f"{b:02x}" for b in before],
        'after' : [f"{b:02x}" for b in after],
        'sbox_indices': before,
    }


def trace_shift_rows(state_hex_flat: str) -> dict:
    """
    Given a 32-hex-char flat state, apply ShiftRows and return
    before/after as 4×4 grids — used by the Internals Explorer.
    """
    raw   = bytes.fromhex(state_hex_flat.replace(' ', ''))[:16]
    state = _bytes_to_state(raw)
    after = shift_rows(state)
    return {
        'before': [[f"{state[r][c]:02x}" for c in range(4)] for r in range(4)],
        'after' : [[f"{after[r][c]:02x}"  for c in range(4)] for r in range(4)],
        'shifts': [0, 1, 2, 3],
    }


def trace_mix_columns(state_hex_flat: str) -> dict:
    """
    Given a 32-hex-char flat state, apply MixColumns and return
    before/after as 4×4 grids — used by the Internals Explorer.
    """
    raw   = bytes.fromhex(state_hex_flat.replace(' ', ''))[:16]
    state = _bytes_to_state(raw)
    after = mix_columns(state)
    return {
        'before': [[f"{state[r][c]:02x}" for c in range(4)] for r in range(4)],
        'after' : [[f"{after[r][c]:02x}"  for c in range(4)] for r in range(4)],
    }


def trace_key_schedule(key_hex: str) -> dict:
    """
    Given a 64-hex-char (32-byte) key, return the first 5 round keys
    as 4×4 hex grids — used by the Internals Explorer.
    """
    key_bytes  = bytes.fromhex(key_hex)
    round_keys = key_expansion(key_bytes)
    result = []
    for i, rk in enumerate(round_keys[:5]):   # Show first 5 round keys
        result.append({
            'round': i,
            'key'  : [[f"{rk[r][c]:02x}" for c in range(4)] for r in range(4)],
        })
    return {'round_keys': result, 'total_rounds': 14}


# ============================================================================
# SELF-TEST (run this file directly: python aes256.py)
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  AES-256 Manual Implementation — Self-Test")
    print("=" * 60)

    # ── Test 1: Key generation ────────────────────────────────────────────
    key = generate_aes_key()
    print(f"\n[1] Generated AES-256 key (64 hex chars):\n    {key}")

    # ── Test 2: Basic round-trip ──────────────────────────────────────────
    messages = [
        "Hello, AES-256!",
        "admin@bmsce.ac.in",
        "Short",
        "A" * 32,     # Multi-block message
        "Unicode: ₹ © ™",
    ]
    print("\n[2] Round-trip encryption/decryption tests:")
    all_pass = True
    for msg in messages:
        ct = encrypt_cbc(msg, key)
        pt = decrypt_cbc(ct, key)
        ok = (pt == msg)
        all_pass = all_pass and ok
        status = "✔ PASS" if ok else "✘ FAIL"
        print(f"    {status}  '{msg[:30]}' → '{ct[:40]}…'")

    # ── Test 3: Wrong key produces error or garbage ───────────────────────
    print("\n[3] Wrong key test:")
    ct  = encrypt_cbc("TOP SECRET DATA", key)
    wrong_key = generate_aes_key()
    try:
        bad = decrypt_cbc(ct, wrong_key)
        print(f"    Result with wrong key: '{bad[:30]}' (should be garbage or error)")
    except Exception as e:
        print(f"    ✔ Wrong key raised error as expected: {type(e).__name__}: {e}")

    print(f"\n{'All round-trip tests PASSED ✔' if all_pass else 'SOME TESTS FAILED ✘'}")
    print("=" * 60)

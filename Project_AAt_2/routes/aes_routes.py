"""
routes/aes_routes.py
====================
Blueprint for the AES-256 JSON API, consumed by the educational modules
(aes_demo.html and aes_internals.html) via JavaScript fetch() calls.
All computation is performed by aes256.py.
"""

from flask import Blueprint, request, jsonify
import aes256

aes_bp = Blueprint('aes', __name__, url_prefix='/api/aes')


@aes_bp.route('/encrypt', methods=['POST'])
def api_encrypt():
    """
    Encrypt a plaintext string using the manually implemented AES-256 CBC cipher.
    Request JSON:  { "text": "plain text", "key": "64_hex_char_key" }
    Response JSON: { "ciphertext": "iv_hex|ct_hex" }
    """
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key  = data.get('key',  '')

    if not text or not key:
        return jsonify({'error': 'Both text and key are required'}), 400
    if len(key) != 64:
        return jsonify({'error': 'Key must be a 64-character hex string (256-bit)'}), 400

    try:
        ciphertext = aes256.encrypt_cbc(text, key)
        return jsonify({'ciphertext': ciphertext})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@aes_bp.route('/decrypt', methods=['POST'])
def api_decrypt():
    """
    Decrypt an AES-256 CBC ciphertext string.
    Request JSON:  { "text": "iv_hex|ct_hex", "key": "64_hex_char_key" }
    Response JSON: { "plaintext": "plain text" }
    """
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key  = data.get('key',  '')

    if not text or not key:
        return jsonify({'error': 'Both text and key are required'}), 400
    if len(key) != 64:
        return jsonify({'error': 'Key must be a 64-character hex string (256-bit)'}), 400

    try:
        plaintext = aes256.decrypt_cbc(text, key)
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@aes_bp.route('/trace/rounds', methods=['POST'])
def api_trace_rounds():
    """
    Generate a complete round-by-round trace of the first 16 bytes.
    Request JSON:  { "text": "plain text", "key": "64_hex_char_key" }
    Response JSON: Trace dictionary containing details for all 14 rounds.
    """
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key  = data.get('key',  '')

    if not text or not key:
        return jsonify({'error': 'Both text and key are required'}), 400
    if len(key) != 64:
        return jsonify({'error': 'Key must be a 64-character hex string (256-bit)'}), 400

    try:
        trace = aes256.get_round_trace(text, key)
        return jsonify(trace)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@aes_bp.route('/trace/subbytes', methods=['POST'])
def api_trace_subbytes():
    """
    Trace SubBytes S-Box substitution for a 32-hex-char flat state.
    Request JSON:  { "state": "32_hex_chars" }
    Response JSON: { "before", "after", "sbox_indices" }
    """
    data  = request.get_json(silent=True) or {}
    state = data.get('state', '')

    if not state or len(state.replace(' ', '')) != 32:
        return jsonify({'error': 'State must be a 32-character hex string (16 bytes)'}), 400

    try:
        trace = aes256.trace_sub_bytes(state)
        return jsonify(trace)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@aes_bp.route('/trace/shiftrows', methods=['POST'])
def api_trace_shiftrows():
    """
    Trace ShiftRows row rotations for a 32-hex-char flat state.
    Request JSON:  { "state": "32_hex_chars" }
    Response JSON: { "before", "after", "shifts" }
    """
    data  = request.get_json(silent=True) or {}
    state = data.get('state', '')

    if not state or len(state.replace(' ', '')) != 32:
        return jsonify({'error': 'State must be a 32-character hex string (16 bytes)'}), 400

    try:
        trace = aes256.trace_shift_rows(state)
        return jsonify(trace)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@aes_bp.route('/trace/mixcolumns', methods=['POST'])
def api_trace_mixcolumns():
    """
    Trace MixColumns GF(2⁸) column mixing for a 32-hex-char flat state.
    Request JSON:  { "state": "32_hex_chars" }
    Response JSON: { "before", "after" }
    """
    data  = request.get_json(silent=True) or {}
    state = data.get('state', '')

    if not state or len(state.replace(' ', '')) != 32:
        return jsonify({'error': 'State must be a 32-character hex string (16 bytes)'}), 400

    try:
        trace = aes256.trace_mix_columns(state)
        return jsonify(trace)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@aes_bp.route('/trace/keyschedule', methods=['POST'])
def api_trace_keyschedule():
    """
    Trace the first 5 round keys expansion for a 64-hex-char key.
    Request JSON:  { "key": "64_hex_char_key" }
    Response JSON: { "round_keys": [...], "total_rounds": 14 }
    """
    data = request.get_json(silent=True) or {}
    key  = data.get('key', '')

    if not key or len(key) != 64:
        return jsonify({'error': 'Key must be a 64-character hex string (256-bit)'}), 400

    try:
        trace = aes256.trace_key_schedule(key)
        return jsonify(trace)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

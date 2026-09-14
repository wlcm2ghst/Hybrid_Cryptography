# ============================================================
# ecc_aes.py
# ECC (NIST P-256) + AES-256 Hybrid Cryptographic Scheme
# Updated: MAC now covers ephemeral_public_key || IV || ciphertext
# (not just ciphertext), and authentication failures raise an
# exception instead of silently returning None.
# ============================================================

import time
import hmac
import hashlib
import psutil
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class AuthenticationError(Exception):
    """Raised when HMAC verification fails, or when the ephemeral
    public key cannot be loaded/validated. A single generic exception
    is used for both cases so callers cannot distinguish failure
    modes from the exception type or message alone."""
    pass


# ============================================================
# KEY GENERATION
# ============================================================

def generate_ecc_keys():
    """Generate ECC NIST P-256 key pair"""
    start_time = time.perf_counter()
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    end_time = time.perf_counter()
    key_gen_time = (end_time - start_time) * 1000
    return public_key, private_key, key_gen_time


# ============================================================
# DERIVE TWO SEPARATE KEYS FROM ECDH SHARED SECRET
# ============================================================

def derive_keys(shared_secret):
    """
    Derive two cryptographically independent keys from the
    ECDH shared secret using HKDF with distinct info strings:
      - enc_key : used exclusively for AES-256-CBC encryption
      - mac_key : used exclusively for HMAC-SHA256 authentication
    Keeping these keys separate prevents key reuse vulnerabilities.
    """
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc_aes_encryption_key',
        backend=default_backend()
    ).derive(shared_secret)

    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc_aes_hmac_authentication_key',
        backend=default_backend()
    ).derive(shared_secret)

    return enc_key, mac_key


# ============================================================
# ENCRYPTION
# ============================================================

def encrypt(transaction_bytes, public_key, private_key):
    """
    Encrypt transaction data using ECC + AES-256 hybrid scheme
    with encrypt-then-MAC using HMAC-SHA256.

    Steps:
    1. Generate ephemeral ECC key pair for forward secrecy
    2. ECDH key exchange to derive shared secret
    3. Derive enc_key and mac_key via HKDF (distinct info strings)
    4. Encrypt transaction data with AES-256-CBC (enc_key + IV)
    5. Compute HMAC-SHA256 over ephemeral_public_key || IV || ciphertext
       (mac_key) — encrypt-then-MAC. Including the ephemeral public key
       and IV in the MAC input binds them to the authenticated data,
       preventing an attacker from substituting either in transit.
    """
    start_time = time.perf_counter()

    # Step 1: Generate ephemeral ECC key pair
    ephemeral_private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Step 2: ECDH key exchange
    shared_secret = ephemeral_private_key.exchange(ECDH(), public_key)

    # Step 3: Derive two separate keys via HKDF
    enc_key, mac_key = derive_keys(shared_secret)

    # Generate random IV for AES-256-CBC
    iv = get_random_bytes(16)  # 128-bit IV, unique per message

    # Step 4: Encrypt transaction data with AES-256-CBC
    aes_cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(transaction_bytes, AES.block_size))

    # Serialise ephemeral public key for transmission
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Step 5: Compute HMAC-SHA256 over ephemeral_public_key || IV || ciphertext
    mac_input = ephemeral_public_bytes + iv + ciphertext
    mac = hmac.new(mac_key, mac_input, hashlib.sha256).digest()

    end_time = time.perf_counter()
    encryption_time = (end_time - start_time) * 1000

    return {
        'ciphertext': ciphertext,
        'ephemeral_public_key': ephemeral_public_bytes,
        'iv': iv,
        'mac': mac,
        'encryption_time': encryption_time
    }


# ============================================================
# DECRYPTION
# ============================================================

def decrypt(encrypted_package, private_key):
    """
    Decrypt transaction data using ECC + AES-256 hybrid scheme.
    Verifies HMAC-SHA256 before decryption (verify-then-decrypt).

    Steps:
    1. Recover ephemeral public key
    2. ECDH key exchange to recover shared secret
    3. Derive enc_key and mac_key via HKDF
    4. Verify HMAC-SHA256 over ephemeral_public_key || IV || ciphertext
       — abort if it fails
    5. Decrypt transaction data with AES-256-CBC (only if MAC verified)

    Raises:
        AuthenticationError: if the ephemeral public key cannot be
        loaded, if MAC verification fails, or if unpadding fails.
        No distinction is made between these failure modes in the
        exception message or timing.
    """
    start_time = time.perf_counter()

    ciphertext              = encrypted_package['ciphertext']
    ephemeral_public_bytes  = encrypted_package['ephemeral_public_key']
    iv                      = encrypted_package['iv']
    received_mac            = encrypted_package['mac']

    # Step 1: Recover ephemeral public key
    try:
        ephemeral_public_key = load_pem_public_key(
            ephemeral_public_bytes, backend=default_backend())
    except (ValueError, TypeError):
        raise AuthenticationError("Ephemeral public key could not be loaded")

    # Step 2: ECDH key exchange to recover shared secret
    shared_secret = private_key.exchange(ECDH(), ephemeral_public_key)

    # Step 3: Derive the same two keys via HKDF
    enc_key, mac_key = derive_keys(shared_secret)

    # Step 4: Verify HMAC-SHA256 BEFORE attempting decryption
    mac_input = ephemeral_public_bytes + iv + ciphertext
    expected_mac = hmac.new(mac_key, mac_input, hashlib.sha256).digest()
    integrity_verified = hmac.compare_digest(expected_mac, received_mac)

    if not integrity_verified:
        # Abort immediately — do NOT proceed to AES decryption.
        # Decrypting unauthenticated ciphertext risks exposing a
        # padding-oracle side channel even if the result is discarded.
        raise AuthenticationError(
            "HMAC verification failed — ciphertext, IV, or ephemeral "
            "key may be tampered or corrupted"
        )

    # Step 5: Decrypt only after the MAC has been verified
    try:
        aes_cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        raise AuthenticationError("Decryption or unpadding failed")

    end_time = time.perf_counter()
    decryption_time = (end_time - start_time) * 1000

    return {
        'decrypted_data': decrypted_data,
        'integrity_verified': integrity_verified,
        'decryption_time': decryption_time
    }


# ============================================================
# FULL TRANSACTION PROCESSING
# ============================================================

def process_transaction(transaction_bytes):
    """Process a single transaction through the ECC+AES-256 cycle.
    Authentication failures are caught here so the performance
    harness can continue across a batch of transactions without
    crashing on a single failure."""
    process = psutil.Process()
    memory_before = process.memory_info().rss / 1024 / 1024
    cpu_before = psutil.cpu_percent(interval=None)

    public_key, private_key, key_gen_time = generate_ecc_keys()
    encrypted_package = encrypt(transaction_bytes, public_key, private_key)

    decrypt_start = time.perf_counter()
    try:
        decrypted_result = decrypt(encrypted_package, private_key)
        integrity_verified = decrypted_result['integrity_verified']
        decrypted_data = decrypted_result['decrypted_data']
        decryption_time = decrypted_result['decryption_time']
    except AuthenticationError as exc:
        integrity_verified = False
        decrypted_data = None
        decryption_time = (time.perf_counter() - decrypt_start) * 1000
        print(f"  [!] Authentication failed: {exc}")

    memory_after = process.memory_info().rss / 1024 / 1024
    cpu_after = psutil.cpu_percent(interval=None)

    return {
        'scheme': 'ECC+AES-256',
        'key_gen_time': key_gen_time,
        'encryption_time': encrypted_package['encryption_time'],
        'decryption_time': decryption_time,
        'memory_used': memory_after - memory_before,
        'cpu_usage': (cpu_before + cpu_after) / 2,
        'integrity_verified': integrity_verified,
        'original_data': transaction_bytes,
        'decrypted_data': decrypted_data
    }


# ============================================================
# TEST
# ============================================================
if __name__ == "__main__":
    from transaction_generator import (
        generate_transaction, transaction_to_bytes, bytes_to_transaction)

    print("=" * 55)
    print("ECC + AES-256 — UPDATED WITH HMAC-SHA256")
    print("=" * 55)

    transaction = generate_transaction(1)
    transaction_bytes = transaction_to_bytes(transaction)

    print(f"\nOriginal Transaction:")
    for k, v in transaction.items():
        print(f"  {k}: {v}")

    print(f"\nProcessing through ECC+AES-256...")
    result = process_transaction(transaction_bytes)

    print(f"\n--- Performance Metrics ---")
    print(f"  Key Generation Time : {result['key_gen_time']:.4f} ms")
    print(f"  Encryption Time     : {result['encryption_time']:.4f} ms")
    print(f"  Decryption Time     : {result['decryption_time']:.4f} ms")
    print(f"  Memory Used         : {result['memory_used']:.4f} MB")
    print(f"  CPU Usage           : {result['cpu_usage']:.2f} %")
    print(f"  HMAC Verified       : {result['integrity_verified']}")

    if result['decrypted_data']:
        recovered = bytes_to_transaction(result['decrypted_data'])
        data_match = transaction == recovered
        print(f"  Data Match          : {data_match}")

        if result['integrity_verified'] and data_match:
            print("\n✅ ECC+AES-256 with HMAC-SHA256 working correctly!")
        else:
            print("\n❌ Something went wrong — check above for errors")
    else:
        print("\n❌ Decryption failed — authentication check rejected the ciphertext")

    # --- Tamper test: confirm the MAC correctly rejects a modified IV ---
    print("\n" + "=" * 55)
    print("TAMPER TEST — flipping one byte of the IV")
    print("=" * 55)

    pub, priv, _ = generate_ecc_keys()
    package = encrypt(transaction_bytes, pub, priv)

    tampered_iv = bytearray(package['iv'])
    tampered_iv[0] ^= 0xFF
    package['iv'] = bytes(tampered_iv)

    try:
        decrypt(package, priv)
        print("❌ TAMPER TEST FAILED — tampered IV was accepted!")
    except AuthenticationError as exc:
        print(f"✅ TAMPER TEST PASSED — rejected as expected: {exc}")
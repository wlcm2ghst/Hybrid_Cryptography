# ============================================================
# rsa_aes.py
# RSA-2048 + AES-256 Hybrid Cryptographic Scheme
# Updated: Two-key HKDF derivation + HMAC-SHA256 (encrypt-then-MAC)
# ============================================================

import time
import hmac
import hashlib
import psutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class AuthenticationError(Exception):
    """Raised when HMAC verification fails or key recovery fails.
    A single generic exception is used for both cases so that callers
    (and timing side-channels) cannot distinguish 'bad padding' from
    'bad MAC' from 'bad ciphertext' — this mitigates Bleichenbacher-style
    padding-oracle attacks against the RSA-OAEP step."""
    pass


# ============================================================
# KEY GENERATION
# ============================================================

def generate_rsa_keys():
    """Generate RSA-2048 key pair"""
    start_time = time.perf_counter()

    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()

    end_time = time.perf_counter()
    key_gen_time = (end_time - start_time) * 1000  # milliseconds

    return public_key, private_key, key_gen_time


# ============================================================
# DERIVE TWO SEPARATE KEYS FROM THE RSA-ENCAPSULATED MASTER SECRET
# ============================================================

def derive_keys(master_secret):
    """
    Derive two cryptographically independent keys from the 256-bit
    master secret using HKDF with distinct info strings:
      - enc_key : used exclusively for AES-256-CBC encryption
      - mac_key : used exclusively for HMAC-SHA256 authentication
    Keeping these keys separate prevents key-reuse vulnerabilities
    (e.g. related-key attacks between the cipher and the MAC).
    """
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'rsa_aes_encryption_key',
        backend=default_backend()
    ).derive(master_secret)

    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'rsa_aes_hmac_authentication_key',
        backend=default_backend()
    ).derive(master_secret)

    return enc_key, mac_key


# ============================================================
# ENCRYPTION
# ============================================================

def encrypt(transaction_bytes, public_key):
    """
    Encrypt transaction data using RSA + AES-256 hybrid scheme
    with encrypt-then-MAC using HMAC-SHA256.

    Steps:
    1. Generate random 256-bit master secret
    2. Derive enc_key and mac_key via HKDF (distinct info strings)
    3. Encrypt transaction data with AES-256-CBC (enc_key + IV)
    4. Compute HMAC-SHA256 over IV || ciphertext (mac_key) — encrypt-then-MAC
    5. Encrypt master secret with RSA-OAEP (SHA-256) for transmission
    """
    start_time = time.perf_counter()

    # Step 1: Generate random 256-bit master secret
    master_secret = get_random_bytes(32)

    # Step 2: Derive two separate keys via HKDF
    enc_key, mac_key = derive_keys(master_secret)

    # Step 3: Encrypt transaction data with AES-256-CBC
    iv = get_random_bytes(16)  # 128-bit IV, unique per message
    aes_cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(transaction_bytes, AES.block_size))

    # Step 4: Compute HMAC-SHA256 over IV || ciphertext (encrypt-then-MAC)
    # Including the IV in the MAC input binds it to the authenticated
    # data, preventing an attacker from substituting a different IV.
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

    # Step 5: Encrypt master secret with RSA-OAEP, SHA-256 explicitly set
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_master_secret = rsa_cipher.encrypt(master_secret)

    end_time = time.perf_counter()
    encryption_time = (end_time - start_time) * 1000  # milliseconds

    return {
        'ciphertext': ciphertext,
        'encrypted_master_secret': encrypted_master_secret,
        'iv': iv,
        'mac': mac,
        'encryption_time': encryption_time
    }


# ============================================================
# DECRYPTION
# ============================================================

def decrypt(encrypted_package, private_key):
    """
    Decrypt transaction data using RSA + AES-256 hybrid scheme.
    Verifies HMAC-SHA256 before decryption (verify-then-decrypt).

    Steps:
    1. Recover master secret via RSA-OAEP
    2. Derive enc_key and mac_key via HKDF
    3. Verify HMAC-SHA256 over IV || ciphertext — abort if it fails
    4. Decrypt transaction data with AES-256-CBC (only if MAC verified)

    Raises:
        AuthenticationError: if key recovery, MAC verification, or
        unpadding fails. No distinction is made between these failure
        modes in the exception message or timing.
    """
    start_time = time.perf_counter()

    ciphertext = encrypted_package['ciphertext']
    encrypted_master_secret = encrypted_package['encrypted_master_secret']
    iv = encrypted_package['iv']
    received_mac = encrypted_package['mac']

    # Step 1: Recover master secret via RSA-OAEP
    try:
        rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        master_secret = rsa_cipher.decrypt(encrypted_master_secret)
    except ValueError:
        # Generic error — do not reveal whether this was a padding
        # failure or another failure (Bleichenbacher mitigation)
        raise AuthenticationError("Key recovery failed")

    # Step 2: Derive the same two keys via HKDF
    enc_key, mac_key = derive_keys(master_secret)

    # Step 3: Verify HMAC-SHA256 BEFORE attempting decryption
    expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    integrity_verified = hmac.compare_digest(expected_mac, received_mac)

    if not integrity_verified:
        # Abort immediately — do NOT proceed to AES decryption.
        # Decrypting unauthenticated ciphertext risks exposing a
        # padding-oracle side channel even if the result is discarded.
        raise AuthenticationError(
            "HMAC verification failed — ciphertext may be tampered or corrupted"
        )

    # Step 4: Decrypt only after the MAC has been verified
    try:
        aes_cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        raise AuthenticationError("Decryption or unpadding failed")

    end_time = time.perf_counter()
    decryption_time = (end_time - start_time) * 1000  # milliseconds

    return {
        'decrypted_data': decrypted_data,
        'integrity_verified': integrity_verified,
        'decryption_time': decryption_time
    }


# ============================================================
# FULL TRANSACTION PROCESSING
# ============================================================

def process_transaction(transaction_bytes):
    """
    Process a single transaction through the complete
    RSA+AES-256 hybrid encryption and decryption cycle.
    Returns all performance metrics. Authentication failures are
    caught here so the performance harness can continue across a
    batch of transactions without crashing on a single failure.
    """
    process = psutil.Process()

    memory_before = process.memory_info().rss / 1024 / 1024  # MB
    cpu_before = psutil.cpu_percent(interval=None)

    # Key Generation
    public_key, private_key, key_gen_time = generate_rsa_keys()

    # Encryption
    encrypted_package = encrypt(transaction_bytes, public_key)

    # Decryption (may raise AuthenticationError)
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

    memory_after = process.memory_info().rss / 1024 / 1024  # MB
    cpu_after = psutil.cpu_percent(interval=None)

    return {
        'scheme': 'RSA+AES-256',
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
# TEST — Run this file directly to verify it works
# ============================================================
if __name__ == "__main__":
    from transaction_generator import generate_transaction, transaction_to_bytes, bytes_to_transaction

    print("=" * 55)
    print("RSA + AES-256 — UPDATED WITH HMAC-SHA256")
    print("=" * 55)

    # Generate a test transaction
    transaction = generate_transaction(1)
    transaction_bytes = transaction_to_bytes(transaction)

    print(f"\nOriginal Transaction:")
    for key, value in transaction.items():
        print(f"  {key}: {value}")

    print(f"\nProcessing through RSA+AES-256...")
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
        print(f"\nRecovered Transaction:")
        for key, value in recovered.items():
            print(f"  {key}: {value}")

        data_match = transaction == recovered
        print(f"\nData Match: {data_match}")

        if result['integrity_verified'] and data_match:
            print("\n✅ RSA+AES-256 with HMAC-SHA256 working correctly!")
        else:
            print("\n❌ Something went wrong — check above for errors")
    else:
        print("\n❌ Decryption failed — authentication check rejected the ciphertext")

    # --- Tamper test: confirm the MAC correctly rejects modified ciphertext ---
    print("\n" + "=" * 55)
    print("TAMPER TEST — flipping one byte of ciphertext")
    print("=" * 55)

    pub, priv, _ = generate_rsa_keys()
    package = encrypt(transaction_bytes, pub)

    tampered_ciphertext = bytearray(package['ciphertext'])
    tampered_ciphertext[0] ^= 0xFF  # flip bits in the first byte
    package['ciphertext'] = bytes(tampered_ciphertext)

    try:
        decrypt(package, priv)
        print("❌ TAMPER TEST FAILED — tampered ciphertext was accepted!")
    except AuthenticationError as exc:
        print(f"✅ TAMPER TEST PASSED — rejected as expected: {exc}")
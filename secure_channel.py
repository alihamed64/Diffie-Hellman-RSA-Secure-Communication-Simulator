"""
Secure Banking Communication Simulation
========================================
Diffie-Hellman key exchange with RSA digital signature authentication.

Alice (mobile banking client) sends a transactions file to Bob (bank server)
over an insecure channel. The protocol provides:
  - Key agreement (Diffie-Hellman)
  - Mutual authentication (RSA signatures over DH values)
  - Confidentiality + integrity for the file (AES-CBC + RSA signature)

This file is structured so each cryptographic primitive (RSA, DH, KDF, AES)
is implemented as a standalone section before the protocol is assembled.
RSA and DH are implemented from scratch to make the math visible; AES is
taken from pycryptodome because re-implementing a real block cipher is out
of scope.
"""

import secrets
import hashlib
import os 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ============================================================
# 1. RSA  --  key generation, signing, verification
# ============================================================

def _miller_rabin(n: int, rounds: int = 40) -> bool:
    """Probabilistic primality test. False = definitely composite."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n == small:
            return True
        if n % small == 0:
            return False

    # write n-1 as 2^r * d with d odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime of the requested bit length."""
    while True:
        # force top bit (right size) and bottom bit (odd)
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(candidate):
            return candidate


def _egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def rsa_keygen(bits: int = 2048) -> dict:
    """
    Generate an RSA key pair.
    Returns {'public': (n, e), 'private': (n, d)}.
    """
    e = 65537
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if _egcd(e, phi)[0] == 1:
            d = _modinv(e, phi)
            return {"public": (n, e), "private": (n, d)}


def rsa_sign(message: bytes, private_key: tuple) -> int:
    """
    Sign by hashing the message (SHA-256) and applying s = H(m)^d mod n.
    The assignment says hashing is optional; we include it because it is the
    real-world practice and prevents trivial existential forgery.
    """
    n, d = private_key
    h = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
    return pow(h, d, n)


def rsa_verify(message: bytes, signature: int, public_key: tuple) -> bool:
    """Verify s^e mod n == H(m) mod n."""
    n, e = public_key
    h = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
    return pow(signature, e, n) == h


# ============================================================
# 2. Diffie-Hellman  (RFC 3526 2048-bit)
# ============================================================

# Standard, publicly-vetted safe prime used in IKE/IPsec/TLS.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2


def dh_private() -> int:
    """Random secret exponent in [2, p-2]."""
    return secrets.randbelow(DH_P - 3) + 2


def dh_public(private: int) -> int:
    """g^private mod p — safe to publish."""
    return pow(DH_G, private, DH_P)


def dh_shared(peer_public: int, my_private: int) -> int:
    """(peer_public)^my_private mod p — the joint secret."""
    return pow(peer_public, my_private, DH_P)


# ============================================================
# 3. Key Derivation Function
# ============================================================

def kdf(shared_secret: int, key_len: int = 32) -> bytes:
    """
    Turn the DH integer into a uniform symmetric key.
    SHA-256 of the secret's big-endian byte form. key_len=32 -> AES-256.
    """
    n_bytes = (shared_secret.bit_length() + 7) // 8
    raw = shared_secret.to_bytes(n_bytes, "big")
    return hashlib.sha256(raw).digest()[:key_len]


# ============================================================
# 4. Symmetric Encryption  (AES-256-CBC with random IV
# ============================================================

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """IV (16 bytes) || ciphertext."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, AES.block_size))


def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    iv, ct = blob[:16], blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


# ============================================================
# 5. Helpers for the protocol steps
# ============================================================

def int_to_bytes(x: int) -> bytes:
    """Canonical big-endian encoding so signer and verifier see the same bytes."""
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


def banner(title: str) -> None:
    print("\n" + "=" * 64)
    print(f"  {title}")
    print("=" * 64)


# ============================================================
# 6. The full simulation
# ============================================================

def run_simulation(transactions_path: str,
                   encrypted_path: str,
                   decrypted_path: str,
                   rsa_bits: int = 2048) -> None:

    banner("SETUP — generate long-term RSA identities")
    print(f"  Generating {rsa_bits}-bit RSA key pair for Alice...")
    alice_rsa = rsa_keygen(rsa_bits)
    print(f"  Generating {rsa_bits}-bit RSA key pair for Bob...")
    bob_rsa = rsa_keygen(rsa_bits)
    print("  Done. Public keys are assumed to be known to the other party")
    print("  (in practice via certificates / a PKI).")

    # ------------------------------------------------------------------
    banner("STEP 1 — Diffie-Hellman key exchange")
    a_priv = dh_private()
    b_priv = dh_private()
    A = dh_public(a_priv)   # Alice's DH public value
    B = dh_public(b_priv)   # Bob's DH public value
    print(f"  Alice  A = g^a mod p   ({A.bit_length()} bits)")
    print(f"  Bob    B = g^b mod p   ({B.bit_length()} bits)")

    # ------------------------------------------------------------------
    banner("STEP 2 — Bob signs his DH value with his RSA private key")
    sig_B = rsa_sign(int_to_bytes(B), bob_rsa["private"])
    print("  Bob -> Alice:  (B, sig_B)")

    banner("STEP 3 — Alice verifies Bob's signature")
    if not rsa_verify(int_to_bytes(B), sig_B, bob_rsa["public"]):
        raise RuntimeError("Bob's signature failed verification — abort.")
    print("  OK — Bob is authenticated.")

    # ------------------------------------------------------------------
    banner("STEP 4 — Alice signs her DH value")
    sig_A = rsa_sign(int_to_bytes(A), alice_rsa["private"])
    print("  Alice -> Bob:  (A, sig_A)")

    banner("STEP 5 — Bob verifies Alice's signature")
    if not rsa_verify(int_to_bytes(A), sig_A, alice_rsa["public"]):
        raise RuntimeError("Alice's signature failed verification — abort.")
    print("  OK — Alice is authenticated.")

    # ------------------------------------------------------------------
    banner("STEP 6 — Derive the shared session key (KDF over DH secret)")
    s_alice = dh_shared(B, a_priv)
    s_bob   = dh_shared(A, b_priv)
    if s_alice != s_bob:
        raise RuntimeError("DH secrets disagree — protocol broken")
    session_key = kdf(s_alice, key_len=32)   # AES-256
    print(f"  Shared secret matches on both sides ({s_alice.bit_length()} bits).")
    print(f"  Derived AES-256 session key: {session_key.hex()}")

    # ------------------------------------------------------------------
    banner("STEP 7 — Alice encrypts the transactions file and signs it")
    with open(transactions_path, "rb") as f:
        plaintext = f.read()
    print(f"  Read plaintext file ({len(plaintext)} bytes).")

    ciphertext = aes_encrypt(plaintext, session_key)
    file_sig = rsa_sign(ciphertext, alice_rsa["private"])
    print(f"  Ciphertext: {len(ciphertext)} bytes (incl. 16-byte IV).")
    print("  Alice -> Bob:  (ciphertext, file_sig)")

    with open(encrypted_path, "wb") as f:
        f.write(ciphertext)
    print(f"  Encrypted file saved to: {encrypted_path}")

    # ------------------------------------------------------------------
    banner("STEP 8 — Bob verifies the file signature and decrypts")
    if not rsa_verify(ciphertext, file_sig, alice_rsa["public"]):
        raise RuntimeError("File signature invalid — discard ciphertext.")
    print("  File signature valid — ciphertext came from Alice, unmodified.")

    recovered = aes_decrypt(ciphertext, session_key)
    with open(decrypted_path, "wb") as f:
        f.write(recovered)
    print(f"  Decrypted file saved to: {decrypted_path}")

    # sanity check
    if recovered != plaintext:
        raise RuntimeError("Decryption did not recover the plaintext!")


# ===========================================================
# 7. Entry point
# ===========================================================

if __name__ == "__main__":
    BASE = os.path.dirname(os.path.abspath(__file__))
    run_simulation(
        transactions_path=os.path.join(BASE, "transactions.txt"),
        encrypted_path  =os.path.join(BASE, "transactions_encrypted.bin"),
        decrypted_path  =os.path.join(BASE, "transactions_decrypted.txt"),
        rsa_bits=2048,
    )

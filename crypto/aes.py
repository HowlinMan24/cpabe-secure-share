"""
AES-256-GCM bulk encryption — the symmetric layer of hybrid encryption.

Why hybrid encryption?
-----------------------
CP-ABE (like all pairing-based schemes) operates on algebraic group elements
and is many orders of magnitude slower than symmetric ciphers.  Encrypting a
large file directly with CP-ABE is impractical.  The standard solution is
hybrid encryption:

  1. Generate a random symmetric key K (here: a GT group element → 32 bytes).
  2. Encrypt the file with K using AES-256-GCM (fast, constant-time).
  3. Encrypt K with CP-ABE under the access policy (slow, but K is tiny).

An adversary who cannot satisfy the policy cannot recover K and therefore
cannot decrypt the file, even with the AES ciphertext in hand.

Why AES-256-GCM?
-----------------
* AES-256: 256-bit key provides 128-bit post-quantum security (Grover halves
  it), making it quantum-resistant at the symmetric layer.
* GCM mode: authenticated encryption — provides both confidentiality AND
  integrity.  A tampered ciphertext raises InvalidTag before any plaintext
  is returned, preventing chosen-ciphertext attacks on the symmetric layer.
* 96-bit nonce: NIST SP 800-38D recommends 96 bits for GCM; it must be
  unique per (key, message) pair.  We generate it with os.urandom(), which
  is cryptographically secure on all supported platforms.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt arbitrary-length plaintext with AES-256-GCM.

    Args:
        plaintext: raw file bytes.
        aes_key:   32-byte key (from crypto.cpabe.gt_to_aes_key).

    Returns:
        (nonce, ciphertext): both must be stored; both are needed to decrypt.
        The 16-byte GCM authentication tag is appended to ciphertext by the
        library and verified automatically on decryption.
    """
    assert len(aes_key) == 32, "AES key must be 32 bytes (AES-256)"
    nonce = os.urandom(12)           # 96-bit random nonce — unique per encryption
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_file(nonce: bytes, ciphertext: bytes, aes_key: bytes) -> bytes:
    """
    Decrypt and authenticate an AES-256-GCM ciphertext.

    Args:
        nonce:      the 12-byte nonce returned by encrypt_file.
        ciphertext: the ciphertext (with appended GCM tag) from encrypt_file.
        aes_key:    the same 32-byte key used during encryption.

    Returns:
        plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: if authentication fails —
        the ciphertext has been tampered with or the wrong key was used.
        This exception should propagate to the caller as-is; it is a
        security signal, not a recoverable error.
    """
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

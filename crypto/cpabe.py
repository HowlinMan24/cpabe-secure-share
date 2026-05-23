"""
CP-ABE cryptographic operations — BSW07 scheme via charm-crypto.

BSW07 (Bethencourt, Sahai, Waters 2007) is the canonical Ciphertext-Policy
Attribute-Based Encryption scheme.  It encrypts data under an arbitrary
monotone Boolean access policy (e.g. "(role:doctor AND dept:cardiology) OR
role:admin") and a user can decrypt only when their attribute set satisfies
that policy.

Security properties
-------------------
* IND-CPA secure under the Decisional Bilinear Diffie-Hellman (DBDH) assumption
  in the random oracle model (selective-set security model).
* Collusion-resistant: each user secret key embeds a random blinding factor
  chosen freshly by the authority.  Two users cannot pool their keys to gain
  decryption rights neither possesses individually.
* Key escrow: the authority that holds the Master Key (MK) can derive a secret
  key for *any* attribute set and therefore decrypt *any* ciphertext.  This is
  an inherent single-authority CP-ABE limitation and is explicitly noted as a
  known weakness of this system.

Pairing group
-------------
SS512 is a 512-bit Type-1 (symmetric) pairing group built on a supersingular
elliptic curve, providing roughly 80-bit classical security.  It is the
standard group used in charm's BSW07 examples and is appropriate for
academic demonstrations.  A production deployment would use a Type-3
(asymmetric, e.g. BN256) group for a better security-to-performance ratio.

Attribute naming convention
---------------------------
All attribute strings MUST be lowercase and use the colon-separated
"namespace:value" format, e.g. 'role:doctor', 'dept:cardiology'.
The policy string uses the same names with 'and' / 'or' operators.
"""

import hashlib
import pickle

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

# Module-level singletons — initialising the pairing group is expensive;
# creating it once at import time avoids repeating that cost.
_GROUP: PairingGroup = PairingGroup('SS512')
_SCHEME: CPabe_BSW07 = CPabe_BSW07(_GROUP)


# ---------------------------------------------------------------------------
# Four core CP-ABE algorithms
# ---------------------------------------------------------------------------

def setup() -> tuple:
    """
    Authority Setup — generate the public key (PK) and master key (MK).

    PK is shared openly; anyone with PK can encrypt.
    MK is kept secret by the authority; it is required to issue user keys.

    Returns:
        (pk, mk): charm dict objects representing the key pair.
    """
    pk, mk = _SCHEME.setup()
    return pk, mk


def keygen(pk, mk, attributes: list[str]):
    """
    Authority KeyGen — issue a secret key for a specific attribute set.

    Collusion resistance is guaranteed by the random blinding factor r that
    the authority samples freshly for every call.  All per-attribute key
    components are computed relative to this r, so two keys with disjoint
    attributes cannot be merged to satisfy a joint policy — their r values
    are independent and the pairing equations will not balance.

    Args:
        pk:         public key (from setup)
        mk:         master key (from setup, authority-only)
        attributes: list of lowercase attribute strings,
                    e.g. ['role:doctor', 'dept:cardiology']

    Returns:
        sk: charm dict representing the user secret key.
    """
    # BSW07 in charm expects lowercase attribute strings.
    attrs = [a.lower() for a in attributes]
    return _SCHEME.keygen(pk, mk, attrs)


def encrypt(pk, policy: str) -> tuple:
    """
    DataOwner Encrypt — encrypt a random GT element under an access policy.

    Why encrypt a GT element rather than the file directly?
    GT elements live in the target group of the bilinear pairing and are the
    natural 'message space' for BSW07.  In our hybrid scheme the caller
    derives a 256-bit AES key from this GT element (via gt_to_aes_key) and
    then uses AES-256-GCM for bulk file encryption.  This keeps the CP-ABE
    ciphertext size constant regardless of file size — CP-ABE is orders of
    magnitude too slow for bulk data encryption.

    Args:
        pk:     public key (from setup)
        policy: access policy string, e.g.
                '(role:doctor and dept:cardiology) or role:admin'
                Operators are case-insensitive; attribute names must be
                lowercase and match those used in keygen.

    Returns:
        (ct, gt_elem): the CP-ABE ciphertext and the plaintext GT element.
        The caller should immediately derive an AES key from gt_elem and
        discard gt_elem — it must not be stored alongside the ciphertext.
    """
    gt_elem = _GROUP.random(GT)
    ct = _SCHEME.encrypt(pk, gt_elem, policy)
    return ct, gt_elem


def decrypt(pk, sk, ct):
    """
    DataUser Decrypt — recover the GT element embedded in a ciphertext.

    Succeeds only when the attributes in sk satisfy the Boolean policy in ct.
    If they do not, charm returns False (it does not raise) and we convert
    that into a typed DecryptionError so callers can handle it cleanly.

    This is a *cryptographic* denial: an unauthorised user cannot recover
    any information about the GT element, and therefore cannot derive the AES
    key or decrypt the file — even with full access to the ciphertext bytes.

    Args:
        pk: public key
        sk: user secret key (from keygen)
        ct: ciphertext (from encrypt)

    Returns:
        gt_elem: the decrypted GT element (use gt_to_aes_key to get the AES key).

    Raises:
        DecryptionError: if the user's attributes do not satisfy the policy.
    """
    result = _SCHEME.decrypt(pk, sk, ct)
    if result is False:
        raise DecryptionError(
            "Attributes do not satisfy the access policy — decryption denied."
        )
    return result


def gt_to_aes_key(gt_elem) -> bytes:
    """
    Derive a 256-bit AES key from a GT group element via SHA-256.

    SHA-256 acts as a key-derivation function (KDF): the GT element provides
    high-entropy randomness; hashing maps it to a uniformly distributed 256-bit
    string suitable for use as an AES-256 key.

    Returns:
        32 bytes suitable for AESGCM(key).
    """
    return hashlib.sha256(_GROUP.serialize(gt_elem)).digest()


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------
# charm group elements are Python objects with a __reduce__ method that makes
# them picklable.  pickle is used here for simplicity in this educational
# project.  A production system would use a language-neutral encoding (e.g.
# charm's objectToBytes / bytesToObject with a versioned envelope).

def serialize_charm_obj(obj) -> bytes:
    """Serialize any charm key or ciphertext dict to bytes."""
    return pickle.dumps(obj)


def deserialize_charm_obj(data: bytes):
    """Deserialize a charm key or ciphertext dict from bytes."""
    return pickle.loads(data)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class DecryptionError(Exception):
    """Raised when CP-ABE decryption fails because the policy is not satisfied."""

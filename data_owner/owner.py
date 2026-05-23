"""
DataOwner — encrypt a file and produce an uploadable package.

Hybrid encryption flow
----------------------
1. Ask CP-ABE to encrypt a random GT element under the access policy.
   → yields (cpabe_ct, gt_elem)

2. Derive a 256-bit AES key:  aes_key = SHA-256(serialize(gt_elem))
   The GT element is the shared secret; its serialisation is high-entropy
   random data; SHA-256 maps it to a uniformly distributed AES key.

3. AES-256-GCM encrypt the file with aes_key.
   → yields (nonce, aes_ciphertext_with_tag)

4. Assemble the encrypted package:
   {
     'version'  : 1,
     'filename' : original filename (so DataUser knows what to call it),
     'policy'   : the access policy string (informational; embedded in cpabe_ct too),
     'cpabe_ct' : serialized CP-ABE ciphertext — contains the wrapped AES key,
     'aes_nonce': 12-byte GCM nonce,
     'aes_ct'   : AES ciphertext (plaintext length + 16-byte GCM tag),
   }
   The package is pickled to bytes and can be stored on an untrusted server.

Storage-server threat model
----------------------------
The server is honest-but-curious: it stores and serves blobs faithfully but
will try to read them.  The package reveals:
  * The access policy string (in plaintext) — in a higher-security design,
    the policy would itself be hidden (hidden-policy CP-ABE), but that is
    outside scope here.
  * Ciphertext length — reveals approximate file size.
  * Nothing about file contents, AES key, or who can decrypt.
"""

import pickle
from pathlib import Path

from authority.authority import load_pk
from crypto.cpabe import encrypt as cpabe_encrypt, gt_to_aes_key, serialize_charm_obj
from crypto.aes import encrypt_file

_DEFAULT_KEYS_DIR = Path("keys")


def encrypt_and_package(
    file_path: str | Path,
    policy: str,
    keys_dir: Path = _DEFAULT_KEYS_DIR,
) -> bytes:
    """
    Encrypt a file under a CP-ABE access policy and return a package blob.

    Args:
        file_path: path to the plaintext file (any size).
        policy:    Boolean access policy, e.g.
                   '(role:doctor and dept:cardiology) or role:admin'
                   Use lowercase attribute names and 'and' / 'or' operators.
        keys_dir:  directory holding pk.pkl (public key).

    Returns:
        Encrypted package bytes — safe to hand to an untrusted storage server.
    """
    file_path = Path(file_path)
    plaintext = file_path.read_bytes()

    pk = load_pk(keys_dir)

    # --- CP-ABE layer: encrypt a random GT element under the policy ----------
    # The GT element is the secret that only authorised users can recover.
    cpabe_ct, gt_elem = cpabe_encrypt(pk, policy)

    # --- Derive AES key from the GT element ----------------------------------
    # We derive rather than use gt_elem directly because gt_elem lives in the
    # pairing group (variable-length serialisation); an AES key must be exactly
    # 32 bytes.  SHA-256 provides that mapping with full entropy preservation.
    aes_key = gt_to_aes_key(gt_elem)

    # gt_elem must not be stored — it IS the secret.  It leaves scope here.

    # --- AES-256-GCM layer: encrypt the file ---------------------------------
    nonce, aes_ct = encrypt_file(plaintext, aes_key)

    # --- Assemble package ----------------------------------------------------
    package = {
        'version':   1,
        'filename':  file_path.name,
        'policy':    policy,
        'cpabe_ct':  serialize_charm_obj(cpabe_ct),  # bytes: serialized charm dict
        'aes_nonce': nonce,
        'aes_ct':    aes_ct,
    }

    package_bytes = pickle.dumps(package)

    print(
        f"[DataOwner] Encrypted '{file_path.name}'  "
        f"({len(plaintext):,} B plaintext → {len(package_bytes):,} B package)"
    )
    print(f"  Policy: {policy}")

    return package_bytes

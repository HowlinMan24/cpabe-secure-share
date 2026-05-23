"""
DataUser — download and decrypt an encrypted package.

Decryption flow
---------------
1. Unpack the blob into its components (cpabe_ct, aes_nonce, aes_ct, …).

2. CP-ABE decrypt cpabe_ct using the user's secret key (sk).
   → This step succeeds only if the attributes embedded in sk satisfy the
     Boolean access policy embedded in cpabe_ct.
   → On failure, charm returns False; we raise DecryptionError immediately.
     No key material is exposed to an unauthorised user.

3. Derive the AES key:  aes_key = SHA-256(serialize(gt_elem_recovered))
   The recovered GT element must equal the one the DataOwner encrypted;
   if it does, the derived AES key is identical to the DataOwner's key.

4. AES-256-GCM decrypt the file.
   → GCM authenticates the ciphertext.  If anyone tampered with aes_ct
     (including the storage server), this step raises InvalidTag.

Security note
--------------
Steps 2 and 4 together enforce *both* access control and integrity:
  * Wrong attributes  → DecryptionError at step 2 (cryptographic denial).
  * Tampered payload  → InvalidTag at step 4 (authentication failure).
Neither failure leaks any plaintext or key material.
"""

import pickle
from pathlib import Path

from authority.authority import load_pk, load_sk
from crypto.cpabe import (
    decrypt as cpabe_decrypt,
    gt_to_aes_key,
    deserialize_charm_obj,
    DecryptionError,
)
from crypto.aes import decrypt_file

_DEFAULT_KEYS_DIR = Path("keys")
_DEFAULT_OUTPUT_DIR = Path("downloads")


def decrypt_package(
    package_bytes: bytes,
    user_id: str,
    output_dir: Path = _DEFAULT_OUTPUT_DIR,
    keys_dir: Path = _DEFAULT_KEYS_DIR,
) -> Path:
    """
    Decrypt an encrypted package as the given user.

    Args:
        package_bytes: raw bytes downloaded from the storage server.
        user_id:       identifier used to load the user's secret key.
        output_dir:    directory where the decrypted file is written.
        keys_dir:      directory holding pk.pkl and users/<user_id>.pkl.

    Returns:
        Path to the decrypted output file.

    Raises:
        DecryptionError:                        policy not satisfied.
        cryptography.exceptions.InvalidTag:     ciphertext integrity check failed.
        FileNotFoundError:                      key files missing.
    """
    package = pickle.loads(package_bytes)

    pk = load_pk(keys_dir)
    sk = load_sk(user_id, keys_dir)
    cpabe_ct = deserialize_charm_obj(package['cpabe_ct'])

    # --- CP-ABE layer: recover the GT element --------------------------------
    # This is the cryptographic gate.  If sk's attributes don't satisfy the
    # policy in cpabe_ct, DecryptionError is raised here and execution stops.
    # The AES key is never derived, so the ciphertext stays opaque.
    gt_elem = cpabe_decrypt(pk, sk, cpabe_ct)

    # --- Derive AES key (mirrors DataOwner's derivation exactly) -------------
    aes_key = gt_to_aes_key(gt_elem)

    # --- AES-256-GCM layer: decrypt and authenticate the file ----------------
    # InvalidTag is raised if the ciphertext was tampered with.
    plaintext = decrypt_file(package['aes_nonce'], package['aes_ct'], aes_key)

    # --- Write output --------------------------------------------------------
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / package['filename']
    output_path.write_bytes(plaintext)

    print(
        f"[DataUser '{user_id}'] Decrypted '{package['filename']}' "
        f"({len(plaintext):,} B) → {output_path}"
    )
    return output_path

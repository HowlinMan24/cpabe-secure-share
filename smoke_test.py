#!/usr/bin/env python3
"""
Charm-crypto smoke test.

Run this *inside the Docker container* immediately after building to verify
that the PBC/GMP native libraries are correctly linked and the BSW07 scheme
works end-to-end before trusting any higher-level code.

  docker run --rm cpabe-secure-share python smoke_test.py

Expected output (all lines prefixed with ✓):
  ✓ charm-crypto imported
  ✓ PairingGroup('SS512') created
  ✓ BSW07 setup()  →  pk, mk
  ✓ BSW07 keygen() →  sk for ['role:doctor', 'dept:cardiology']
  ✓ BSW07 encrypt() under 'role:doctor and dept:cardiology'
  ✓ BSW07 decrypt() — recovered GT element matches original
  ✓ BSW07 decrypt() correctly denied for wrong attributes
  ✓ AES-256-GCM encrypt/decrypt round-trip
  ✓ gt_to_aes_key() produces 32-byte key
  All smoke tests passed.
"""

import sys

_PASS = "✓"
_FAIL = "✗"


def ok(msg: str) -> None:
    print(f"  {_PASS}  {msg}")


def fail(msg: str, exc: Exception | None = None) -> None:
    print(f"  {_FAIL}  FAIL — {msg}", file=sys.stderr)
    if exc:
        print(f"       {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# 1. Import charm
# ---------------------------------------------------------------------------
try:
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
    ok("charm-crypto imported")
except ImportError as e:
    fail("charm-crypto import failed — was it installed in the Dockerfile?", e)

# ---------------------------------------------------------------------------
# 2. Create pairing group
# ---------------------------------------------------------------------------
try:
    group = PairingGroup("SS512")
    ok("PairingGroup('SS512') created")
except Exception as e:
    fail("PairingGroup creation failed — PBC library missing or not linked?", e)

# ---------------------------------------------------------------------------
# 3. BSW07 setup
# ---------------------------------------------------------------------------
try:
    cpabe = CPabe_BSW07(group)
    pk, mk = cpabe.setup()
    ok("BSW07 setup()  →  pk, mk")
except Exception as e:
    fail("setup() raised an exception", e)

# ---------------------------------------------------------------------------
# 4. BSW07 keygen
# ---------------------------------------------------------------------------
attrs = ["role:doctor", "dept:cardiology"]
try:
    sk_good = cpabe.keygen(pk, mk, attrs)
    ok(f"BSW07 keygen() →  sk for {attrs}")
except Exception as e:
    fail("keygen() raised an exception", e)

# ---------------------------------------------------------------------------
# 5. BSW07 encrypt
# ---------------------------------------------------------------------------
policy = "role:doctor and dept:cardiology"
try:
    M = group.random(GT)
    ct = cpabe.encrypt(pk, M, policy)
    ok(f"BSW07 encrypt() under '{policy}'")
except Exception as e:
    fail("encrypt() raised an exception", e)

# ---------------------------------------------------------------------------
# 6. BSW07 decrypt — correct attributes (should succeed)
# ---------------------------------------------------------------------------
try:
    M_dec = cpabe.decrypt(pk, sk_good, ct)
    if M_dec is False:
        fail("decrypt() returned False for a key that should satisfy the policy")
    if M_dec != M:
        fail("decrypt() returned a value but it does not match the original GT element")
    ok("BSW07 decrypt() — recovered GT element matches original")
except Exception as e:
    fail("decrypt() raised an unexpected exception for valid key", e)

# ---------------------------------------------------------------------------
# 7. BSW07 decrypt — wrong attributes (should fail)
# ---------------------------------------------------------------------------
try:
    sk_wrong = cpabe.keygen(pk, mk, ["role:nurse"])
    result = cpabe.decrypt(pk, sk_wrong, ct)
    if result is False:
        ok("BSW07 decrypt() correctly denied for wrong attributes")
    else:
        fail("decrypt() SUCCEEDED for a key that should NOT satisfy the policy — "
             "this is a security failure!")
except Exception:
    # Some versions of charm raise rather than returning False; that is also correct.
    ok("BSW07 decrypt() correctly denied for wrong attributes (raised exception)")

# ---------------------------------------------------------------------------
# 8. AES-256-GCM round-trip
# ---------------------------------------------------------------------------
try:
    import os
    from crypto.aes import encrypt_file, decrypt_file

    key = os.urandom(32)
    plaintext = b"Hello, CP-ABE world! " * 100
    nonce, ciphertext = encrypt_file(plaintext, key)
    recovered = decrypt_file(nonce, ciphertext, key)
    assert recovered == plaintext, "AES plaintext mismatch"
    ok("AES-256-GCM encrypt/decrypt round-trip")
except Exception as e:
    fail("AES smoke test failed", e)

# ---------------------------------------------------------------------------
# 9. gt_to_aes_key produces 32 bytes
# ---------------------------------------------------------------------------
try:
    from crypto.cpabe import gt_to_aes_key, _GROUP
    sample_gt = _GROUP.random(GT)
    derived = gt_to_aes_key(sample_gt)
    assert len(derived) == 32, f"Expected 32 bytes, got {len(derived)}"
    ok("gt_to_aes_key() produces 32-byte key")
except Exception as e:
    fail("gt_to_aes_key() failed", e)

# ---------------------------------------------------------------------------
print()
print("  All smoke tests passed.")

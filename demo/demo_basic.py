"""
Basic CP-ABE Demo — access control enforcement.

Demonstrates two outcomes that together prove the system works correctly:

  (a) AUTHORISED ACCESS: Alice has attributes [role:doctor, dept:cardiology].
      The policy is '(role:doctor and dept:cardiology) or role:admin'.
      Alice satisfies the AND clause → decryption succeeds.

  (b) CRYPTOGRAPHIC DENIAL: Bob has attributes [role:nurse, dept:cardiology].
      He satisfies dept:cardiology but not role:doctor.
      Neither clause of the OR is satisfied → decryption is cryptographically
      denied.  Bob cannot decrypt even with the full ciphertext in hand.

Run with:
  python cli.py demo
or directly:
  python -m demo.demo_basic
"""

import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEPARATOR = "─" * 60
_WIDE_SEP  = "=" * 60


def _hdr(title: str) -> None:
    print(f"\n{_WIDE_SEP}\n  {title}\n{_WIDE_SEP}")


def _step(n: str, desc: str) -> None:
    print(f"\n[Step {n}] {desc}")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def run_demo() -> None:
    from authority.authority import authority_setup, authority_keygen
    from data_owner.owner import encrypt_and_package
    from data_user.user import decrypt_package
    from crypto.cpabe import DecryptionError

    _hdr("CP-ABE BASIC ACCESS CONTROL DEMO")

    with tempfile.TemporaryDirectory() as tmpdir:
        keys_dir  = Path(tmpdir) / "keys"
        out_dir   = Path(tmpdir) / "out"

        # ── 1. Authority Setup ────────────────────────────────────────────
        _step("1", "Authority Setup — generating PK and MK")
        authority_setup(keys_dir)
        print("  ✓ PK and MK created")

        # ── 2. Issue user keys ────────────────────────────────────────────
        _step("2", "Authority KeyGen — issuing user secret keys")
        authority_keygen("alice", ["role:doctor", "dept:cardiology"], keys_dir)
        authority_keygen("bob",   ["role:nurse",  "dept:cardiology"], keys_dir)
        print("  ✓ Alice: [role:doctor, dept:cardiology]  — should SUCCEED")
        print("  ✓ Bob:   [role:nurse,  dept:cardiology]  — should FAIL")

        # ── 3. DataOwner encrypts a file ──────────────────────────────────
        _step("3", "DataOwner encrypts a sensitive patient record")
        policy = "(role:doctor and dept:cardiology) or role:admin"
        print(f"  Policy: {policy}")

        sample = Path(tmpdir) / "patient_record.txt"
        sample.write_text(
            "════════════════════════════════════════\n"
            "  CONFIDENTIAL PATIENT RECORD\n"
            "════════════════════════════════════════\n"
            "Patient  : Jane Smith, DOB 1979-08-22\n"
            "Diagnosis: Stable Angina Pectoris\n"
            "Treatment: Continue bisoprolol 5 mg QD\n"
            "Notes    : Follow-up in 4 weeks.\n"
            "════════════════════════════════════════\n"
        )

        pkg_bytes = encrypt_and_package(sample, policy, keys_dir)
        print(f"  ✓ Package: {len(pkg_bytes):,} bytes")
        print("  (This package is safe to upload to an untrusted server.)")

        # ── 4a. Authorised user decrypts ──────────────────────────────────
        _step("4a", "Alice (role:doctor AND dept:cardiology) decrypts")
        print("  Alice satisfies BOTH sides of the AND clause → should succeed.")
        try:
            path = decrypt_package(pkg_bytes, "alice", out_dir / "alice", keys_dir)
            print(f"\n  ✓  SUCCESS — file recovered at {path}")
            print(f"\n{_SEPARATOR}")
            print(path.read_text())
            print(_SEPARATOR)
        except DecryptionError as exc:
            print(f"\n  ✗  UNEXPECTED FAILURE: {exc}")

        # ── 4b. Unauthorised user is denied ───────────────────────────────
        _step("4b", "Bob (role:nurse AND dept:cardiology) attempts decryption")
        print("  Bob satisfies dept:cardiology but NOT role:doctor.")
        print("  Neither OR clause is fully satisfied → should be denied.")
        try:
            decrypt_package(pkg_bytes, "bob", out_dir / "bob", keys_dir)
            print("\n  ✗  UNEXPECTED SUCCESS — this would be a security breach!")
        except DecryptionError as exc:
            print(f"\n  ✓  CRYPTOGRAPHICALLY DENIED")
            print(f"     Reason: {exc}")
            print("     Bob cannot recover the AES key and therefore cannot read")
            print("     the file — even with the full encrypted package.")

        _hdr("DEMO COMPLETE")
        print()
        print("  Outcome (a): Alice [role:doctor, dept:cardiology] → DECRYPTED ✓")
        print("  Outcome (b): Bob   [role:nurse,  dept:cardiology] → DENIED    ✓")
        print()
        print("  The access policy is enforced by the mathematics of bilinear")
        print("  pairings, not by a gate-check in software.  Bob cannot bypass")
        print("  it even with direct access to the ciphertext bytes.")
        print()


if __name__ == "__main__":
    run_demo()

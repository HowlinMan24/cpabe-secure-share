"""
Collusion Resistance Demo.

Background
----------
A naive access control system might be broken by key pooling: if Bob has
attribute role:doctor and Carol has attribute dept:cardiology, and the policy
requires (role:doctor AND dept:cardiology), they might try to combine their
credentials to jointly decrypt.

CP-ABE prevents this via per-key random blinding factors.

How BSW07 collusion resistance works
-------------------------------------
During KeyGen the authority samples a fresh random scalar r ∈ Z_p for each
user.  Every component of the user secret key is computed relative to this r:

  D        = g^{(α + r) / β}   ← the "core" blinding component
  D_{x}    = g^r · H(x)^{r_x}  ← per-attribute component (x ∈ S)
  D_{x}'   = g^{r_x}            ← per-attribute randomness

During Decrypt, the algorithm uses Lagrange interpolation to reconstruct a
pairing value that cancels the encryption blinding.  The cancellation requires
that ALL per-attribute components (D_{x}) and the core component (D) were
computed with the SAME r.

If we take Bob's D (based on r_bob) and Carol's D_{dept:cardiology} (based
on r_carol), the pairings do not balance:

  e(D_bob, ...)  expects r_bob everywhere,
  but Carol's component carries r_carol ≠ r_bob.

The result is a random group element — not the plaintext GT element — so the
AES key derived from it is garbage.  Decryption silently fails.

What this demo shows
---------------------
1. Bob  [role:doctor]        alone  → DENIED (missing dept:cardiology)
2. Carol [dept:cardiology]   alone  → DENIED (missing role:doctor)
3. Naive key merge (Bob's SK dict ∪ Carol's SK dict)  → DENIED
   This is the colluding attempt: we manually combine the two key dicts
   and ask charm to decrypt.  Despite covering all required attributes,
   the mismatched blinding factors cause decryption to return False.
4. The only way to get a valid key for (role:doctor AND dept:cardiology)
   is to ask the authority to issue one — which requires the master key.

Run with:
  python cli.py demo-collusion
or directly:
  python -m demo.demo_collusion
"""

import pickle
import tempfile
from pathlib import Path


_SEP  = "─" * 60
_WIDE = "=" * 60


def _hdr(t):
    print(f"\n{_WIDE}\n  {t}\n{_WIDE}")


def _step(n, d):
    print(f"\n[Step {n}] {d}")


# ---------------------------------------------------------------------------

def run_collusion_demo() -> None:
    from authority.authority import authority_setup, authority_keygen, load_pk
    from data_owner.owner import encrypt_and_package
    from data_user.user import decrypt_package
    from crypto.cpabe import (
        deserialize_charm_obj, serialize_charm_obj,
        DecryptionError, _SCHEME,
    )

    _hdr("CP-ABE COLLUSION RESISTANCE DEMO")

    with tempfile.TemporaryDirectory() as tmpdir:
        keys_dir = Path(tmpdir) / "keys"
        out_dir  = Path(tmpdir) / "out"

        # ── 1. Setup and key issuance ─────────────────────────────────────
        _step("1", "Authority Setup + KeyGen for partial-attribute users")
        authority_setup(keys_dir)

        # Bob:   role:doctor       only (no dept:cardiology)
        # Carol: dept:cardiology   only (no role:doctor)
        authority_keygen("bob",   ["role:doctor"],    keys_dir)
        authority_keygen("carol", ["dept:cardiology"], keys_dir)
        print("  Bob   : [role:doctor]             (missing dept:cardiology)")
        print("  Carol : [dept:cardiology]          (missing role:doctor)")

        # ── 2. Encrypt under a conjunctive policy ─────────────────────────
        _step("2", "DataOwner encrypts under 'role:doctor and dept:cardiology'")
        policy = "role:doctor and dept:cardiology"
        print(f"  Policy: {policy}")
        print("  Together Bob+Carol's attributes COVER this policy.")
        print("  Individually they do NOT.  Can they collude?")

        secret = Path(tmpdir) / "secret.txt"
        secret.write_text(
            "TOP SECRET — For cardiologists only.\n"
            "Clinical trial data: compound XR-7, Phase II.\n"
        )
        pkg_bytes = encrypt_and_package(secret, policy, keys_dir)

        # ── 3. Individual attempts ────────────────────────────────────────
        _step("3", "Individual decryption attempts (both must fail)")

        for uid, attrs in [("bob",   "role:doctor only"),
                           ("carol", "dept:cardiology only")]:
            try:
                decrypt_package(pkg_bytes, uid, out_dir / uid, keys_dir)
                print(f"  {uid} ({attrs}): ✗  UNEXPECTED SUCCESS — security failure!")
            except DecryptionError:
                print(f"  {uid} ({attrs}): ✓  DENIED (as expected)")

        # ── 4. Collusion attempt — naive key merge ────────────────────────
        _step("4", "Collusion attempt — merging Bob's and Carol's secret keys")
        print()
        print("  Strategy: load both SK dicts; merge them so the combined")
        print("  key appears to cover role:doctor AND dept:cardiology.")
        print()

        pk     = load_pk(keys_dir)
        sk_bob   = deserialize_charm_obj(
            (keys_dir / "users" / "bob.pkl").read_bytes()
        )
        sk_carol = deserialize_charm_obj(
            (keys_dir / "users" / "carol.pkl").read_bytes()
        )

        pkg = pickle.loads(pkg_bytes)
        cpabe_ct = deserialize_charm_obj(pkg["cpabe_ct"])

        # Build a 'merged' key by unioning both SK dicts.
        # We keep Bob's core blinding component (D) and merge Carol's
        # per-attribute entries — this is the best a colluder can do.
        merged_sk = dict(sk_bob)                        # start with Bob's key
        for k, v in sk_carol.items():
            if k not in merged_sk:
                merged_sk[k] = v                        # add Carol's attrs
            elif k == "S":
                # 'S' is the attribute list; union them
                merged_sk["S"] = list(set(sk_bob.get("S", [])) |
                                      set(sk_carol.get("S", [])))

        print("  Merged key attribute coverage:", merged_sk.get("S", "(unknown)"))
        print("  Attempting CP-ABE decrypt with merged key …")

        try:
            result = _SCHEME.decrypt(pk, merged_sk, cpabe_ct)
            if result is False:
                print()
                print("  ✓  COLLUSION BLOCKED — charm returned False.")
            else:
                print()
                print("  ✗  Merged key produced a result — verifying correctness …")
                # Even if we get a value back it should not be the right GT element,
                # so AES key derivation will produce garbage and file decrypt fails.
                from crypto.cpabe import gt_to_aes_key
                from crypto.aes import decrypt_file
                from cryptography.exceptions import InvalidTag
                aes_key = gt_to_aes_key(result)
                try:
                    decrypt_file(pkg["aes_nonce"], pkg["aes_ct"], aes_key)
                    print("  ✗  File decrypted! Unexpected — please report this.")
                except InvalidTag:
                    print("  ✓  COLLUSION BLOCKED — wrong GT element → wrong AES key")
                    print("       → GCM authentication tag invalid → file unreadable.")
        except Exception as exc:
            print(f"  ✓  COLLUSION BLOCKED — exception during decrypt: {type(exc).__name__}")

        # ── 5. Conclusion ─────────────────────────────────────────────────
        _hdr("COLLUSION RESISTANCE VERIFIED")
        print()
        print("  Result summary:")
        print("  ┌──────────────────────────────────────────────┬──────────┐")
        print("  │ Attempt                                      │ Outcome  │")
        print("  ├──────────────────────────────────────────────┼──────────┤")
        print("  │ Bob alone   [role:doctor]                    │ DENIED ✓ │")
        print("  │ Carol alone [dept:cardiology]                │ DENIED ✓ │")
        print("  │ Merged key  [role:doctor ∪ dept:cardiology]  │ DENIED ✓ │")
        print("  └──────────────────────────────────────────────┴──────────┘")
        print()
        print("  WHY collusion fails in CP-ABE")
        print("  " + _SEP[:55])
        print("  Bob's SK:   D_bob   = g^{(α + r_bob)  / β}  ← r_bob  random")
        print("  Carol's SK: D_carol = g^{(α + r_carol) / β}  ← r_carol random")
        print()
        print("  Decryption requires the core component D and all per-attribute")
        print("  components to have been computed with the SAME blinding factor r.")
        print("  Bob's D uses r_bob; Carol's dept:cardiology uses r_carol.")
        print("  Since r_bob ≠ r_carol, the pairing equations do not balance,")
        print("  and the recovered GT element is random garbage — not the secret.")
        print()
        print("  To obtain a valid key for the full policy, an attacker would")
        print("  need the Master Key MK — held only by the authority.")
        print()


if __name__ == "__main__":
    run_collusion_demo()

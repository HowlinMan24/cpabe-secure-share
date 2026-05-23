"""
Authority — trusted key-issuing authority.

Threat model
------------
The authority is the only trusted party in the system.  It:
  * Generates the public/master key pair once (Setup).
  * Issues attribute-bound secret keys to users on request (KeyGen).
  * Must protect the master key (MK) at all costs.

KEY ESCROW — a known architectural limitation
---------------------------------------------
Because the authority generates all user secret keys from MK, it can create
a secret key for *any* attribute set, including one that satisfies every
policy in the system.  The authority can therefore decrypt any ciphertext.

This is not a bug but an inherent property of single-authority CP-ABE.
Mitigations in the literature include:
  * Multi-authority CP-ABE (Chase 2007; Lewko & Waters 2011): attributes are
    split across independent authorities, each holding a partial master key.
    An adversary would need to corrupt all authorities to break the scheme.
  * Decentralised ABE: no single authority; attributes self-certify via
    public-key infrastructure.

For this academic project we accept key escrow and document it explicitly.

In production the master key would be stored in a Hardware Security Module
(HSM) or protected via threshold secret sharing so that no single person or
machine holds it in cleartext.
"""

from pathlib import Path

from crypto.cpabe import setup, keygen, serialize_charm_obj, deserialize_charm_obj

# Default directory layout (overridable in tests via keys_dir parameter)
_DEFAULT_KEYS_DIR = Path("keys")


def authority_setup(keys_dir: Path = _DEFAULT_KEYS_DIR) -> tuple:
    """
    Run CP-ABE Setup — call once to bootstrap the system.

    Generates PK (public, share freely) and MK (secret, authority only).
    Both are persisted to disk under keys_dir/.

    Returns:
        (pk, mk) as charm dict objects.
    """
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "users").mkdir(exist_ok=True)

    pk, mk = setup()

    (keys_dir / "pk.pkl").write_bytes(serialize_charm_obj(pk))
    (keys_dir / "mk.pkl").write_bytes(serialize_charm_obj(mk))

    print(f"[Authority] Setup complete.")
    print(f"  PK → {keys_dir / 'pk.pkl'}  (share with all participants)")
    print(f"  MK → {keys_dir / 'mk.pkl'}  (KEEP SECRET — key escrow risk)")
    return pk, mk


def authority_keygen(
        user_id: str,
        attributes: list[str],
        keys_dir: Path = _DEFAULT_KEYS_DIR,
) -> None:
    """
    Run CP-ABE KeyGen — issue a secret key for user_id.

    The resulting key cryptographically binds a fresh random blinding factor
    to the given attribute set.  This binding is what prevents collusion:
    two users issued at different times have independent blinding factors that
    cannot be combined to extend either user's decryption capability.

    Args:
        user_id:    unique string identifier for the user.
        attributes: lowercase attribute strings,
                    e.g. ['role:doctor', 'dept:cardiology'].
        keys_dir:   root of the key storage directory.
    """
    pk = load_pk(keys_dir)
    mk = _load_mk(keys_dir)

    sk = keygen(pk, mk, attributes)

    user_path = keys_dir / "users" / f"{user_id}.pkl"
    user_path.write_bytes(serialize_charm_obj(sk))

    # Normalise for display (keygen already lowercases)
    display_attrs = [a.lower() for a in attributes]
    print(f"[Authority] Key issued for '{user_id}': {display_attrs}")
    print(f"  SK → {user_path}")


# ---------------------------------------------------------------------------
# Key loading helpers (used by DataOwner and DataUser)
# ---------------------------------------------------------------------------

def load_pk(keys_dir: Path = _DEFAULT_KEYS_DIR):
    """Load the public key.  Required by DataOwner (encrypt) and DataUser (decrypt)."""
    path = keys_dir / "pk.pkl"
    if not path.exists():
        raise FileNotFoundError(
            f"Public key not found at {path}. Run 'authority setup' first."
        )
    return deserialize_charm_obj(path.read_bytes())


def load_sk(user_id: str, keys_dir: Path = _DEFAULT_KEYS_DIR):
    """Load a user's secret key.  Required by DataUser (decrypt)."""
    path = keys_dir / "users" / f"{user_id}.pkl"
    if not path.exists():
        raise FileNotFoundError(
            f"No secret key found for user '{user_id}' at {path}. "
            "Run 'authority keygen' for this user first."
        )
    return deserialize_charm_obj(path.read_bytes())


def _load_mk(keys_dir: Path = _DEFAULT_KEYS_DIR):
    """Load the master key.  MUST remain authority-internal — never expose to users."""
    path = keys_dir / "mk.pkl"
    if not path.exists():
        raise FileNotFoundError(
            f"Master key not found at {path}. Run 'authority setup' first."
        )
    return deserialize_charm_obj(path.read_bytes())

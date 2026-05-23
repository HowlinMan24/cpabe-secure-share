# How the System Works — Step-by-Step Walkthrough

This document explains every part of the project in plain language,
following the exact order things happen at runtime.

---

## The Big Picture

The system has four roles and one central idea:

> A file is locked with a **password that only the right combination of
> attributes can unlock** — and that lock is mathematical, not software.

| Role | What it does |
|------|-------------|
| **Authority** | The only trusted party. Generates keys for users. |
| **Data Owner** | Encrypts a file and uploads it. |
| **Storage Server** | Stores encrypted files. Never sees the contents. |
| **Data User** | Downloads and decrypts — only succeeds if their attributes match the policy. |

---

## Part 1 — The Cryptography Primitives (`crypto/`)

Before anything else, understand the two crypto building blocks.

### `crypto/cpabe.py` — The CP-ABE Layer (the access control lock)

**CP-ABE** stands for Ciphertext-Policy Attribute-Based Encryption.
The scheme used here is **BSW07** (Bethencourt, Sahai, Waters, 2007),
loaded from the `charm-crypto` library.

This file wraps four functions around charm:

#### `setup()` → `(pk, mk)`
Generates two keys:
- **PK (Public Key)** — given to everyone. Anyone with PK can *encrypt*.
- **MK (Master Key)** — kept secret by the authority. Anyone with MK can
  issue user keys (and therefore decrypt anything — this is the key escrow
  limitation we document).

Internally, charm picks random elements in a bilinear pairing group
(SS512 — a type of elliptic curve math) and derives the two keys from them.

#### `keygen(pk, mk, attributes)` → `sk`
Takes the master key and a **list of attributes** like
`['role:doctor', 'dept:cardiology']` and produces a **user secret key (SK)**.

The critical detail: each SK contains a **fresh random blinding factor `r`**
chosen specifically for this user. Every per-attribute component in the SK
is mathematically tied to that `r`. This is what makes the scheme
collusion-resistant (explained in Part 5).

#### `encrypt(pk, policy)` → `(ct, gt_elem)`
This does NOT encrypt the file. It encrypts a **random group element**
(called `gt_elem`) under the access policy string, e.g.
`"(role:doctor and dept:cardiology) or role:admin"`.

The `gt_elem` is the secret that will become the AES key (see Part 2).
The `ct` (ciphertext) can only be unlocked by someone whose attributes
satisfy the policy.

#### `decrypt(pk, sk, ct)` → `gt_elem`
Tries to recover the `gt_elem` from the ciphertext using the user's SK.

- If the user's attributes **satisfy** the policy → returns the original `gt_elem`.
- If they **do not satisfy** the policy → charm returns `False`, and we
  raise a `DecryptionError`. No key material is exposed.

#### `gt_to_aes_key(gt_elem)` → `32 bytes`
Converts the recovered `gt_elem` into an AES key by hashing it:
```
AES key = SHA-256( serialize(gt_elem) )
```
SHA-256 maps the variable-length group element to exactly 32 bytes
suitable for AES-256.

---

### `crypto/aes.py` — The AES Layer (the fast encryption for the file)

CP-ABE is too slow for large files (it uses expensive pairing operations).
So the actual file is encrypted with **AES-256-GCM**, which is fast,
constant-time, and handles files of any size.

**GCM mode** gives us two things at once:
1. **Confidentiality** — the content is hidden.
2. **Integrity** — if anyone tampers with the ciphertext (including the
   storage server), the decryption step throws an `InvalidTag` error
   before returning any data.

#### `encrypt_file(plaintext, aes_key)` → `(nonce, ciphertext)`
Generates a random 12-byte **nonce** (a one-time number), then encrypts
the plaintext. The 16-byte GCM authentication tag is automatically
appended to the ciphertext by the library.

#### `decrypt_file(nonce, ciphertext, aes_key)` → `plaintext`
Reverses the above. If the tag doesn't match, it raises `InvalidTag`
before returning anything — tamper detection built into the cipher.

---

## Part 2 — Authority (`authority/authority.py`)

The authority is the only party that runs once at the start to set
up the system, and then on demand to issue user keys.

### Step A: `authority_setup(keys_dir)`

Calls `setup()` from `crypto/cpabe.py` to get `(pk, mk)`, then
saves them to disk:

```
keys/pk.pkl   ← public key (share with everyone)
keys/mk.pkl   ← master key (NEVER share — key escrow risk)
```

Both are saved using Python's `pickle` module. Pickle turns the charm
dictionary objects into raw bytes that can be written to a file and
read back later.

### Step B: `authority_keygen(user_id, attributes, keys_dir)`

Loads PK and MK from disk, calls `keygen(pk, mk, attributes)` from
`crypto/cpabe.py`, and saves the resulting user secret key:

```
keys/users/alice.pkl   ← Alice's secret key (give only to Alice)
keys/users/bob.pkl     ← Bob's secret key
```

Each call to `keygen` for a different user picks a **new independent
random blinding factor** — this is the source of collusion resistance.

---

## Part 3 — Data Owner (`data_owner/owner.py`)

The data owner encrypts a file and packages it into a blob
that is safe to hand to the untrusted storage server.

### `encrypt_and_package(file_path, policy, keys_dir)` → `bytes`

Here is the exact sequence of operations:

**Step 1 — CP-ABE encrypt a random GT element under the policy**
```python
cpabe_ct, gt_elem = cpabe_encrypt(pk, policy)
```
`gt_elem` is a random secret. `cpabe_ct` is a lock that only users
satisfying `policy` can open. The storage server gets the lock but never
the secret.

**Step 2 — Derive the AES key from the GT element**
```python
aes_key = gt_to_aes_key(gt_elem)   # SHA-256(serialize(gt_elem)) → 32 bytes
```
The GT element leaves scope immediately after this. It is never stored.

**Step 3 — AES-256-GCM encrypt the actual file**
```python
nonce, aes_ct = encrypt_file(plaintext, aes_key)
```
This encrypts the full file contents. The AES key is used here and then
also discarded — it is re-derived during decryption.

**Step 4 — Package everything together**
```python
package = {
    'version':   1,
    'filename':  'patient_record.txt',
    'policy':    '(role:doctor and dept:cardiology) or role:admin',
    'cpabe_ct':  <serialized CP-ABE ciphertext>,  # the lock
    'aes_nonce': <12 bytes>,
    'aes_ct':    <file ciphertext + GCM tag>,
}
return pickle.dumps(package)
```

The package is a single blob of bytes. The storage server cannot extract
anything useful from it because:
- `cpabe_ct` requires a matching SK to unlock.
- `aes_ct` requires the AES key, which requires unlocking `cpabe_ct`.

---

## Part 4 — Storage Server (`storage_server/server.py`)

A simple **FastAPI** web server with four endpoints:

| Endpoint | What it does |
|----------|-------------|
| `POST /upload/{file_id}` | Saves the encrypted blob to the `storage/` folder |
| `GET /download/{file_id}` | Sends the blob back |
| `GET /files` | Lists stored file IDs and sizes |
| `DELETE /files/{file_id}` | Removes a file |
| `GET /health` | Liveness check (used by docker-compose) |

The server has **no knowledge of any keys**. It receives only encrypted
bytes and stores them as-is. Even if an attacker has root access to the
server's filesystem, they cannot decrypt anything without a valid user SK.

The server includes path-traversal protection — a `file_id` containing
`/`, `\`, or starting with `.` is rejected, preventing requests like
`../secrets`.

---

## Part 5 — Data User (`data_user/user.py`)

### `decrypt_package(package_bytes, user_id, output_dir, keys_dir)` → `Path`

Reverses the data owner's work. Steps in exact order:

**Step 1 — Unpack the blob**
```python
package = pickle.loads(package_bytes)
```
Recovers the dict with `cpabe_ct`, `aes_nonce`, `aes_ct`, etc.

**Step 2 — Load keys**
```python
pk = load_pk(keys_dir)          # keys/pk.pkl
sk = load_sk(user_id, keys_dir) # keys/users/<user_id>.pkl
```

**Step 3 — CP-ABE decrypt (the cryptographic gate)**
```python
gt_elem = cpabe_decrypt(pk, sk, cpabe_ct)
```
This is where access control happens. Charm runs pairing operations to
check if `sk`'s attributes satisfy the policy in `cpabe_ct`.

- **Satisfied** → `gt_elem` is recovered (identical to the one the owner
  encrypted).
- **Not satisfied** → `DecryptionError` is raised. Execution stops. No
  AES key is ever computed. The file remains unreadable.

**Step 4 — Derive the AES key (mirrors the owner exactly)**
```python
aes_key = gt_to_aes_key(gt_elem)   # SHA-256(serialize(gt_elem))
```
Because `gt_elem` is identical to the owner's, this produces the same
32-byte AES key.

**Step 5 — AES-256-GCM decrypt**
```python
plaintext = decrypt_file(package['aes_nonce'], package['aes_ct'], aes_key)
```
If the AES key is correct and the ciphertext hasn't been tampered with,
this returns the original file bytes.

**Step 6 — Write the file**
The plaintext is written to `output_dir/<original_filename>`.

---

## Part 6 — Collusion Resistance (Why Two Partial Keys Don't Add Up)

Suppose the policy is `role:doctor AND dept:cardiology`.

- Bob has `[role:doctor]` → denied.
- Carol has `[dept:cardiology]` → denied.
- What if Bob gives Carol his SK file, and she combines them?

**This fails because of the random blinding factor `r`.**

When the authority runs `keygen` for Bob, it picks a random `r_bob`.
Every component of Bob's SK is computed from `r_bob`:
```
D_bob           = g^((α + r_bob) / β)    ← the core component
D_bob[role:doctor] = g^r_bob · H(role:doctor)^r_x
```

For Carol, a different random `r_carol` is chosen:
```
D_carol[dept:cardiology] = g^r_carol · H(dept:cardiology)^r_y
```

During decryption, the algorithm runs a Lagrange interpolation that needs
all per-attribute components to have the **same** `r`. Bob's core component
`D_bob` is locked to `r_bob`. Carol's `dept:cardiology` component was
built with `r_carol`. Since `r_bob ≠ r_carol`, the pairing equations
produce a wrong answer — a random group element instead of the real
`gt_elem`. The derived AES key is therefore wrong, and AES-GCM's
authentication tag rejects it.

The only way to get a valid key covering both attributes is to ask the
authority — which requires MK.

---

## Part 7 — CLI (`cli.py`)

The CLI is the thin layer that wires everything together.
It uses the **Click** library for argument parsing.

Each command maps directly to one function call:

```
setup          → authority.authority_setup()
keygen         → authority.authority_keygen()
encrypt        → data_owner.encrypt_and_package()  + write .pkg file
upload         → HTTP POST /upload/{id}  to storage server
ls             → HTTP GET  /files
download       → HTTP GET  /download/{id}
decrypt        → data_user.decrypt_package()
demo           → demo.demo_basic.run_demo()
demo-collusion → demo.demo_collusion.run_collusion_demo()
```

The server URL and keys directory can be set via `--server` / `--keys-dir`
flags or via environment variables `STORAGE_SERVER_URL` and `KEYS_DIR`.
This is how docker-compose passes `http://storage:8000` to the client
container without hardcoding it.

---

## Part 8 — Demo Scripts (`demo/`)

Both demos run entirely in a **temporary directory** — they set up a fresh
key pair, issue keys, encrypt a file, then decrypt it, all in memory and
on disk in `/tmp`. Nothing persists and the storage server is not needed.

### `demo_basic.py`

1. `authority_setup()` — generates PK/MK.
2. `authority_keygen("alice", ["role:doctor", "dept:cardiology"])`.
3. `authority_keygen("bob", ["role:nurse", "dept:cardiology"])`.
4. `encrypt_and_package(sample_file, policy)` — encrypts a patient record.
5. `decrypt_package(pkg, "alice")` → **success**, prints the file contents.
6. `decrypt_package(pkg, "bob")` → **`DecryptionError`** — cryptographic denial.

### `demo_collusion.py`

1–4. Same setup but Bob has `[role:doctor]` and Carol has `[dept:cardiology]`.
5. `decrypt_package(pkg, "bob")` → denied.
6. `decrypt_package(pkg, "carol")` → denied.
7. Manually merges both SK dicts into `merged_sk`.
8. Calls `_SCHEME.decrypt(pk, merged_sk, cpabe_ct)` directly → still fails.
9. Prints the mathematical explanation of why blinding factors prevent combination.

---

## Summary: Data Flow End-to-End

```
Authority
  setup()           →   pk, mk
  keygen(mk, attrs) →   sk  (one per user, stored in keys/users/)

Data Owner
  encrypt(pk, policy) →  cpabe_ct, gt_elem
  SHA-256(gt_elem)    →  aes_key
  AES-GCM(file, key)  →  nonce, aes_ct
  package: {cpabe_ct, nonce, aes_ct, policy, filename}  →  storage server

Data User
  download package from server
  cpabe_decrypt(pk, sk, cpabe_ct)   →  gt_elem  [GATE — fails if policy unmet]
  SHA-256(gt_elem)                  →  aes_key
  AES-GCM-decrypt(nonce, aes_ct)    →  plaintext file
```

---

## Why `__init__.py` Files Must Exist

Each folder (`crypto/`, `authority/`, etc.) is a Python **package**.
Python only recognises a folder as a package if it contains an
`__init__.py` file — even if that file is completely empty.

Without them, `from crypto.cpabe import setup` would raise
`ModuleNotFoundError` because Python would not know `crypto` is a package.
The files have no code; they simply act as markers.

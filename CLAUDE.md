# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**cpabe-secure-share** is a Python implementation of a Secure File Sharing system using **CP-ABE (Ciphertext-Policy Attribute-Based Encryption)** — specifically the BSW07 scheme from [charm-crypto](https://github.com/JHUISI/charm). Files are encrypted under a Boolean access policy; only users whose attributes satisfy the policy can decrypt. It is a university Data Security project.

## Running the System

### Preferred: Docker (charm-crypto has native C dependencies)

```bash
docker compose build               # ~10 min first time (compiles PBC + charm)
docker compose up -d storage       # start storage server on :8000
docker compose run --rm client python cli.py demo
docker compose run --rm client python cli.py demo-collusion
```

### Verify charm works first

```bash
docker run --rm cpabe-secure-share python smoke_test.py
```

### CLI commands

```bash
python cli.py setup
python cli.py keygen alice -a role:doctor -a dept:cardiology
python cli.py encrypt report.pdf -p "role:doctor and dept:cardiology"
python cli.py upload report.pdf.pkg
python cli.py ls
python cli.py download report.pdf.pkg
python cli.py decrypt report.pdf.pkg alice   # succeeds
python cli.py decrypt report.pdf.pkg bob     # denied
```

### Run demos directly (no server needed)

```bash
python -m demo.demo_basic
python -m demo.demo_collusion
```

### Storage server standalone

```bash
python -m storage_server.server    # FastAPI on :8000
```

## Architecture

```
crypto/cpabe.py   ← BSW07 wrapper (setup, keygen, encrypt, decrypt, gt_to_aes_key)
crypto/aes.py     ← AES-256-GCM helpers (encrypt_file, decrypt_file)
authority/        ← Setup() + KeyGen(); manages PK/MK/SK files under keys/
data_owner/       ← encrypt_and_package(): hybrid encrypt → bytes blob
data_user/        ← decrypt_package(): unpack blob → CP-ABE → AES → plaintext file
storage_server/   ← FastAPI blob store (POST/GET /upload /download /files)
demo/             ← self-contained demo scripts (no server required)
cli.py            ← Click CLI wiring all the above together
smoke_test.py     ← standalone charm-crypto verification (run after docker build)
```

## Hybrid Encryption Flow

**Encrypt (data_owner/owner.py):**
1. `cpabe_encrypt(pk, policy)` → `(cpabe_ct, gt_elem)`  — random GT element encrypted under policy
2. `gt_to_aes_key(gt_elem)` → `SHA-256(serialize(gt_elem))` → 32-byte AES key
3. `encrypt_file(plaintext, aes_key)` → `(nonce, aes_ct)` — AES-256-GCM
4. Package: `{cpabe_ct, aes_nonce, aes_ct, policy, filename}` → pickled bytes

**Decrypt (data_user/user.py):**
1. `cpabe_decrypt(pk, sk, cpabe_ct)` → `gt_elem` (fails with `DecryptionError` if policy unmet)
2. `gt_to_aes_key(gt_elem)` → same 32-byte AES key
3. `decrypt_file(nonce, aes_ct, aes_key)` → plaintext

## Key Design Decisions

- **Attribute convention**: All attribute strings are **lowercase** with `namespace:value` format (e.g. `role:doctor`, `dept:cardiology`). Policies use `and`/`or` operators.
- **Serialisation**: charm objects (keys, ciphertexts) are pickled via `serialize_charm_obj` / `deserialize_charm_obj` in `crypto/cpabe.py`. The outer package dict is also pickled. Production would use a language-neutral format.
- **Module-level singletons**: `_GROUP = PairingGroup('SS512')` and `_SCHEME = CPabe_BSW07(_GROUP)` are created once at import time in `crypto/cpabe.py`. All modules share them by importing from there.
- **Error handling**: `DecryptionError` (from `crypto.cpabe`) signals policy-not-satisfied; `cryptography.exceptions.InvalidTag` signals tampered ciphertext. Both propagate up to the CLI.
- **No server calls in crypto/authority/owner/user modules**: HTTP calls live only in `cli.py`. The role modules are pure Python with file I/O only.

## Key Escrow

The authority holds MK and can decrypt any ciphertext. This is an inherent single-authority CP-ABE limitation, explicitly documented in `authority/authority.py` and the README.

## charm-crypto Notes

- Must be installed via Dockerfile (not pip); requires compiled PBC and GMP C libraries.
- Uses `PairingGroup('SS512')` — 512-bit symmetric pairing group, ~80-bit classical security.
- `keygen(pk, mk, attrs)` expects lowercase string list.
- `encrypt(pk, M, policy_str)` returns False (not exception) when auth fails; we wrap in `DecryptionError`.
- If charm returns `False` from decrypt, it means the policy was not satisfied — not an exception.

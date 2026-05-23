# CP-ABE Secure File Sharing

A university Data Security project demonstrating **Ciphertext-Policy
Attribute-Based Encryption (CP-ABE)** for fine-grained, cryptographically
enforced access control on shared files.

---

## What This System Does

A Data Owner encrypts a file under an **access policy** such as:

```
(role:doctor AND dept:cardiology) OR role:admin
```

Only users whose attribute set **satisfies** the policy can decrypt the file.
The enforcement is mathematical — it relies on bilinear pairings, not on a
software gate or a database lookup.  An unauthorised user with the ciphertext
in hand cannot decrypt it, even by inspecting or modifying the code.

---

## Architecture

```
┌──────────────┐        Setup / KeyGen         ┌───────────────────┐
│  Authority   │ ─────────────────────────────▶ │  Users (SK files) │
│  (PK + MK)   │                                └───────────────────┘
└──────────────┘
       │ PK (public)
       ▼
┌──────────────┐   encrypted package (blob)    ┌───────────────────┐
│  Data Owner  │ ─────────────────────────────▶ │  Storage Server   │
│  (encrypts)  │                                │  (untrusted)      │
└──────────────┘                                └───────────────────┘
                                                        │ blob
                                                        ▼
                                               ┌────────────────────┐
                                               │  Data User         │
                                               │  (decrypts if SK   │
                                               │   satisfies policy) │
                                               └────────────────────┘
```

### Four Roles

| Role | Responsibility |
|------|---------------|
| **Authority** | Runs `Setup()` once to produce PK/MK; runs `KeyGen()` to issue attribute-bound user keys |
| **Data Owner** | Encrypts files with hybrid encryption (AES-256-GCM + CP-ABE key wrap) under a policy |
| **Storage Server** | Untrusted blob store; never sees plaintext or keys |
| **Data User** | Downloads and decrypts; succeeds only if attributes satisfy the policy |

### Hybrid Encryption (Why AES + CP-ABE?)

CP-ABE operates on pairing-group elements and is orders of magnitude slower
than AES.  Encrypting a file of arbitrary size with CP-ABE directly is
impractical.  Instead:

```
random GT element  ──CP-ABE──▶  cpabe_ciphertext  (small, policy-bound)
       │
    SHA-256
       │
  aes_key (32 B)  ──AES-256-GCM──▶  aes_ciphertext  (bulk file data)
```

The package stored on the server contains `cpabe_ciphertext + aes_ciphertext`.
The AES key is never stored; it is derived on demand by the user who recovers
the GT element via CP-ABE decryption.

### BSW07 Scheme

The project uses the **Bethencourt–Sahai–Waters 2007** CP-ABE scheme via
[charm-crypto](https://github.com/JHUISI/charm).  BSW07 supports arbitrary
monotone Boolean access policies and is proven IND-CPA secure under the
Decisional Bilinear Diffie-Hellman (DBDH) assumption.

---

## Security Properties and Known Limitations

### Properties
- **Cryptographic access control** — denial is enforced by the math, not by code.
- **Collusion resistance** — each user key embeds a unique random blinding factor;
  two users with disjoint attributes cannot pool their keys to gain joint access.
- **Integrity** — AES-256-GCM provides authenticated encryption; a tampered
  ciphertext is detected and rejected before any plaintext is produced.
- **Untrusted server** — the storage server learns only ciphertext and the
  access policy string; it cannot decrypt even with full filesystem access.

### Known Limitations (inherent to single-authority CP-ABE)
- **Key escrow** — the Authority holds the master key and can issue a secret key
  for any attribute set.  It can therefore decrypt any ciphertext.  In
  production this would be mitigated by multi-authority CP-ABE or an HSM.
- **Policy visibility** — the access policy is embedded in cleartext in the
  package.  Hidden-policy CP-ABE (not implemented here) can conceal it.
- **No user revocation** — revoking a user's key requires re-encrypting all
  files they could access.  Attribute revocation schemes exist but are complex.
- **~80-bit security** — the SS512 pairing group provides approximately 80-bit
  classical security, sufficient for academic demonstration but below modern
  production standards (NIST recommends ≥ 128-bit).

---

## Setup — Docker (Primary Path)

Docker is the recommended setup because charm-crypto requires native PBC and
GMP C libraries that are difficult to install consistently on all platforms.

### Prerequisites
- [Docker Desktop](https://docs.docker.com/get-docker/) ≥ 24 (or Docker Engine + Compose plugin)
- ~4 GB disk space (image is large due to compiled C libraries)
- ~10 minutes for the first build (PBC + charm compilation)

### 1. Build

```bash
docker compose build
```

The Dockerfile compiles PBC 0.5.14 from source and builds charm-crypto from
the upstream GitHub repo.  A smoke test runs automatically at the end of the
build; if it passes, the image is good.

To see the smoke test output explicitly:

```bash
docker run --rm cpabe-secure-share python smoke_test.py
```

### 2. Start the Storage Server

```bash
docker compose up -d storage
```

Verify it is healthy:

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

### 3. Run CLI Commands

Use `docker compose run --rm client` to execute any CLI command:

```bash
# Authority: initialise the system
docker compose run --rm client python cli.py setup

# Authority: issue keys
docker compose run --rm client python cli.py keygen alice \
    -a role:doctor -a dept:cardiology

docker compose run --rm client python cli.py keygen bob \
    -a role:nurse -a dept:cardiology

# DataOwner: encrypt a file
echo "Confidential data" > secret.txt
docker compose run --rm client python cli.py encrypt secret.txt \
    -p "(role:doctor and dept:cardiology) or role:admin"

# Upload the package
docker compose run --rm client python cli.py upload secret.txt.pkg

# List files on server
docker compose run --rm client python cli.py ls

# Download the package
docker compose run --rm client python cli.py download secret.txt.pkg

# DataUser: decrypt (Alice should succeed, Bob should fail)
docker compose run --rm client python cli.py decrypt secret.txt.pkg alice
docker compose run --rm client python cli.py decrypt secret.txt.pkg bob
```

### 4. Run the Demos

The demos are self-contained and do **not** require the storage server.

```bash
# Basic access control demo (success + failure)
docker compose run --rm client python cli.py demo

# Collusion resistance demo
docker compose run --rm client python cli.py demo-collusion
```

Or run them directly:

```bash
docker run --rm cpabe-secure-share python -m demo.demo_basic
docker run --rm cpabe-secure-share python -m demo.demo_collusion
```

---

## Connecting PyCharm Professional to the Docker Interpreter

PyCharm Professional supports a Docker-based Python interpreter, giving full
run/debug/breakpoint support inside the container.

### Option A — Docker image interpreter (simplest)

1. **Build the image** first: `docker compose build`
2. In PyCharm: **Settings** → **Project: cpabe-secure-share** →
   **Python Interpreter** → click the gear → **Add Interpreter** →
   **On Docker…**
3. Set:
   - Server: `Docker` (or create a new connection to your Docker socket)
   - Image: `cpabe-secure-share`
   - Python interpreter path: `/usr/bin/python3`
4. Click **OK** → PyCharm indexes the environment.
5. Right-click any `.py` file → **Run** — it executes inside the container.

### Option B — Docker Compose interpreter (recommended for full stack)

1. In PyCharm: **Settings** → **Python Interpreter** → **Add Interpreter** →
   **On Docker Compose…**
2. Set:
   - Configuration file: `docker-compose.yml`
   - Service: `client`
3. PyCharm will start the `client` service and connect to it as the
   interpreter.  The `storage` service starts automatically via `depends_on`.

### Debugging tip

Set breakpoints anywhere in the source.  When you run `cli.py` or a demo
script with the Docker interpreter, PyCharm's debugger connects to the process
inside the container over a TCP port it manages automatically.

---

## Native Install Fallback (Linux/macOS)

If you cannot use Docker, you can install the dependencies natively.  This
is more fragile but possible on Ubuntu 22.04 or macOS with Homebrew.

### 1. Install GMP and OpenSSL

**Ubuntu/Debian:**
```bash
sudo apt-get install libgmp-dev libssl-dev build-essential flex bison
```

**macOS (Homebrew):**
```bash
brew install gmp openssl flex bison
export LIBRARY_PATH="$(brew --prefix gmp)/lib:$(brew --prefix openssl)/lib:$LIBRARY_PATH"
export C_INCLUDE_PATH="$(brew --prefix gmp)/include:$(brew --prefix openssl)/include:$C_INCLUDE_PATH"
```

### 2. Build and Install PBC

```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz && cd pbc-0.5.14
./configure && make -j$(nproc) && sudo make install && sudo ldconfig
```

### 3. Build and Install charm-crypto

```bash
git clone --depth=1 https://github.com/JHUISI/charm.git
cd charm
python3 configure.sh
pip install -e .
```

### 4. Install Python dependencies and run

```bash
pip install -r requirements.txt
python smoke_test.py        # verify everything works
python cli.py --help
```

> **Note on macOS:** charm's configure.sh sometimes struggles to find
> Homebrew-installed libraries.  Pass explicit paths if the configure step
> fails:
> ```bash
> CFLAGS="-I$(brew --prefix gmp)/include" \
> LDFLAGS="-L$(brew --prefix gmp)/lib" python3 configure.sh
> ```

---

## Project Structure

```
cpabe-secure-share/
├── Dockerfile                 # Multi-stage build: PBC → charm → app
├── docker-compose.yml         # storage server + client services
├── smoke_test.py              # Verifies charm-crypto before running the app
├── requirements.txt           # Python deps (charm excluded; see Dockerfile)
├── cli.py                     # Click CLI entry point
│
├── crypto/
│   ├── cpabe.py               # BSW07 wrapper: setup, keygen, encrypt, decrypt
│   └── aes.py                 # AES-256-GCM helpers for the file layer
│
├── authority/
│   └── authority.py           # Setup(), KeyGen(), key file management
│
├── data_owner/
│   └── owner.py               # encrypt_and_package() — hybrid encryption
│
├── data_user/
│   └── user.py                # decrypt_package() — hybrid decryption
│
├── storage_server/
│   └── server.py              # FastAPI blob store (POST/GET /files)
│
└── demo/
    ├── demo_basic.py          # Success + failure access control demo
    └── demo_collusion.py      # Collusion resistance demo
```

---

## CLI Reference

```
python cli.py [--server URL] [--keys-dir DIR] COMMAND

  setup                        Generate PK and MK (run once)
  keygen USER -a ATTR ...      Issue a secret key for USER
  encrypt FILE -p POLICY       Encrypt FILE under POLICY → FILE.pkg
  upload PKG                   Upload PKG to storage server
  ls                           List files on storage server
  download FILE_ID             Download encrypted package
  decrypt PKG USER             Decrypt PKG as USER
  demo                         Run basic access control demo
  demo-collusion               Run collusion resistance demo
```

Environment variables:
- `STORAGE_SERVER_URL` — overrides `--server` (default: `http://localhost:8000`)
- `KEYS_DIR` — overrides `--keys-dir` (default: `keys/`)

---

## Attribute Naming Convention

All attribute strings must be **lowercase** and use the `namespace:value`
format:

```
role:doctor       dept:cardiology
role:admin        dept:oncology
role:nurse        clearance:top-secret
```

Policies use `and` / `or` operators (case-insensitive) and parentheses:

```
(role:doctor and dept:cardiology) or role:admin
role:admin or (clearance:top-secret and dept:research)
```

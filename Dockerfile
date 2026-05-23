# ============================================================================
# CP-ABE Secure File Sharing — Dockerfile
# ============================================================================
#
# Build stages
# ────────────
#   Stage 1 (builder): compile PBC and charm-crypto from source.
#   Stage 2 (runtime): copy compiled artifacts; install Python deps.
#
# Why not `pip install charm-crypto`?
#   The PyPI package is outdated and does not compile cleanly against modern
#   system libraries.  Building from the upstream GitHub source is required.
#
# Why Ubuntu 22.04?
#   LTS, stable GMP/OpenSSL packages, Python 3.10 in-distro.
#
# Why compile PBC from source?
#   libpbc-dev is not in Ubuntu 22.04's default apt sources.  The upstream
#   tarball (pbc-0.5.14) is the reference implementation from Ben Lynn's
#   Stanford page and is the same one charm's CI uses.
# ============================================================================

# ── Stage 1: build charm-crypto (heavy, cached) ─────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.10 \
        python3.10-dev \
        python3-pip \
        python3-setuptools \
        libgmp-dev \
        libssl-dev \
        build-essential \
        flex \
        bison \
        wget \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Ensure python3 → python3.10
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1 \
 && update-alternatives --install /usr/bin/python  python  /usr/bin/python3.10 1

# ── PBC (Pairing-Based Cryptography) library ────────────────────────────────
# charm requires the PBC C library for bilinear pairing operations.
# We compile it from source and install to /usr/local.
ENV PBC_VERSION=0.5.14
RUN wget -q "https://crypto.stanford.edu/pbc/files/pbc-${PBC_VERSION}.tar.gz" \
 && tar xf "pbc-${PBC_VERSION}.tar.gz" \
 && cd "pbc-${PBC_VERSION}" \
 && ./configure --prefix=/usr/local \
 && make -j"$(nproc)" \
 && make install \
 && ldconfig \
 && cd .. \
 && rm -rf "pbc-${PBC_VERSION}" "pbc-${PBC_VERSION}.tar.gz"

# Make sure pkg-config and compiler can find PBC and GMP headers/libs
ENV C_INCLUDE_PATH=/usr/local/include
ENV LIBRARY_PATH=/usr/local/lib
ENV LD_LIBRARY_PATH=/usr/local/lib

# ── charm-crypto (CP-ABE primitives) ─────────────────────────────────────────
# Clone the upstream JHUISI/charm repo and build in-place.
# --depth=1 keeps the layer small.
RUN git clone --depth=1 https://github.com/JHUISI/charm.git /opt/charm \
 && cd /opt/charm \
 && python3 configure.sh \
 && pip3 install --no-cache-dir -e . \
 # Quick import check: fail the build early if charm doesn't load.
 && python3 -c "
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
g = PairingGroup('SS512')
s = CPabe_BSW07(g)
pk, mk = s.setup()
M = g.random(GT)
ct = s.encrypt(pk, M, 'one and two')
sk = s.keygen(pk, mk, ['one', 'two'])
assert s.decrypt(pk, sk, ct) == M, 'BSW07 round-trip failed'
print('[✓] charm-crypto + BSW07 smoke test passed in builder stage')
"

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV LD_LIBRARY_PATH=/usr/local/lib

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.10 \
        python3.10-dev \
        python3-pip \
        libgmp-dev \
        libssl-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1 \
 && update-alternatives --install /usr/bin/python  python  /usr/bin/python3.10 1

# Copy PBC shared libraries from builder
COPY --from=builder /usr/local/lib/libpbc*  /usr/local/lib/
COPY --from=builder /usr/local/include/pbc  /usr/local/include/pbc
RUN ldconfig

# Copy the installed charm-crypto package (site-packages + any compiled .so files)
COPY --from=builder /usr/local/lib/python3.10 /usr/local/lib/python3.10
COPY --from=builder /opt/charm /opt/charm

# Re-link charm into this Python environment
RUN pip3 install --no-cache-dir --no-build-isolation -e /opt/charm

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Create runtime directories
RUN mkdir -p keys/users storage uploads downloads

# Verify everything works in the final image
RUN python3 smoke_test.py

EXPOSE 8000

# Default: show CLI help.  Override CMD in docker-compose for specific roles.
CMD ["python3", "cli.py", "--help"]

# threshold_ecdsa

Research artifact for a C++20 implementation of the GG2019 threshold ECDSA protocol.

## Paper Reference

- Rosario Gennaro, Steven Goldfeder.  
  *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (CCS 2019).

This repository implements protocol components as executable state machines and emphasizes:

- protocol-correct message flow,
- strict input validation and abort behavior,
- reproducible tests and benchmarks.

It is not a production-ready wallet/signing service.

## Scope of This Artifact

### Implemented Components

- Elliptic-curve scalar/point operations (`libsecp256k1`-backed wrappers).
- Paillier encryption wrapper (`libhcs`-backed).
- Hashing, commitments, transcript/challenge utilities, wire encoding.
- Session model with lifecycle management (`running/completed/aborted/timed-out`).
- In-memory transport and session routing.
- Threshold key generation (`KeygenSession`, 3 phases).
- Threshold signing (`SignSession`, Phase1 to Phase5E).
- Strict/dev gating for square-free and auxiliary-parameter proof artifacts.

### Current Engineering Goal

The repository targets protocol engineering reproducibility, not hardened deployment.

## Repository Layout

```text
include/tecdsa/
  crypto/      # Scalar/ECPoint/Paillier/hash/commitment/encoding/transcript/proofs
  net/         # Envelope, transport interfaces, in-memory network
  protocol/    # Session base, router, keygen/sign state machines
src/
  crypto/
  net/
  protocol/
tests/
  crypto_primitives_tests.cpp
  protocol_infrastructure_tests.cpp
  keygen_flow_tests.cpp
  sign_flow_tests.cpp
bench/
  protocol_flow_bench.cpp
third_party/
  secp256k1/
  libhcs/
```

## Reproducibility

### Requirements

- CMake >= 3.22
- C++20 compiler (`clang++`/`g++`)
- GMP / gmpxx
- OpenSSL `libcrypto`
- Git submodules:
  - `third_party/secp256k1`
  - `third_party/libhcs`

### Build

```bash
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
```

### Test Suite

Run all tests:

```bash
ctest --test-dir build --output-on-failure
```

Run individual executables:

```bash
./build/crypto_primitives_tests
./build/protocol_infrastructure_tests
./build/keygen_flow_tests
./build/sign_flow_tests
```

### Test Coverage Summary

- `crypto_primitives_tests`: basic crypto primitives and wire format checks.
- `protocol_infrastructure_tests`: transport/router/session skeleton behavior.
- `keygen_flow_tests`: end-to-end keygen, strict gating, and adversarial tampering.
- `sign_flow_tests`: end-to-end signing, proof checks, and adversarial failure paths.

## Protocol Flow (Implemented)

### Keygen (`KeygenSession`)

1. Phase1: broadcast commitment + Paillier public parameters.
2. Phase2: broadcast opens/commitments and send shares point-to-point.
3. Phase3: broadcast `X_i = g^{x_i}` with Schnorr proof.
4. Finalization: aggregate `x_i`, `y`, all `X_i`, and Paillier/public proof artifacts.

### Sign (`SignSession`)

1. Phase1: commit to `Gamma_i`.
2. Phase2: MtA/MtAwc interaction with Appendix-A style proof checks.
3. Phase3: broadcast `delta_i` and aggregate inversion path.
4. Phase4: open `Gamma_i`, verify proof, derive `R` and `r`.
5. Phase5A~5E: commit/open rounds with relation proofs, then finalize `(r, s)`.

## Benchmarking

Run:

```bash
./build/protocol_flow_bench --n 5 --t 2 --keygen-iters 1 --sign-iters 20
```

Arguments:

- `--n`: total parties
- `--t`: threshold (`t < n`)
- `--keygen-iters`: keygen benchmark iterations
- `--sign-iters`: signing benchmark iterations
- `--paillier-bits`: Paillier modulus bits (`>= 2048`)

Output sections:

- `[Keygen]`: per-phase average latency and bytes.
- `[Sign]`: per-phase average latency and bytes.
- `[Strict-Proof Attribution]`: proof-related byte/time attribution.

## Published Baseline Results (2026-02-23)

Raw and summarized artifacts are stored in:

- `bench/results/classic_20260223_000650/index.md`
- `bench/results/classic_20260223_000650/summary.csv`
- `bench/results/classic_20260223_000650/summary.md`

Reported wall-clock summary:

| case | n/t | paillier | keygen_iters | sign_iters | elapsed_sec | keygen_strict_ratio% | sign_strict_ratio% |
|---|---:|---:|---:|---:|---:|---:|---:|
| n2_t1_p2048_k3_s20 | 2/1 | 2048 | 3 | 20 | 24.55 | 88.88 | 76.52 |
| n3_t1_p2048_k3_s20 | 3/1 | 2048 | 3 | 20 | 28.61 | 88.26 | 76.52 |
| n5_t2_p2048_k2_s20 | 5/2 | 2048 | 2 | 20 | 67.21 | 86.74 | 78.38 |
| n5_t2_p3072_k1_s10 | 5/2 | 3072 | 1 | 10 | 80.09 | 89.20 | 75.17 |

Reproduction commands:

```bash
./build/protocol_flow_bench --n 2 --t 1 --paillier-bits 2048 --keygen-iters 3 --sign-iters 20
./build/protocol_flow_bench --n 3 --t 1 --paillier-bits 2048 --keygen-iters 3 --sign-iters 20
./build/protocol_flow_bench --n 5 --t 2 --paillier-bits 2048 --keygen-iters 2 --sign-iters 20
./build/protocol_flow_bench --n 5 --t 2 --paillier-bits 3072 --keygen-iters 1 --sign-iters 10
```

## Limitations

- Network layer is in-memory only (no real transport security/retransmission/persistence).
- No claim of production security hardening.
- Intended for protocol implementation study, testing, and benchmarking.

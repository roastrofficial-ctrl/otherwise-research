# Otherwise — Generation 0.2: The Bounded Authority

An open conditional-custody laboratory: independently evidenced obligations govern release of an encrypted Capsule. One human with one absence contract remains the default use case. More complex contract compositions use the same engine; **one authoriser does not mean one custodian**.

Generation 0.2 separates the application from three key-share services and an independent retained-history witness. Custodians fetch and verify history themselves using Python and JavaScript. This is a bounded feasibility experiment, not production custody or cryptographically unavoidable conditional release.

## Run the complete experiment

Requirements: a running Docker daemon, Docker Compose, a POSIX shell and `openssl` for random bootstrap capabilities. No Python/Node packages install on the host.

```sh
./scripts/experiment02.sh
```

This builds the runtime, runs the original 20 tests, starts a disposable isolated cluster, runs 21 new custody/clock/storage tests, checks 14 fixed vectors and 180 generated snapshots across Python/JavaScript, and runs Solo Witness and Council demos. It removes only its own cluster and volumes on exit. Actual output is preserved in `doc/results02/`.

The cluster has no published ports and its network has no external route. Each custody service and the witness have their own state volume; none is mounted in the adversarial operator container. The trusted runner has provisioning capabilities but no custody volumes. Docker/host administrators remain outside the tested operator boundary.

The old environment still runs:

```sh
./scripts/experiment.sh
```

Original observations under `doc/results/` are retained. The 0.2 script records its baseline rerun separately in `doc/results02/generation01.txt`.

## What was built

- `Engine/`: the original SQLite ordering engine, ciphertext-only ingestion and head-bound owner commands.
- `Bounded/`: trusted creator provisioning, witness commits, real/controlled clock adapters, isolated custody services, adversarial app and synthetic recipient recovery.
- `Verifier/verify.mjs`: independently written JavaScript signature/history/policy verifier.
- `Protocol/vectors/generation02.json`: fixed signed public test fixtures and expected outcomes.
- `tests/`, `tests02/`: preserved original tests plus executable operator/custody/clock/crash attacks.
- `App/demo02.py`: the one-human Solo lifecycle and multi-authority Council through the same protocol machinery.

A trusted creator encrypts with AES-128-GCM and provisions PyCryptodome's established 2-of-3 Shamir sharing. The operator receives ciphertext/public metadata, never the complete key. Its local facts become externally authoritative only after the witness commits a verified immutable prefix. Honest custodians independently validate current witnessed history before issuing scoped share responses. A synthetic recipient reconstructs after permission; no real email, SMS, publishing or sensitive data is used.

## Findings and limits

All recorded checks pass, including the tests that **expect an attack to succeed**. Two malicious custodians decrypt early. A compromised operator plus a compromised witness can fabricate absence if no surviving independent custodian retained the original presence checkpoint. Previously informed custodians can reject such a rewrite.

Clock checks are bounded observations, not proof of correct UTC or human incapacity. Application-only partitions can still look like silence. Physical sampling-to-commit latency, production transport, trusted-client distribution, terminal restart recovery, secure erasure and independent organisational deployment remain unresolved. Static shares cannot be revoked once obtained.

Read [the actual results and six answers](doc/generation02/RESULTS.md), [protocol profiles](PROTOCOL.md), [threat model](THREAT_MODEL.md), [conformance](CONFORMANCE.md), [architecture](doc/generation02/ARCHITECTURE.md), [clock model](doc/generation02/CLOCK_AND_RECOVERY.md), [custody research](CUSTODY_RESEARCH.md) and [proposed Generation 0.3](doc/generation02/GENERATION_0_3.md).

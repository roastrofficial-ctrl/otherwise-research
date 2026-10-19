# Otherwise — Generation 0.1

Conditional custody governed by independently evidenced obligations.

A Capsule commits to encrypted content, independently versioned contracts and an immutable composition of their results. A dead man's switch is one possible composition; a contract attestation is a signed claim, not proof that a real-world fact is true.

This is an executable research laboratory, not a production disclosure service. All content and recipients are synthetic. No HTTP server, public publishing, email, SMS or push integration is provided.

## Run

Install Docker with Compose, start its daemon, then from this directory:

```sh
./scripts/experiment.sh
```

The script builds the environment, runs the complete suite and prints the demo's audit history. Actual output is written to `doc/results/latest-tests.txt` and `doc/results/latest-demo.txt`. Test and demo containers have no network access. Build requires access to Python images and packages. Nothing installs on the host.

Individual commands:

```sh
docker compose build
docker compose run --rm experiment
docker compose run --rm demo
```

The demo creates an AES-256-GCM encrypted Capsule, arms a signed 2-of-3 policy, accepts A and B's positive attestations and C's negative attestation, evaluates the committed policy, waits five simulated seconds, authorises release, decrypts to a simulated durable inbox and exports its full audit history. Each run uses an isolated temporary directory and deletes it on exit. The automated experiments also demonstrate repeated presence without release, missed challenges and authenticated disarm.

## Boundaries

- `Protocol/` and [PROTOCOL.md](PROTOCOL.md): implementation-independent semantics and wire examples.
- `Engine/`: reference engine, signed messages, SQLite acceptance authority, encrypted storage, two policy evaluators.
- `App/demo.py`: thin CLI; the engine runs without it.
- `tests/`: executable adversarial experiments.
- `doc/`: decisions, research, future work and preserved actual output.

The engine API accepts a storage directory; fresh engine objects reopen the same durable state. SQLite serialises competing writers with `BEGIN IMMEDIATE`; workers do not decide from local wall clocks. Controlled time is persisted in the same database and advances only through the trusted test adapter. The reference evaluator and independent interpreter separately implement contract semantics, expression reduction and grace eligibility. They share the canonical wire specification and trust the exported acceptance authority.

The operator holds the decryption capability. Encryption, signatures and audit hashes do **not** stop a malicious operator from decrypting early or rewriting the authority. No zero-knowledge, distributed consensus or administrator-resistant custody is claimed.

See [PROTOCOL.md](PROTOCOL.md), [THREAT_MODEL.md](THREAT_MODEL.md), [CONFORMANCE.md](CONFORMANCE.md), [EXPERIMENTS.md](EXPERIMENTS.md), [CUSTODY_RESEARCH.md](CUSTODY_RESEARCH.md) and [Generation 0.2](doc/GENERATION_0_2.md).

# Otherwise 0.7 — The Missing Piece

A research harness now requires cryptographically indispensable components from **both** custody and an independent authorisation domain. Entire one-domain compromise is insufficient under secure independent setup; combined-domain collusion, compromised provisioning and shared administration still win. The prototype also excludes malformed replies independently and uses parallel witness collection.

Read the [0.7 executive examination](doc/generation07/EXECUTIVE-0.7.md), [research and threat model](doc/generation07/README.md), and [attack lab/runbook](doc/generation07/ATTACK-LAB-0.7.md). The inherited early-finalisation cancellation limit remains an executable counterexample. This is unreviewed cryptographic research using synthetic data, not production security.

---

# Otherwise 0.6 — The Honest Custodian

A synthetic threshold-decryption research harness now sits alongside the preserved 0.1–0.5 implementations. Honest release avoids reconstructing the reusable custody private scalar; a malicious 2-of-3 threshold still decrypts early. No cryptographic policy-enforcement claim is made.

Read the [0.6 research and results](doc/generation06/README.md), [trust boundaries](doc/generation06/SECURITY.md) and [Docker runbook](doc/generation06/RUNBOOK.md). Run `./scripts/experiment06.sh` for the new experiments and `python3 scripts/regression06.py` for all earlier generations. Synthetic content and simulated disclosure only.

---

# OTHERWISE 0.5 — The Untrusted Operator

An independently installed creator client now owns key generation, signing, encryption and an encrypted portable recovery capability. The separate Laravel consumer receives only public protocol material. Its page is explicitly untrusted; no operator-delivered browser code is claimed safe for private-key handling.

```sh
./scripts/lab05.sh up -d --build aw1 aw2 aw3 aw4 ak1 ak2 ak3 hostile product-db laravel
```

Open **http://localhost:8050** for the public operator view. Use the [trusted-client runbook](doc/generation05/RUNBOOK.md) for local create/arm/check-in/fresh status/disarm/recovery. Independently authenticate the client build and provider configuration before relying on this model.

```sh
./scripts/experiment05.sh
```

The hostile SaaS tries forgery, false success, substitution, censorship, stale responses and malicious code delivery. Tests retain successful attacks: executing untrusted client code, using previously exposed/stolen keys, censorship past deadline, and colluding static-share custodians. The integrated driver stops Laravel/backend/database, restores an older device backup, recovers newer presence, rotates a Capsule and repeats operation through a witness restart.

- [Security and client-distribution roots](doc/generation05/SECURITY.md)
- [Observed attack classifications and evidence](doc/generation05/RESULTS.md)
- [Recovery, cloning and explicit retirement](doc/generation05/RECOVERY.md)
- [Custody alternatives and unresolved trust](doc/generation05/CUSTODY.md)
- [Separation and deployment boundaries](doc/generation05/ARCHITECTURE.md)

Synthetic content and simulated disclosure only. This is not production-secure, a trustless-custody system, a censorship guarantee or a secure automatic client-update scheme. PorterNet remains unimplemented and unnecessary. Earlier implementations and counterexamples are preserved below and in their original directories.

---

# OTHERWISE 0.4 — The Available Witness

An independently operable conditional-custody protocol, with a local Laravel consumer prototype. All Capsules contain synthetic content and all delivery is simulated.

```sh
./scripts/lab04.sh up -d --build aw1 aw2 aw3 aw4 ak1 ak2 ak3 protocol-adapter product-db laravel
```

Open **http://localhost:8040**. Create, save the private recovery kit, arm, check in, inspect evidence, then disarm early—or miss the last window and simulate release. The default demo uses real wall/monotonic clocks. It is a laboratory, not production custody.

The new static four-witness profile uses three signed observations and three signed closures, with durable locks, direct receipt retention and authenticated same-identity repair. Python and an independent Node evaluator verify portable certificates. The consumer database is disposable: the owner CLI operates directly against witnesses/custodians using an independently retained kit. Neither the protocol image nor CLI contains Laravel or PorterNet. Two conventional transport adapters and explicit custody capability checks have executable conformance tests.

```sh
./scripts/experiment04.sh
```

This isolated Docker experiment runs adversarial tests, actual HTTPS substitution, Laravel HTTP/CSRF, a network partition, witness process recovery, and **stops Laravel, PostgreSQL and the adapter** before exercising independent recovery/check-in/disarm/release. Stop the demo's Laravel container first if it occupies port 8040. Results are retained under [doc/results04](doc/results04).

- [Runbook and standalone owner CLI](doc/generation04/RUNBOOK.md)
- [Protocol, timing assumptions and recovery boundaries](doc/generation04/PROTOCOL.md)
- [Architecture and custody/transport interfaces](doc/generation04/ARCHITECTURE.md)
- [Results and limitations](doc/generation04/RESULTS.md)
- [HTTPS versus correspondence: design only](doc/generation04/UNREACHABLE_AUTHORITY.md)

A malicious static-share custody quorum can still decrypt early. Four containers on one host do not establish independent administrative or clock trust. The prototype passes owner keys through a local trusted adapter; use synthetic data only. Committee-wide restart, identity replacement and production key recovery are outside this profile.

---

# Otherwise — Generation 0.3: The Retained Witness

Conditional custody governed by independently evidenced obligations. One human can use one absence contract; advanced Council policies compose several independently signed contracts. Technical witnesses and custodians do not become additional human trustees.

Generation 0.3 asks who can remember a check-in when the application wants to erase it. It adds three independently stored witness services, durable signed receipts, verifiable acknowledgment certificates, challenge finalisation and compact custody verification. Generations 0.1 and 0.2 remain runnable, including their successful attacks.

## Run everything

Requirements: Docker with Compose, a POSIX shell and `openssl` for disposable provisioning capabilities. All engine, witness, custody, verifier and benchmark software runs inside Docker.

```sh
./scripts/experiment03.sh
```

This reruns the original 20 tests, the 21 Generation 0.2 tests and its portable verifier, then starts a uniquely named disposable six-service witness/custody cluster, runs 13 new tests, checks 48 fixed/reordered witness proof objects across Python/JavaScript, and measures practical costs. Only its own containers/volumes are removed. Raw output is retained under `doc/results03/`; earlier output directories remain available.

Earlier generations still run independently:

```sh
./scripts/experiment.sh
./scripts/experiment02.sh
```

No real email, SMS, publishing, secrets or third-party data is used. Containers have no published ports. Separate volumes and capabilities establish a laboratory boundary, not independent administrative domains; host/Docker administrators can defeat it.

## The finding

Naive 2-of-3 presence and 2-of-3 absence can conflict when their intersection signer is malicious. That attack is reproduced and preserved.

The implemented profile accepts presence with **two receipts** but requires **all three finalisations** to establish absence. With at most one faulty witness, an honest presence holder lies in every attempted release quorum and refuses ABSENT. One silent witness therefore permits check-in through the other two, but blocks release. This is a safety/availability choice, not consensus.

`CheckInClient.check_in` returns a verified, durably cached acknowledgment certificate suitable for a future API/mobile boundary. Custodians verify complete slot-bound proof objects independently in Python and JavaScript rather than trusting app-selected history. Solo covers repeated/late/missed check-ins, grace, custody recovery and disarm; Council uses the same mechanism for signed boolean claims and threshold policy.

All 54 test methods pass. The new corpus has 22 fixed and 26 reordered proof objects with no language disagreement. Local measured median durable acknowledgment latency was about 10 ms; see the report for sample sizes, storage/write costs, timeout limitations and availability trade-offs.

## Repository map

- `Engine/`, `Bounded/`, `tests/`, `tests02/`: preserved previous-generation machinery and attacks.
- `Retained/`: generic witness state, certificate verification, creator API, independent-storage service and benchmark.
- `Verifier/retained.mjs`: independent JavaScript compact-proof verifier.
- `Protocol/vectors/generation03.json`: fixed signed witness fixtures, including successful attacks.
- `tests03/`: counterexample and mandatory adversarial experiments A–L.
- `doc/generation03/`: research, observations, costs, architecture, founding brief and proposed 0.4.

Read [actual results](doc/generation03/RESULTS.md), [the eight research answers](doc/generation03/RESEARCH.md), [measurements](doc/generation03/PERFORMANCE.md), [protocol](PROTOCOL.md), [threat model](THREAT_MODEL.md) and [conformance](CONFORMANCE.md).

A malicious custody quorum can still reconstruct outside policy. Too many compromised/forgetful witnesses can still conceal presence. Clocks and administrative independence remain assumptions. We have tested how to make accepted presence non-erasable under a stated fault bound; we have not proved anyone alive or made disclosure unconditionally safe.

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

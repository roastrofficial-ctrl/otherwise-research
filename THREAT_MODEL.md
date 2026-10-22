# Generation 0.1 threat model

## Protected assets and trusted components

Assets are payload confidentiality, scoped evidence, committed policy, correct release permission, terminal disarm and an explainable decision history. The trusted computing base is the engine code, Python/cryptography libraries, durable SQLite/filesystem, acceptance authority and controlled clock adapter. Owner and evidence private keys are held by test callers, not persisted by the engine. A compromised owner can arm, disarm, revoke and acknowledge clock recovery for its own Capsule.

SQLite's committed writer order is the Generation 0.1 ordering authority. No quorum, geographically replicated log, network front end, authentication session layer or Byzantine consensus is implemented. Audit chain head/count anchors are inside the authority's database.

## Adversaries and outcomes

| Adversary/failure | Handling | Remaining boundary |
| --- | --- | --- |
| Forged submission, wrong authority, cross-contract or cross-Capsule replay | Whole-message Ed25519 signature plus identity/commitment/schema/window checks | Stolen authority key can make scoped claims |
| Same accepted submission ID, changed content | Reject collision | An authority can issue contradictory claims with new IDs; contract becomes unsatisfied while both are active |
| Duplicate jobs, lost receipts | Recover accepted receipt or immutable decision; durable inbox key prevents duplicate simulated insertion | Real delivery provider may have no idempotency support |
| Scheduler failure | Grace starts at observation; declared outage latches uncertainty; per-owner recovery starts fresh grace | Hidden downtime cannot be inferred from a frozen controlled clock |
| Clock rollback or large jump | Reject rollback; latch unhealthy on excessive advance | Gradual drift, freezes or dishonest clock inputs are not detected |
| Simple deletion/reordering/alteration of audit data | Validate sequence, hash chain, head/count and policy commitment under lock | Rewriting all database anchors or restoring an entire old database snapshot defeats this check |
| Payload tampering | AES-GCM authentication fails before simulated insertion | Can still deny delivery; authorization checks references, not ciphertext availability |
| Malicious custodian/operator | Outside prevention guarantee | Can read keys, decrypt early, bypass engine, fake clock or replace history |
| Unreachable creator/notification failure | Notification transport result does not satisfy any contract | If the creator cannot reach the acceptance authority, policy may still permit release after grace |
| Disk failure or SQLITE_BUSY | Transaction errors propagate; no new permission from partial database operations | Liveness and external storage durability are not guaranteed |

## Development custody

A random AES-256-GCM key and 96-bit nonce encrypt each synthetic payload, with Capsule ID and policy commitment as associated data. Ciphertext is in `payloads/`, keys in `keys/` with restrictive file permissions. The engine operates on random payload references. Creation flushes files/directories before committing their reference; a failed creation may leave orphan encrypted files/keys but no armed Capsule. Production garbage collection, backup policy and secure erasure remain unimplemented.

Separate directories are an operational separation, not a security boundary against the same operator. Automatic delivery loads the server-held key. An administrator, code-execution attacker or reader of both locations has early decryption capability. A simulated inbox intentionally contains plaintext after delivery; histories and policy results contain references and evidence, not payload plaintext. Even after arming, the operator can bypass the engine. No client-side encryption or zero-knowledge claim is made.

## Knowledge, availability and safety

Presence is an authenticated response accepted for one obligation, not proof of health. Attestation authenticates a speaker and statement, not objective truth. Absence means no authoritative timely response was observed, not death, incapacity or consent at release time.

Within its stated authority model the engine fails closed on ambiguous history, clock uncertainty, missing satisfaction or disarm. This sacrifices prompt release during uncertainty. It does not eliminate the possibility that a healthy but disconnected creator misses an obligation; that experiment explicitly results in policy authorisation. A policy composed only of absence contracts authorises based on operational silence by design. Additional independent positive obligations can reduce dependence on silence, but their real-world reliability remains outside cryptographic verification.

The tests are finite observations, not a proof of correctness for all schedules or a security audit. They simulate acknowledgement loss, declared outages and adapter crash points. They do not kill the OS during disk writes, emulate network partitions between replicas, or model hardware clock failures. This laboratory should not hold real secrets pending those engineering and governance questions.

---

# Generation 0.2 feasibility boundary

## What changed

The 0.1 trusted-operator custody model remains available for old experiments. The opt-in 0.2 profile moves key generation to a trusted creator, gives only ciphertext/public metadata to the app, puts individual shares in separate services, and requires independently witnessed history before honest custodians participate. The operator may alter every app file, database row, schedule, worker, delivery adapter and app setting. That authority does not include custody/witness configuration, their volumes, bootstrap capabilities, signing keys, the trusted creator or the recipient.

## Explicit trust assumptions

1. Creator code/provisioning and service identity discovery are trusted. A malicious operator distributing a compromised client could capture plaintext or the key before custody; that threat is not solved. The creator/orchestrator necessarily has all shares during provisioning, and Python memory erasure is not established.
2. The witness is independent of the application operator, correctly retains history, and provides a defensible observation clock. The application cannot replace its pinned identity at the custodians. One witness is a deliberate single trust/availability dependency, not a consensus system.
3. Fewer than two custodians collude before release. Their storage, code and configuration are outside app control. AES-GCM, Ed25519, SHA-256 and the library's Shamir construction have their usual security assumptions; the integrated system has not received a cryptographic audit.
4. The trusted test runner is a creator/fault-injection administrator. Its random bootstrap capabilities can provision all services and model compromise. It is outside the operator threat boundary. Deliberate `/test-*` administrative routes are laboratory instrumentation, not production features.
5. Container/host/Docker-daemon control is not app control in the experiment. A host administrator or Docker administrator can inspect all volumes, environments and processes and defeat the separation. Local containers demonstrate distinct capabilities/mounts, not independent organisations or resistance to host compromise.
6. Private Docker-network HTTP transport is assumed isolated against peer eavesdropping/impersonation. No mTLS deployment or production authentication boundary was built. Receipts are signed and nonce-bound, but enrollment shares and post-release shares need protected transport in a real deployment.

The runner has no custody volumes mounted; each custodian has only its own state volume. The adversarial operator has only its app volume, no bootstrap variables, no witness/custody state mount and no Docker socket. Containers drop capabilities, use a read-only root and publish no ports. These are concrete lab boundaries, not a guarantee about every Docker vulnerability.

## Observed attacks and limits

| Compromise/failure | Outcome in this model |
| --- | --- |
| App/operator only, no permission | Concrete key guesses fail; every honest custodian refuses; no full key exists in app storage |
| Operator forges a successful decision | Witness/lifecycle validators reject; custodians fetch their own witnessed evidence |
| Operator rolls back a complete app database | Independent retained prefix rejects the fork, even if the new local history is semantically self-consistent |
| Replay against another Capsule/manifest/epoch/payload | Request or recipient context verification rejects; GCM binds the ciphertext scope |
| One missing custodian | Other two recover after valid authorisation; one share or duplicate indices do not satisfy recovery |
| Two compromised custodians | They export their shares and decrypt before authorisation: intentionally successful attack |
| Witness unavailable or clock uncertain | No new share; availability is sacrificed |
| Operator and witness compromised, custodians have not seen original presence | Fabricated internally valid absence history can obtain shares: intentionally successful attack |
| Compromised witness contradicts a prefix already retained by two custodians | Those services refuse; the uninformed third cannot supply a quorum alone |
| App becomes unreachable from the creator but still heartbeats to witness | Not distinguishable from silence; policy may still authorise after grace |
| Witness/custodian history and keys all rolled back or replaced | No surviving independent anchor is guaranteed; not prevented |
| Shares already issued | Later policy/disarm/clock changes cannot claw them back |

Policy thresholds do not automatically enforce cryptographic thresholds. A 2-of-3 contract expression authenticates independently scoped obligations; a 2-of-3 key quorum is a separate trust arrangement whose honest services voluntarily enforce the verified decision. Static shares do not make an arbitrary Boolean policy cryptographically unavoidable.

The scope of demonstrated independence is therefore precise: **application compromise alone does not provide the laboratory's decryption key under trusted provisioning, witness and non-colluding custody assumptions**. We have not shown unconditional non-disclosure, admin-resistant single-host custody, independent organisational governance, correct real-world attestations, globally correct clocks or production readiness.

---

# Generation 0.3 retained-witness assumptions

The new profile treats operator storage as erasable and does not trust its chosen history. At most one of three independently administered witness identities may equivocate, forget durable state, disclose its signing key or violate its observation-clock rules. At least two must retain their per-slot fences. Honest witnesses commit observations before returning signed receipts, refuse conflicting first observations, and never reverse a closed slot. The membership/thresholds and custody operation are owner-signed and static.

Presence requires two receipts; release requires all three finalisations for every committed slot. Their intersection includes at least one honest state-retaining witness under `f<=1`. This prevents accepted presence and an ABSENT release certificate for the same slot, even if the application erases every local receipt. A single honest minority observation can block release without a complete acceptance certificate: deliberate conservative liveness loss.

The unsafe 2/3-versus-2/3 counterexample is preserved with genuine signatures. One malicious intersection witness signs both. The safe profile rejects that configuration. An additional executable boundary shows that two malicious witnesses can defeat the revised thresholds; informed custodians retain a separate veto, but uninformed verifiers cannot infer a violated fault budget from signatures alone.

The new witness and custody roles have distinct volumes, private random identities and separate administrative bootstrap capabilities. The trusted fixture runner has these capabilities to provision and inject individual faults. It is outside the operator boundary. All containers still share one host, daemon, image supply chain and administrator; this does not establish real administrative independence. Private-network HTTP and trusted creator code remain laboratory assumptions. No real secret, recipient or public disclosure is introduced.

A complete local database rollback is tested, with retained peer receipts exposing it. If a fault hides the audit request or peers are unreachable, detection may not happen immediately. Safety still depends on the remaining honest receipt holder refusing absence; more than one history-losing/signing fault is outside the bound. Rollback of every anchor, malicious witness-majority cooperation, provisioning-client compromise and custody quorum collusion are not solved.

The suite's clocks are explicit controlled integer sources; inherited 0.2 actual-clock/fault tests are rerun. Clock validity is an assumption for timing claims, not proof of UTC. A real-mode restart with uncertain clock cannot mint new finalisations. Observation outages and a creator's inability to reach witnesses can still leave no accepted certificate; neither outcome proves death. Finite closed slots, first-observation fencing and unanimous finalisation restrict this profile; dynamic evidence amendment, witness rotation, automatic quarantine repair and production clock recovery require future specifications.

Availability is deliberately asymmetric. Two available honest witnesses can retain a check-in while a third is offline. No new release certificate can form while any required witness is silent, maliciously withholding or quarantined. A fast HTTP refusal in the measured workload is not a network-timeout guarantee. The client currently contacts witnesses sequentially and may wait for its configured request timeout.


## Generation 0.4 — scoped fault tolerance and separability

The four-witness certificate model assumes at most one faulty witness for a static epoch, healthy bounded clocks and preserved/repaired durable locks. It does not protect against a malicious custody quorum, compromised owner kit/SaaS origin, common Docker-host compromise, arbitrary UTC failure or cumulative theft of old signer keys. Three-member partitions can progress; two-member partitions cannot. Restarted witnesses require authenticated recovery. See [the full protocol boundaries](doc/generation04/PROTOCOL.md) and [the consumer trust boundary](doc/generation04/ARCHITECTURE.md).


## Generation 0.5 — malicious SaaS is an explicit adversary

Laravel, its backend/database/deployment and every SaaS response may be adversarial. Newly generated owner secrets remain on an independently trusted creator device. This does not protect against malicious client installation, stolen unlocked devices, already exposed keys, arbitrary censorship or a malicious custody quorum. [Attack results](doc/generation05/RESULTS.md) classify prevented, detectable, recoverable and successful cases separately.

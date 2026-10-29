# Guarantee matrix and remaining attacks

Synthetic content and local simulated disclosure only. The consensus and cryptographic integration are research code, not externally audited or production-certified.

| Property / attacker | Result | Evidence / assumptions |
|---|---|---|
| Historical PRESENT window closes while overall predicate false | New terminal disarm succeeds; old0.7 V still fails unchanged | A and historical reproduction. Per-window FINAL cannot cast a v8 terminal vote |
| No conflicting irreversible DISARM/RELEASE | Intended under f<=1 durable honest protocol; bounded model finds no counterexample | Prepare/commit/view-change fences; D/E/F/O, public vectors, independent bounded exploration. Not a proof of all code/executions |
| Honest capabilities before RELEASE commitment | Policy proof alone, legacy route, disarm certificate or forged commitment rejected | V; each honest holder verifies scope, finality, policy evidence and exact contribution context |
| Custody quorum fully compromised | Still lacks independent authority component under secure independent provisioning | K portion of K/L; mathematical XOR requirement plus threshold-DH/AEAD assumptions; finite failed decrypts are not exhaustive proof |
| Combined cryptographic thresholds / shared host admin | Early raw decryption still succeeds without a terminal certificate | L, retained0.7 C/K and prior generations; consensus cannot constrain a coalition already owning all secrets |
| Related keys / malicious dealer / reused entropy | Known related scalars still collapse independence; exact cross-domain reuse and wrong commitments rejected | Q and historical U. Distinct public keys cannot prove independent unknown secrets. Trusted creator/dealer and RNG remain assumptions |
| Delayed genuinely accepted presence | Timely authoritative receipts remain valid when copied late and block the conflicting predicate | G; locally created/never accepted presence is not a receipt quorum |
| SaaS censorship, fake cancellation or stale status | Cannot forge valid terminal proof; fresh challenge and direct path detect/recover where reachable | H/S/T. Censorship is not prevented; a suppressed request may lose the race. No fake success without a verified certificate |
| Byzantine malformed/duplicated/incorrectly scoped minority | Individual source validation excludes it; compatible remaining quorum progresses in tests | T and preserved bounded collection. Peer-recovery availability has stricter3-other-peers requirement |
| Process crashes at durable vote/decision boundary | Pre-write no emitted committed vote; post-write vote persists; restart quarantines, peer recovery preserves commitments | I/R/O, actual process exits plus deterministic SQLite-backed schedules; honest fsync/storage assumed |
| Rollback of one signer | Quarantine and fresh authenticated state transfer prevent uncertain old-view re-voting in tests | O/R; restoring every key/anchor or silently corrupting a running honest process exceeds the stated model |
| Creator disappears | Public worker can evaluate, commit and collect; recipient verifies offline | M; no creator/recipient secret sent to worker, no SaaS, both domain thresholds and correct evidence required |
| Creator returns after disclosure | Can sign a request but cannot retract a committed entitlement or erase recovered plaintext | N/C. A missing acknowledgement does not imply the creator still controls an unresolved race |
| Prepared RELEASE but no certificate yet visible to creator | A new-view decision may be constrained to RELEASE; cancellation success is not guaranteed | F retained as an uncertainty boundary, not advertised as Model B/C cancellation-until-delivery |
| Witness or authority membership replacement | Unsafe hot swap refused, old epochs/registry scopes cannot authorise new instances | J. Safe reconfiguration/succession remains unfinished, not supplied by a hidden administrator |

## Where the trust lies

The content-key components and existing threshold group algebra provide missing-capability protection under primitive and secure-creation assumptions. Each honest holder's **software** enforces finality. Window observations, clock bounds, acceptance/finality and terminal voting rely on honest participants following the protocol. Secret independence, separate administrators/backups/update paths, durable storage, authenticated creator/recipient installation and long-term operation are deployment assumptions.

No key reconstruction event is needed for a confidentiality failure. A combined coalition can compute equivalent partial operations and decrypt early. A signature authenticates an assertion; DLEQ proves arithmetic, not legitimate policy or objective real-world truth. Finality signs an ordered entitlement; it does not prove that ciphertext reached a recipient or that anyone read the message.

There is one effective host-admin compromise domain in this local Docker deployment. Each holder has only its own private state/TLS mounts, but the host/runner can inspect all of them. Deliberate seed/log extraction, rollback and process-crash routes require the private laboratory capability and LAB_FAULTS. They must not be exposed in a pilot. No real data, mail/SMS destinations or PorterNet integration is introduced.

## Safety versus liveness

With fixed epoch, at most one Byzantine key over that epoch, unforgeable signatures, correct guards and intact honest promises/votes, the intended protocol prevents conflicting terminal values despite partitions/delay. It does not terminate under arbitrary asynchrony: FLP and practical pacemaker/gossip requirements matter. The implemented driver has finite attempts and views, local timeout/resource bounds and no production gossip daemon. Liveness claims are conditional on enough compatible honest peers, eventual timely delivery, a fair/stable driver and an honest leader before view exhaustion.

Eventual disarm is conditional on remaining admissible in the competing operation history; it is not a guarantee that every request submitted before a visible certificate overrides a prepared RELEASE. A successful DISARM certificate is definitive; a pending request is not. Two incompatible partitions refuse to decide rather than invent global order. Authorised independent recovery after healing carries prepared/terminal facts forward rather than choosing by timestamps.

## Formal/experimental scope and minimal pilot blockers

The independent finite model explores two values, two views, four replicas and every Byzantine position; it abstracts signatures, valid proposals and durable fences. It excludes arbitrary views, implementation refinement, clocks/FS errors, membership, global rollback and full liveness. Its deliberately broken view-change variant produces a conflicting-decision trace. Actual signed-message schedules use the implementation and SQLite; live Docker tests exercise crashes/TLS/creatorless delivery. Passing those tests is not a complete distributed-consensus proof.

Before a credible real-world pilot, the smallest essential work is: independently reviewed consensus integration with real pacemaking/gossip, rate/state bounds and recovery; cryptographic review and defensible independent provisioning/administration; pre-authorised membership/key/recipient succession and tested disaster restore; hardened independently distributed creator/recipient clients; and measured multi-host clock/network/durability operations with accurate product uncertainty. None is replaced by a larger committee or a new version number.

Healthy replicas reject unnecessary recovery challenges; state transfer is allowed only after quarantine or explicit evidence-repair state. A normal caller cannot use the recovery endpoint to force a healthy signer into a higher view. The failure/recovery cases test this guard alongside creator-independent repair.

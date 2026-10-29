# The Last Word — executive examination

Attack V is corrected in a new versioned profile: closing an earlier check-in window no longer prevents a valid terminal disarm while the complete release predicate is false. Historical U/V and combined-domain early decryption still reproduce in their original implementations.

**Q1. When does the creator definitively lose disarm authority?** Under selected Model A, when a valid RELEASE terminal certificate exists: the declared prepared/commit quorums have durably voted that value. Authorisation and commitment coincide; window closure and a policy proof do not. An in-flight prepared release may already constrain a competing request, so “I sent disarm before seeing a certificate” is not a cancellation guarantee. Only a valid DISARM certificate proves cancellation success.

**Q2. Can independent honest participants verify that moment?** They can verify the immutable registry/epoch, complete policy/ARM evidence and distinct prepared/commit signatures. A portable certificate is independently checkable; notification time is not the ordering point. This relies on the declared fault/honesty and durable-state assumptions, not omniscience of every machine.

**Q3. Can both outcomes become final?** The intended single-instance protocol prevents that for f<=1 with honest no-double-vote, durable promises and safe highest-prepared view changes. Bounded exploration and adversarial schedules support it; they are not a complete implementation proof. More stolen keys, rollback beyond recovery assumptions or a protocol defect can invalidate the claim.

**Q4. What if the network partitions at the worst instant?** Insufficient quorums refuse to decide. Prepared knowledge survives and is carried into later views after healing. Permanent2/2 separation cannot promise progress; no clock or SaaS timeout breaks the tie.

**Q5. Can a malicious SaaS fake cancellation?** It can show a lie and censor a valid request. The independent client rejects unsupported success/stale status and has a direct route. Censorship itself is not prevented, and a suppressed request can lose the race before any valid cancellation acknowledgement.

**Q6. Can the creator permanently disappear without making release impossible?** Yes in the tested healthy-quorum scenario: a public child worker with no owner/recipient secret obtains missed-window evidence, commits RELEASE and exports recipient-bound material. Once committed, retained certificates allow disclosure even with all witness routes unavailable. Uncommitted globally quarantined/lost committees remain a survival failure without legitimate succession/recovery.

**Q7. Can the recipient establish authorisation independently?** The recipient verifies the portable package offline against its separately authenticated expected registry/ciphertext and recipient secret, including policy, finality, both cryptographic thresholds, proofs and plaintext commitment. The tested recipient container has networking disabled and no owner/fault/provider secrets. It cannot prove objective human death or absence of infrastructure compromise.

**Q8. What if committee members disappear permanently?** One missing witness leaves3; one missing holder in either domain leaves2. Further losses can block useful release. Membership is not silently shrunk/replaced: safe old/new quorum continuity and key/recipient succession need pre-authorisation or a future reviewed protocol. A committed certificate already retained elsewhere remains usable.

**Q9. Did a new component gain unilateral rewrite/release power?** No normal protocol actor gets it. Leaders rotate and need independently verified quorum proofs; recovery requires three other signed fresh checkpoints; key holders require a terminal certificate. A shared Docker host/backup/update administrator still collapses practical independence, and the trusted creator/dealer temporarily knows setup secrets.

**Q10. What can a malicious combined cryptographic quorum still do?** Compute both components and decrypt early, without a finality certificate or reusable private-scalar reconstruction. Attack U's related provisioning can make one nominal domain sufficient. The finality redesign does not repair either assumption failure.

**Q11. What is demonstrated, modelled or assumed?** Live Docker tests demonstrate corrected V, durable vote/decision crashes and recovery, creatorless worker operation, offline recipient verification, scoped Byzantine collection and remaining attacks. Deterministic SQLite-backed schedules exercise ordering. The separate finite model checks two views/two values with a retained unsafe variant. Arbitrary executions, cryptographic security, honest/durable clocks/storage, cumulative fault bounds, full liveness and independent administration remain assumptions or review work.

**Q12. What smallest problems block a credible pilot?** Reviewed consensus/pacemaker/gossip and bounded recovery; defensible independent key generation/administration and crypto review; pre-authorised membership/recipient/algorithm succession and restore drills; hardened independently distributed clients; and real multi-host operational evidence with correct uncertainty/cancellation UX. Fault-injection APIs and a single-host laboratory are not a production deployment.

Measured costs and exact artifacts are in BENCHMARKS-0.8.md and FINALITY-LAB-0.8.md. No real Capsule, external disclosure, Laravel dependency or PorterNet integration was introduced.

Validation: **150 test methods passed** (131 preserved across0.1–0.7 and19 new0.8 methods). The independent checkers agree on21 terminal vectors; the finite model explored58,880 transitions with no conflicting commits under its assumptions and retained a fork for the deliberately unsafe variant. The separate network-disabled recipient verified an actual release package. Exact limits and observations accompany every artifact.

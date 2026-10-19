# OTHERWISE
## Generation 0.3 — The Retained Witness

**Independent observation, durable presence and the limits of proving absence.**

Professor,

Welcome back to Otherwise.

Generation 0.1 established deterministic conditional release from authoritative evidence.

Generation 0.2 separated acceptance, decision and custody authority. It introduced independent custodians, portable conformance, bounded clock uncertainty and adversarial custody experiments.

Most importantly, it produced two successful attacks:

1. A malicious quorum of custodians could reconstruct the decryption secret without policy authorisation.
2. A compromised operator and acceptance witness could manufacture an absence history when the custodians had not previously observed the genuine presence evidence.

The second result is our starting point.

When custodians had already retained genuine presence evidence, the forged absence history was rejected.

This suggests a new research direction:

> Can independent observers retain enough evidence of someone's presence that a compromised authority cannot subsequently erase it and manufacture an authorised release?

We are calling this generation **The Retained Witness**.

Build it as a continuation of the existing repository. Preserve all previous conformance tests, successful attacks and documented limitations.

Do not redesign the entire protocol merely to accommodate the new mechanism.

---

# 1. The central distinction

We must separate three concepts:

**Submission:** The creator attempts to check in.

**Observation:** An independent witness durably records valid presence evidence.

**Acceptance:** The protocol establishes that the evidence satisfies a particular challenge under the committed policy.

These are not interchangeable.

A user pressing a button is not proof that the service received their check-in.

A service receiving a request is not proof that it durably retained the evidence.

A witness retaining evidence is not necessarily proof that the check-in satisfied the policy's acceptance rules.

Generation 0.3 must define the exact boundaries between these events.

Our principal invariant:

**Once valid presence evidence has been durably accepted under the committed rules, an attacker controlling fewer than the specified number of independent witnesses must not be able to manufacture an absence-based release by deleting or rewriting that evidence.**

State the trust and availability assumptions required for this guarantee.

---

# 2. Preserve the Solo Witness

This is non-negotiable.

Otherwise remains, first and foremost, a simple dead man's switch for ordinary people.

One human creator.

One Capsule.

One check-in contract.

One release destination.

No additional human approval required.

The system may employ multiple independent technical witnesses and custodians, but the creator should not need to understand or operate them.

The user experience remains:

"Still here?"

"Yes."

The machinery underneath must establish what that answer means.

Retain the multi-party Council scenario as an equally important advanced conformance case.

Both must run through the same protocol.

---

# 3. Independent presence witnesses

Introduce a small network of independent witness processes.

Start with three.

Each witness should possess its own identity and signing key, durable local storage, and independent observation history.

A witness must be able to:

- Validate a check-in against a committed challenge and policy.
- Record the evidence durably.
- Issue a signed receipt identifying exactly what it retained.
- Return the same receipt on idempotent replay.
- Recover its history after restart.
- Detect conflicting or contradictory histories within its own observed lineage.
- Reject evidence belonging to another Capsule, challenge, policy version or creator.

Do not treat three containers controlled by the same operator as genuinely independent administrative domains.

Docker isolation is sufficient for the laboratory, but document the limitation explicitly.

The important question is what survives when individual witnesses become malicious, unavailable or inconsistent.

---

# 4. The acknowledgement problem

A creator submits a check-in.

Witness A retains it.

Witness B retains it.

Witness C is offline.

The application crashes before acknowledging success.

Did the check-in count?

We need an unambiguous answer.

Define a durable acknowledgement certificate containing sufficient witness receipts to satisfy the committed acceptance rule.

For the first experiment, consider a two-of-three witness threshold.

But do not assume that threshold is automatically correct.

Investigate the relationship between:

- The number of witnesses.
- The number required to accept presence.
- The number required to authorise absence-based release.
- The number that may be malicious.
- The number that may be unavailable.

Explicitly distinguish a threshold of retained observations from a consensus protocol.

A collection of signed receipts does not automatically establish a globally agreed event order.

Determine which guarantees require ordering, intersection or additional coordination.

If a safe design requires stronger coordination, explain precisely why.

---

# 5. Absence as a bounded claim

A witness can attest:

"I observed and retained valid presence evidence."

It cannot simply attest:

"This person was absent everywhere."

Absence-based release therefore requires a carefully bounded observation model.

Define what constitutes sufficient evidence that no qualifying presence was accepted within a challenge window.

Investigate whether this can be established using:

- Signed witness observations.
- Explicitly closed acceptance windows.
- Independently retained history commitments.
- Witness quorum certificates.
- Challenge-specific finalisation records.

The release protocol must not treat a lack of communication from a witness as a vote for absence.

If insufficient evidence exists to establish the release condition, the Capsule must remain unreleased.

Document how this affects liveness.

**Critical requirement:** An accepted presence certificate must conflict with any purported absence certificate for the same challenge. Under the declared fault model, the protocol must prevent both from being validly produced.

If this cannot be guaranteed using the proposed witness arrangement, preserve the counterexample and revise the model.

---

# 6. The intersection experiment

This is the mathematical heart of Generation 0.3.

Consider three witnesses: A, B and C.

Presence requires two witness receipts.

Absence release also requires two witness attestations.

A and B retain presence.

B and C later attest absence.

These quorums intersect at B.

If B is malicious, it can sign both claims.

Therefore, ordinary majority intersection is not necessarily sufficient to prevent contradictory certificates under Byzantine behaviour.

Investigate this explicitly.

Determine the quorum and fault assumptions needed to prevent conflicting presence and absence certificates.

Explore whether additional constraints are required, such as:

- Witnesses refusing to sign conflicting facts.
- Durable per-challenge finalisation.
- Stronger quorum intersection.
- Shared authoritative ordering.
- An explicit consensus protocol.

Do not introduce consensus automatically.

First produce the counterexample.

Then establish the minimum mechanism that eliminates it under a clearly defined threat model.

We want evidence, not distributed-systems theatre.

---

# 7. Custodians must verify retained presence

Generation 0.2 established that independent custodians could reject a forged history if they had previously retained genuine presence evidence.

Generalise this principle.

A custodian should not trust an operator-provided release decision merely because it is correctly signed.

It must verify the decision against the committed policy and sufficient independently witnessed evidence.

Investigate whether custodians can verify a compact release certificate without downloading the entire historical record.

Bind every certificate to:

- Capsule identity.
- Policy version or digest.
- Challenge identity.
- Relevant evidence commitments.
- Authoritative deadline and grace conditions.
- The specific release authorisation.
- The intended cryptographic custody operation.

Prevent replay across Capsules, policies, challenges and release attempts.

Do not allow the operator to select a convenient subset of history that conceals previously accepted presence.

Preserve the existing threshold-custody limitations: a malicious quorum with sufficient recoverable shares may still bypass the protocol.

This generation does not need to solve malicious custodian collusion.

---

# 8. Adversarial experiments

Build executable, reproducible experiments.

### A. The Lost Acknowledgement

Two witnesses durably retain presence.

The application crashes before acknowledging the creator.

The creator retries.

Recover the original accepted evidence and demonstrate that duplicate submission cannot create contradictory state.

### B. The Forgotten Witness

One witness loses its local database or restores an old snapshot.

Determine whether independently retained commitments expose the rollback.

### C. The Fabricated Absence

Compromise the application operator and one witness.

Attempt to erase an accepted presence and obtain an absence-based release certificate.

### D. The Equivocating Witness

One witness signs contradictory presence and absence claims.

Determine whether the remaining honest witnesses and custodians can detect or prevent a conflicting release.

### E. The Partitioned Network

Split witnesses into isolated groups across the deadline.

Attempt both presence acceptance and absence finalisation.

Record whether the system preserves safety by sacrificing availability.

### F. The Late Witness

A valid check-in reaches one witness before the deadline and another after it.

Define whether and when it becomes authoritative.

Test the precise boundary.

### G. The Silent Witness

One witness becomes unavailable.

Prove that its silence is not interpreted as evidence of the creator's absence.

### H. The Stolen Identity

Attempt to forge witness receipts, replay old receipts and substitute receipts from another challenge.

### I. The Custodian's Doubt

Present a valid-looking absence certificate to custodians that possess contradictory retained presence evidence.

They must reject release.

### J. The Solo Witness

Demonstrate the entire single-human dead man's switch lifecycle using the new witness mechanism.

No additional human authoriser.

### K. The Council

Demonstrate multi-party contract composition with independently witnessed evidence.

The witness mechanism must not be hardcoded to absence contracts.

### L. The Hostile Recovery

Crash witnesses at durable-write boundaries, restart them in different orders and replay requests.

Determine whether accepted evidence survives and whether conflicting certificates can emerge.

Preserve successful attacks as regression fixtures rather than hiding them.

---

# 9. Portable conformance and proof objects

Extend the existing conformance corpus with witness-specific canonical vectors.

Include:

- Signed presence receipts.
- Receipt-quorum certificates.
- Absence-finalisation evidence.
- Conflicting certificates.
- Replayed and expired proofs.
- Invalid witness identities.
- Cross-Capsule substitution.
- Snapshot rollback.
- Malicious witness equivocation.

Keep the independent JavaScript verifier aligned with the protocol specification.

The verifier must reject invalid proof objects independently of the reference Python implementation.

Where useful, add property-based tests and counterexample shrinking.

The specification must remain implementation-independent.

---

# 10. Performance and practicality

Measure the operational cost of independent witnessing.

At minimum:

- Check-in acceptance latency.
- Receipt sizes.
- Certificate sizes.
- Durable writes per accepted check-in.
- Storage growth per Capsule.
- Recovery time after witness restart.
- Release-verification cost.
- Behaviour when one witness is unavailable.

Use modest workloads and clearly describe the test environment.

Compare the results against Generation 0.2 where meaningful.

We are not optimising prematurely.

We are establishing whether this architecture is practical for a consumer application.

---

# 11. Deliverables

Extend the existing repository.

Preserve Generations 0.1 and 0.2.

Update:

- `PROTOCOL.md`
- `THREAT_MODEL.md`
- `CONFORMANCE.md`
- `EXPERIMENTS.md`

Add a dedicated Generation 0.3 research report describing the witness model, quorum assumptions, certificate semantics and observed failure cases.

Provide executable witness services or isolated processes, durable receipt storage, independent proof verification, adversarial tests and reproducible Docker experiments.

Record actual outputs and performance measurements.

At completion, provide a proposed Generation 0.4 based on the results.

Do not build the full SaaS yet.

However, ensure the protocol exposes a clean client-facing check-in operation and a verifiable acknowledgement result suitable for a future Laravel API and mobile companion.

---

# 12. The questions to answer

At the end of Generation 0.3, answer:

1. Can a creator obtain independently verifiable proof that their check-in counted?
2. Can a compromised operator erase accepted presence from the effective release history?
3. What minimum number of independent witnesses must be trusted?
4. Can valid presence and absence certificates coexist under the declared fault model?
5. What happens when witnesses disagree or become unreachable?
6. Can custodians verify release eligibility without trusting the application operator's interpretation?
7. Does the same mechanism support both Solo and Council configurations?
8. What are the latency, storage and operational costs of this independence?

Do not force favourable conclusions.

If the system cannot safely establish absence, it must not release.

---

# 13. The philosophical boundary

Otherwise is not attempting to prove that a human being is alive.

It is attempting to establish whether qualifying evidence of presence was accepted under a committed protocol.

That distinction is essential.

The system should never infer more about the world than its evidence justifies.

And our most important design principle remains:

> **The creator's presence must not become erasable merely because the operator wishes them absent.**

Generation 0.1 established the meaning of a release decision.

Generation 0.2 investigated who possesses the power to disclose.

Generation 0.3 investigates who possesses the power to remember.

Build the experiments.

Break the assumptions.

Preserve the failures.

**Otherwise 0.3 — The Retained Witness.**

*Your message stays yours. Otherwise...*
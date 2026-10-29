# OTHERWISE 0.7 — THE MISSING PIECE

## A research generation in cryptographic authority, independently verifiable contributions and resilient distributed custody

Professor, welcome back.

We have reached an important boundary in Otherwise's development.

Generation 0.6 demonstrated that honest threshold custodians can complete authorised disclosure without reconstructing a reusable master private key.

It also demonstrated that a malicious threshold can perform equivalent cryptographic operations prematurely.

That successful attack is not a regression to conceal. It is the starting point for this generation.

Our objective is to discover whether **a complete compromise of the custody quorum can cease to be sufficient for unauthorised disclosure**, by requiring an additional, independently controlled cryptographic capability that is released only following valid protocol authorisation.

We also need to address several distributed-systems weaknesses identified in 0.6.

This is an experimental research generation. Do not begin by assuming the proposed architecture is correct.

Read the existing repository, specifications, research records, attack transcripts, threat models, conformance tests and operational evidence before designing anything.

Preserve the complete historical experimental record.

---

# PART I — THE QUESTION

## 1. The fundamental challenge

Currently, a threshold of malicious custodians can produce the cryptographic capability necessary to decrypt a Capsule before its release policy authorises disclosure.

The custodians need not reconstruct the long-lived private scalar.

Possession of a sufficient threshold of partial-decryption capability is itself enough.

We want to test a stronger construction:

> The custody quorum, even when completely compromised, does not independently possess everything necessary to disclose the Capsule.

Instead, some indispensable capability must reside across an independently governed authorisation boundary.

That capability must be cryptographically necessary, not merely an approval flag checked by cooperative software.

A malicious custody quorum must not be able to replace, bypass, simulate or derive the missing capability from information already available to it.

**This is the central falsifiable hypothesis of Generation 0.7.**

## 2. Important limits

Do not confuse the following properties:

- No single custodian can disclose.
- An honest custody quorum can disclose without reconstructing a long-lived private key.
- A malicious custody quorum cannot disclose without authorisation-side capability.
- A malicious authorisation quorum cannot disclose without custody-side capability.
- A combined malicious quorum spanning both domains cannot disclose without legitimate policy authorisation.

The fifth property is substantially stronger than the third and fourth.

Do not claim it unless supported by a construction and threat model that actually establish it.

We expect that ordinary software-only cryptography cannot prevent disclosure when an attacker possesses all indispensable secret capabilities and can execute arbitrary computations.

If this is the applicable impossibility boundary, demonstrate it clearly.

The objective is to **change what a compromised party possesses**, not pretend that malicious software can be persuaded to respect policy.

---

# PART II — ESTABLISH THE THREAT MODEL

## 3. Model the participants explicitly

Distinguish at minimum:

- Creator and independently trusted creator client.
- Consumer SaaS operator.
- Evidence witnesses.
- Cryptographic custodians.
- Any independent authorisation-key holders.
- Recipient and recipient-side decryption client.
- Recovery operators and administrators.
- Transport and storage providers.

For every participant, document:

1. Identity and authentication mechanism.
2. Public and private cryptographic material.
3. Durable state and backup requirements.
4. Authority to sign, attest, authorise or decrypt.
5. Information learned during normal operation.
6. Consequences of full compromise.
7. Ability to censor, delay, replay or equivocate.
8. Relevant administrative and infrastructure dependencies.

Distinguish cryptographic independence from administrative independence.

Three services using separate keys but one cloud administrator do not provide three independent compromise domains.

Likewise, independently administered services may share a vulnerable dependency or compromised software update.

Explicitly model correlated compromise.

## 4. Define the required guarantee

Construct a precise security statement along these lines:

> Given a securely created Capsule, an uncompromised creator and recipient encryption boundary, sound cryptographic primitives, and an uncompromised indispensable authorisation capability, a fully compromised custody quorum cannot obtain the protected plaintext before legitimate release.

Identify every assumption necessary for that statement.

Define exactly what counts as obtaining plaintext, obtaining the content-encryption key, obtaining an equivalent decryption capability, or causing an unauthorised recipient to receive the content.

Do not rely solely on the absence of a master-key reconstruction event.

A successful premature partial-decryption attack is a confidentiality failure even if no long-lived secret is reconstructed.

---

# PART III — COMPARE ARCHITECTURES BEFORE SELECTING ONE

## 5. Candidate A: Separate custody and authorisation capabilities

Investigate a construction in which:

- The custody domain controls capability A.
- An independent authorisation domain controls capability B.
- Neither capability alone permits Capsule disclosure.
- A valid release operation requires appropriately authenticated contributions from both domains.

Use established cryptographic primitives.

Investigate combinations such as layered encryption, independently distributed key components, threshold encryption, threshold signatures and verifiable partial-decryption protocols.

Be careful: two sequential encryption layers may provide a useful research baseline, but the layer order, plaintext exposure, intermediate-key handling and recipient access must be analysed.

No hidden trusted coordinator may possess both complete capabilities.

No SaaS process may reconstruct the complete secret.

## 6. Candidate B: Witnesses as authorisation-capability holders

Investigate whether the existing independent evidence witnesses can also provide the missing cryptographic capability.

Advantages might include fewer committees and direct proximity to authoritative evidence.

Disadvantages may include:

- Concentration of evidence and cryptographic authority.
- Larger consequences from witness compromise.
- Increased key-management complexity.
- More difficult witness replacement and recovery.
- New opportunities for collusion or correlated failure.

Determine whether these concerns outweigh the operational simplicity.

Do not automatically equate a witness's authority to attest evidence with authority to perform cryptographic release.

Those are separate privileges unless the architecture deliberately combines them.

## 7. Candidate C: Stronger policy-aware cryptographic constructions

Conduct a bounded research investigation into whether established approaches involving MPC, verifiable computation, functional encryption, attribute-based encryption, witness encryption or related primitives materially improve our desired guarantee.

This is research, not an instruction to implement every candidate.

For each approach, ask:

- What precise security property does it provide?
- What information must already be available?
- Who holds the indispensable secrets?
- Can colluding participants bypass the prescribed computation?
- Does it require an honest participant or trusted hardware?
- Can it express the relevant release predicate?
- Can it represent an absence condition without assuming complete and trustworthy observations?
- Does it support creator disarm and changing lifecycle state?
- Is there a mature, independently reviewed implementation?
- What happens over decades of operation?

In particular, investigate the distinction between:

**A proof that an authorisation statement is valid** and **a cryptographic mechanism that makes such a proof indispensable to decryption**.

A signature over an approval is not, by itself, a decryption capability.

A zero-knowledge proof of an authorisation statement does not automatically prevent secret holders from bypassing the proof verifier.

A threshold-signature certificate may be useful as an input to a construction, but simply checking that certificate in software does not constrain a fully malicious custodian.

Report whether any construction genuinely changes that boundary.

Do not invent new cryptographic primitives or imply that speculative academic constructions are production-ready.

## 8. Explicitly exclude time-dependent disclosure primitives

Do not pursue time-lock puzzles, verifiable delay functions, scheduled key revelation or future randomness beacons as the primary release mechanism.

Otherwise's release predicate concerns independently established lifecycle evidence, not merely the passage of time.

Time remains relevant for check-in windows, evidence finality and protocol ordering.

It must not become an alternative basis for disclosing the secret.

---

# PART IV — INDIVIDUAL AND COLLECTIVE CRYPTOGRAPHIC VERIFICATION

## 9. Authenticate every contribution

The architecture must answer:

**How do we know who produced each piece?**

Use independently verifiable participant identities and authenticated contributions.

Bind each contribution to the relevant protocol context, including:

- Protocol version and cryptographic suite.
- Capsule identifier.
- Immutable Capsule commitment.
- Ciphertext digest.
- Recipient identity and encryption scope.
- Policy version.
- Release attempt identifier.
- Evidence head or finality certificate.
- Authorisation decision.
- Key generation or rotation epoch.
- Relevant participant and committee identities.

Use unambiguous canonical encoding and domain separation.

Prevent cross-Capsule, cross-recipient, cross-protocol and cross-generation substitution.

## 10. Prove mathematical correctness

The architecture must also answer:

**How do we know each piece is cryptographically valid?**

Investigate suitable established methods for verifying partial operations, including:

- Verifiable secret sharing.
- Public commitments to key shares.
- Proofs of correct partial decryption.
- Chaum–Pedersen-style equality-of-discrete-log proofs where applicable.
- Proofs of possession and authenticated committee membership.
- Robust combination procedures that reject invalid contributions.

Do not assume that a valid digital signature proves the cryptographic payload is correct.

Do not assume that a mathematically correct contribution was legitimately authorised.

Those are separate verification requirements.

## 11. Verify the collective result

Answer:

**How do we know the accepted contributions belong together and produce the intended result?**

The combiner or recipient must:

- Verify each individual contribution.
- Reject malformed and incorrectly scoped contributions.
- Detect duplicates and inconsistent epochs.
- Require the correct independent thresholds.
- Verify the applicable release evidence.
- Reject contradictory or superseded release states under the protocol's finality rules.
- Bind the result to the committed Capsule and intended recipient.
- Avoid accepting a result merely because a server reports success.

Where feasible, make the final result independently verifiable without requiring trust in the combiner.

Document exactly where plaintext becomes accessible.

## 12. Protect the capabilities

For each secret capability, specify:

- Secure provisioning and distributed generation.
- Storage and backup.
- Rotation and revocation.
- Participant replacement.
- Disaster recovery.
- Share refresh where supported.
- Protection against accidental logging.
- Key-exfiltration consequences.
- Behaviour under malicious administrators.
- Recovery when participants permanently disappear.

Be especially cautious about trusted-dealer provisioning.

If one component temporarily possesses all key material, describe that trust exposure and investigate alternatives.

If the selected construction cannot eliminate that exposure, retain it as an explicit limitation.

---

# PART V — THE HOSTILE CRYPTOGRAPHIC LABORATORY

## 13. Required experiments

Build reproducible attacks using synthetic Capsules and simulated disclosure.

### Experiment A — Entire custody quorum compromised

Give the attacker complete control of every custody participant and all custody-local secret material.

Do not give it authorisation-domain secrets.

Attempt premature disclosure.

**Expected property:** Custody compromise alone remains insufficient.

Prove this by attacking the implemented construction, not merely by observing that honest APIs refuse a request.

### Experiment B — Entire authorisation quorum compromised

Give the attacker complete control of the authorisation capability but no custody-side secrets.

Attempt disclosure.

**Expected property:** Authorisation compromise alone remains insufficient.

### Experiment C — Combined quorum collusion

Compromise sufficient participants across both domains.

Attempt premature disclosure.

Record the successful attack if it succeeds.

Do not conceal it.

### Experiment D — Valid authorised release

Complete a legitimate release using the appropriate evidence certificate and independent cryptographic contributions.

Verify that the correct recipient can recover the correct synthetic Capsule.

Determine whether any long-lived private key or unnecessary intermediate plaintext was reconstructed.

### Experiment E — Forged authorisation

Compromise the SaaS and fabricate an apparently valid release response without the required witness evidence.

Attempt to induce cryptographic disclosure.

### Experiment F — Valid arithmetic, invalid authority

Produce mathematically correct cryptographic contributions for a release that is not authorised.

Demonstrate that honest independent participants and verifiers reject the operation.

Record separately whether a sufficiently colluding set can bypass those checks.

### Experiment G — Substitution

Attempt to substitute:

- Ciphertext.
- Capsule identity.
- Recipient.
- Policy version.
- Evidence certificate.
- Committee membership.
- Key epoch.
- Partial operation from another release.

### Experiment H — Disarm versus release

Race a valid disarm against an emerging release authorisation.

Establish the exact durable finality boundary.

Prove the outcome from protocol facts rather than wall-clock observations.

If a valid disarm is accepted before final release commitment, determine whether disclosure can still occur.

If a release has irreversibly committed, specify what disarm can and cannot undo.

### Experiment I — Provisioning compromise

Attack key generation and initial distribution.

Determine whether one participant can bias, substitute, retain or reconstruct material that should be independently controlled.

### Experiment J — Rotation and participant replacement

Replace compromised participants.

Determine whether historical secret exposure survives rotation, and whether a newly formed committee can protect old Capsules without introducing a temporary single point of key compromise.

### Experiment K — Correlated compromise

Simulate shared administration, deployment credentials, backup access or update infrastructure spanning multiple nominally independent participants.

Identify how many effective trust boundaries actually remain.

### Experiment L — Independent recipient verification

Have a recipient independently verify the release proof and resulting plaintext commitment.

Attempt to mislead the recipient using a malicious combiner and forged SaaS status.

For each experiment, preserve the attacker configuration, inputs, transcript, output, exact result and security classification.

Use:

**Prevented / Detected / Recoverable / Successful / Outside the threat model.**

Do not confuse prevention with detection.

---

# PART VI — DISTRIBUTED-SYSTEMS RESILIENCE

The following problems were identified in Generation 0.6.

They deserve architectural attention, not merely local patches.

## 14. Byzantine-tolerant response collection

A single malformed custodian response must not poison an otherwise valid quorum.

Design a collector that:

- Requests contributions concurrently where appropriate.
- Authenticates and validates responses independently.
- Excludes invalid responses without discarding valid ones.
- Selects a sufficient compatible quorum.
- Enforces bounded concurrency and deadlines.
- Records invalid responses as auditable evidence.
- Does not silently downgrade cryptographic requirements.
- Does not rely on response arrival order for correctness.

A malicious minority may cause delays or consume resources, but must not be able to force failure when a sufficient valid quorum is reachable within the declared timing assumptions.

Test invalid, duplicated, delayed, reordered, equivocated and missing responses.

## 15. Witness availability

Investigate the sequential witness-request behaviour that can exhaust client timeouts.

Preserve existing quorum-intersection and evidence-safety guarantees.

Implement or prototype parallel witness requests with correct finality and quorum selection.

Demonstrate successful operation with one unavailable witness in the established four-witness configuration.

Do not assume that a response timeout establishes dishonesty or absence.

Distinguish safety, liveness and eventual recovery.

## 16. Durable evidence and rollback

Rollback detection must not depend exclusively on evidence retained by a compromised SaaS or a single client device.

Investigate independently retained monotonic evidence, cross-witness reconciliation and authenticated recovery checkpoints.

Simulate:

- SaaS database rollback.
- Creator device loss.
- Restoration from an old encrypted vault.
- Witness restart.
- Custodian restart.
- Conflicting evidence heads.
- Delayed evidence delivery.
- Long-term loss of one participant.

State which rollback attempts are prevented, detected or recoverable.

If a globally consistent ordering cannot be guaranteed under the network assumptions, do not pretend that wall-clock timestamps solve it.

## 17. Recovery and disaster scenarios

Explore the operational consequences of the new architecture.

Can a Capsule survive:

- One permanently lost custodian?
- One permanently lost authorisation participant?
- Replacement of a committee?
- Migration between infrastructure providers?
- SaaS shutdown?
- Creator device loss?
- Temporary network partition?
- Partial infrastructure restoration?

For every scenario, distinguish confidentiality preservation from eventual authorised disclosure.

An inaccessible secret is not a successful dead-man's-switch service.

---

# PART VII — IMPLEMENTATION STRATEGY

## 18. Research first, implement one candidate

Produce an architecture decision record comparing at least the two practical split-capability candidates and the bounded advanced-cryptography research track.

Then select one candidate for implementation.

Selection criteria:

1. Strength and clarity of the confidentiality guarantee.
2. Independence of compromise domains.
3. Mature cryptographic libraries and reviewability.
4. Honest handling of malicious-quorum limitations.
5. Independent recipient verification.
6. Recoverability and long-term maintenance.
7. Operational complexity.
8. Availability under partial failure.
9. Integration with existing protocol semantics.
10. Measured performance.

Prefer a smaller, comprehensible construction with explicit assumptions over an elaborate, unaudited design.

Do not introduce a custom cryptographic primitive.

If a production-grade library cannot support the intended property, implement an explicitly labelled research harness and document the gap.

## 19. Preserve existing architecture

Otherwise has three independently valuable pillars:

**Protocol:** Implementation-independent rules for lifecycle evidence, authority, custody and release.

**Consumer SaaS:** A replaceable Laravel product that consumes protocol services without owning authoritative truth or creator private capabilities.

**Infrastructure:** A separately designed deployment and administrative trust model.

Preserve these boundaries.

The protocol must work without Laravel.

The creator must be able to act without the SaaS.

Recipients must be able to verify release without trusting the SaaS.

Custody implementations must remain replaceable.

No PorterNet integration.

No real-world sensitive Capsules.

No real external disclosure.

## 20. Compatibility and conformance

Retain existing Generation 0.1–0.6 tests and successful attack counterexamples.

Add cross-language vectors where cryptographic proof objects or canonical encodings change.

If protocol compatibility must break, document the migration and version the relevant structures.

Do not silently reinterpret old evidence.

Run existing conformance tests before and after the change.

---

# PART VIII — MEASUREMENT AND EVIDENCE

## 21. Benchmark honestly

Compare Generation 0.6 and the new construction under equivalent workloads.

Measure:

- Capsule provisioning.
- Key generation and distribution.
- Encryption overhead.
- Check-in latency.
- Authorisation latency.
- Partial contribution generation.
- Contribution verification.
- Quorum collection.
- Honest disclosure.
- Recipient verification.
- Rotation and recovery.
- Persistent storage.
- Network payloads.
- CPU and memory consumption.
- Behaviour under one unavailable participant.
- Behaviour under one malicious participant.

Report medians and tail latencies where supported by sample sizes.

Separate cryptographic computation from network and persistence costs.

Record the actual environment.

Local Docker measurements are not WAN performance claims.

## 22. Required artifacts

Deliver:

1. `RESEARCH-0.7.md` — candidate comparison, literature and decision rationale.
2. `THREAT-MODEL-0.7.md` — explicit compromise assumptions and trust boundaries.
3. `PROTOCOL-0.7.md` — new cryptographic authorisation and verification semantics.
4. `ATTACK-LAB-0.7.md` — reproducible attacks and results.
5. `AVAILABILITY-0.7.md` — quorum collection, failure handling and recovery.
6. `BENCHMARKS-0.7.md` — measured performance and limitations.
7. Updated conformance tests and retained transcripts.
8. Working reference implementation or clearly scoped research harness.
9. Updated architecture and operational diagrams.
10. A concise Generation 0.7 executive report.

Use the repository's existing documentation conventions where appropriate.

---

# PART IX — THE FINAL EXAMINATION

Conclude with direct answers to the following questions.

**Q1.** Can a fully malicious custody quorum disclose a Capsule without the independent authorisation capability?

**Q2.** Can a fully malicious authorisation quorum disclose without the custody capability?

**Q3.** What happens when sufficient participants from both domains collude?

**Q4.** How is each cryptographic contribution authenticated?

**Q5.** How is its mathematical correctness verified?

**Q6.** How is the collective release independently verified?

**Q7.** What stops a legitimate contribution being replayed for a different Capsule, recipient, policy or evidence state?

**Q8.** What prevents a malformed or unavailable participant from defeating an otherwise healthy quorum?

**Q9.** What exactly happens when disarm and release race?

**Q10.** What new operational dependencies have we created, and what happens when they fail?

**Q11.** Which guarantees are mathematical, which rely on honest participants, and which depend on operational or administrative controls?

**Q12.** What successful attacks remain?

Do not answer these with marketing language.

Answer them with evidence, exact assumptions and reproducible results.

---

# SUCCESS CRITERIA

Generation 0.7 succeeds if it demonstrates that a fully compromised custody quorum alone is no longer sufficient for premature disclosure, while preserving legitimate release and independent verification.

It must also demonstrate materially improved tolerance of malformed and unavailable participants without weakening the evidence or cryptographic thresholds.

If the desired confidentiality property cannot be implemented responsibly, an experimentally justified negative result is acceptable.

Do not manufacture success.

Do not let a larger committee masquerade as a stronger trust boundary.

Do not let valid cryptographic arithmetic masquerade as legitimate authority.

And do not allow operational convenience to quietly restore a single component capable of disclosing everything.

**The custodian must possess a piece of the answer, not the authority to answer the question.**

Now build the missing piece.

Then try to steal it.
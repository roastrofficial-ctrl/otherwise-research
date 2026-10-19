# OTHERWISE
## Generation 0.2 — The Bounded Authority

**From verifiable decisions to independently enforced custody.**

Professor,

Generation 0.1 has given us something rather lovely.

We have an executable conditional-custody laboratory, a versioned protocol, independently evaluated contract semantics, durable acceptance ordering, encrypted Capsules and an adversarial test suite.

More importantly, we have established the beginnings of a general-purpose primitive:

> Information whose release is governed by independently evidenced obligations.

Now we want to discover whether those obligations can constrain the actual ability to decrypt information, rather than merely instructing a trusted server when to do so.

Welcome to Generation 0.2.

---

# 1. The founding principle: simplicity and complexity must coexist

Before we begin, an important clarification of the product vision.

**The single-authoriser dead man's switch remains a first-class use case.**

Our fascination with multi-party contracts must not obscure the original premise.

An ordinary person should be able to:

1. Create an encrypted Capsule.
2. Specify its destination.
3. Choose a check-in schedule.
4. Arm it.
5. Periodically confirm they are still present.

That's it.

No additional human trustees. No quorum configuration. No understanding of threshold cryptography.

If they fail to check in and the release policy is satisfied, the Capsule becomes eligible for release.

At the same time, advanced users should be able to establish Capsules governed by multiple independent entities, contracts and thresholds.

These are not separate products.

They are two configurations of the same protocol.

**One authoriser must not imply one custodian.**

A single human may establish and satisfy a release policy while independent cryptographic custodians protect the underlying decryption capability.

This distinction is foundational.

We want the user experience to be simple precisely because the protocol handles the complexity.

---

# 2. The three authorities

Generation 0.2 should explicitly distinguish three forms of authority.

### Acceptance authority

Determines which evidence has been durably accepted, in what order, and under which policy version.

Its responsibility is historical.

It answers:

"What evidence became authoritative, and when?"

### Decision authority

Evaluates the committed policy against accepted evidence.

Its responsibility is semantic.

It answers:

"Does the evidence authorise release?"

### Custody authority

Controls the cryptographic capability required to recover the Capsule's plaintext.

Its responsibility is cryptographic.

It answers:

"Can this information actually be decrypted?"

These authorities may initially share infrastructure, but their responsibilities must remain separate.

The central experiment is whether custody can become genuinely independent of the service operator.

An operator must not be able to obtain plaintext merely by fabricating a successful policy evaluation.

---

# 3. Two mandatory reference scenarios

Implement and test both scenarios through the same protocol and engine.

## Scenario A — The Solo Witness

One creator.

One absence contract.

One encrypted Capsule.

One configured release policy.

No second human authoriser.

The creator periodically submits authenticated presence evidence.

If sufficient evidence is absent, and all committed safeguards have been satisfied, release becomes authorised.

Independent custodians may participate automatically in enforcing that decision.

The creator must not need to interact with those custodians directly.

This is our primary consumer-product scenario.

**Success criterion:** demonstrate the complete lifecycle, including check-in, missed check-in, grace period, release, disarm and recovery, without introducing additional human approval requirements.

## Scenario B — The Council

One encrypted Capsule.

Three independent contract authorities.

A committed `THRESHOLD(2, 3)` release policy.

Independent attestations are submitted, accepted and evaluated.

The Capsule becomes eligible for release only when the composition is satisfied.

**Success criterion:** demonstrate that multiple independent entities can govern the same Capsule without altering the underlying release machinery.

Critically, distinguish the policy threshold from the cryptographic custody threshold.

`THRESHOLD(2, 3)` in a release policy does not automatically mean that a 2-of-3 cryptographic scheme correctly enforces that policy.

These are different layers with different security properties.

---

# 4. The central experiment: remove the operator's power

Generation 0.1 acknowledges that the service operator possesses the decryption capability.

Generation 0.2 should attempt to remove that capability.

Investigate a small independent custody model, initially with three custodians and a two-of-three recovery threshold.

Use established, reviewed cryptographic constructions. Do not invent new cryptography.

The operator may control:

- The application server.
- The database.
- The scheduler.
- The release workers.
- The delivery adapters.
- The application configuration.
- The operator-controlled filesystem.

The operator must not automatically control the independent custodians or their secrets.

The experiment should attempt to establish:

> Compromise of the application operator alone is insufficient to recover a Capsule's plaintext before authorised release.

But that is only half the problem.

If two custodians can reconstruct the secret whenever they choose, they can bypass the release policy.

We must investigate whether custodian participation can be bound to independently verified, snapshot-specific release authorisation.

A signed release claim supplied by the operator must not automatically be accepted as truth.

Custodians should independently verify whatever authoritative evidence the protocol requires.

If the chosen construction cannot enforce this, document the limitation rather than claiming success.

Do not confuse distributing key shares with enforcing conditional release.

---

# 5. Real clocks and uncertain absence

Generation 0.1 uses a controlled clock.

That was the correct choice for deterministic experiments, but it cannot establish real-world timing guarantees.

Introduce a carefully specified clock authority and failure model.

Investigate:

- Wall-clock drift.
- Monotonic time.
- Restarts.
- Clock discontinuities.
- Storage restoration.
- Long scheduler pauses.
- Evidence arriving near a deadline.
- Network partitions.
- Receipt time versus durable acceptance time.
- Service outages spanning entire check-in windows.

Define which authority determines deadline eligibility.

Define the precise acceptance threshold.

Define how uncertainty affects release eligibility.

In particular, establish whether an outage can safely extend a grace period without violating the committed policy.

A missing check-in must never be described as proof that the creator is dead or incapacitated.

It is only an absence of qualifying evidence under a particular observation model.

When the observation model is compromised, the system must not silently pretend certainty.

Prefer withholding release when the evidence needed for authorisation is ambiguous.

Document the corresponding liveness trade-off.

---

# 6. Durable history and independent witnesses

Generation 0.1 uses SQLite to serialise authoritative decisions.

That is an entirely reasonable local foundation.

However, local durability is not equivalent to externally verifiable history.

An operator with sufficient control may restore an earlier database snapshot, removing previously accepted presence evidence.

A locally stored audit hash cannot, by itself, detect a complete rollback when the attacker controls the database and its anchor.

Introduce an experiment involving independently retained history commitments.

For example, an external witness may retain signed or authenticated history heads.

Test whether a restored or rewritten authority can be detected.

The objective is not to build a blockchain.

The objective is to establish the smallest mechanism that makes history rewriting observable to an independent participant.

Investigate crash consistency across database commits, encrypted payload writes and key-custody operations.

Define how orphaned objects, incomplete commits and recovery are handled.

Preserve the exact threshold at which a fact becomes authoritative.

---

# 7. Portable conformance

Generation 0.1 introduced independent policy evaluation.

Generation 0.2 should make conformance portable.

Publish fixed canonical fixtures containing:

- Protocol versions.
- Test identities and keys.
- Signed evidence.
- Contract definitions.
- Policy expressions.
- Authoritative histories.
- Expected decisions.
- Rejected evidence.
- Boundary-time cases.
- Disarm and release races.

Implement a genuinely independent interpreter or verifier in another language.

Avoid simply translating the reference implementation line by line.

Both implementations should agree on the meaning of the same committed history.

Add generated histories with nested policies and deliberately adversarial ordering.

When a disagreement is discovered, shrink it to a minimal reproducible counterexample.

Preserve every meaningful counterexample as a permanent regression test.

The continuous-grace boundary deserves particular attention.

A condition being satisfied at the beginning and end of a period must not be assumed to mean it remained satisfied throughout.

---

# 8. Adversarial custody experiments

Build executable attacks against the chosen custody model.

At minimum:

**A. The Compromised Operator**

Give the operator complete access to operator-controlled infrastructure.

Attempt to decrypt the Capsule without custodian cooperation.

**B. The Forged Release**

Have the operator manufacture a successful release decision unsupported by authoritative evidence.

Attempt to persuade custodians to release key material.

**C. The Replayed Authorisation**

Present an old valid release authorisation for a different Capsule, policy version or history snapshot.

Verify that it cannot authorise unrelated decryption.

**D. The Missing Custodian**

Make one custodian unavailable.

Determine whether authorised recovery remains possible and whether security guarantees change.

**E. The Colluding Custodians**

Allow enough custodians to cooperate maliciously.

Document what they can do.

If threshold custody permits them to recover the plaintext outside policy, acknowledge that limitation explicitly.

**F. The Rewritten History**

Restore an old database snapshot after valid presence evidence has been accepted.

Determine whether independent witnesses detect the rollback and whether custodians refuse unsupported release.

**G. The Solo Witness**

Run the entire single-authoriser lifecycle with independent custody enabled.

No additional human intervention should be necessary.

**H. The Council**

Run the multi-contract threshold scenario.

Verify that policy authorisation and cryptographic custody remain distinct and correctly bound.

**I. The Emergency Disarm**

Race disarm against release authorisation and custodian participation.

Define the irreversible threshold beyond which disclosure cannot be recalled.

Test whether disarm prevents new authorisations and whether previously issued cryptographic capabilities can still be used.

**J. The Broken Authority**

Simulate an unavailable, compromised or inconsistent acceptance authority.

Establish whether custodians can safely distinguish a valid release from an unsupported claim.

---

# 9. Preserve the product boundary

We are ultimately building a consumer SaaS on top of an open protocol.

The eventual product should support:

- Encrypted Capsules.
- Simple check-in schedules.
- Clear release conditions.
- Email, SMS and hosted delivery destinations.
- A companion app with push notifications.
- Escalation and grace periods.
- Emergency disarming.
- Optional multi-party approval.
- Understandable custody and release receipts.

However, Generation 0.2 is not the moment to build all of that.

Do not introduce real-world disclosure destinations yet.

Continue using synthetic recipients and isolated test environments.

A thin Laravel client may be introduced if useful for validating the integration boundary, but it must not dictate protocol semantics.

No real secrets or sensitive third-party data should enter the laboratory.

The eventual product must make its limitations clear, prevent accidental publication, verify recipient consent and avoid presenting missed check-ins as proof of death.

---

# 10. Deliverables

Extend the existing repository rather than rebuilding it.

Preserve the working Generation 0.1 experiments and conformance tests.

Provide:

1. Updated `PROTOCOL.md` describing the three authorities and any new wire semantics.
2. Updated `THREAT_MODEL.md` with explicit operator, custodian and collusion assumptions.
3. Updated `CONFORMANCE.md` with Solo and Council reference scenarios.
4. A portable, fixed-vector conformance corpus.
5. A second-language verifier.
6. A real-clock and outage experiment suite.
7. An independently witnessed history experiment.
8. A small independent custody implementation or an explicitly bounded feasibility experiment if secure implementation cannot be justified.
9. Executable adversarial custody tests.
10. Recorded results, including failures and limitations.
11. A proposed Generation 0.3 grounded in the findings.

Retain Docker Compose reproducibility.

Keep the system runnable without production infrastructure or external delivery services.

Do not report proposed experiments as completed experiments.

---

# 11. Research discipline

Continue the approach that made Generation 0.1 successful.

No unnecessary infrastructure.

No speculative security guarantees.

No distributed systems merely for aesthetic effect.

No home-grown cryptography.

No pretending that signatures establish the truth of real-world claims.

No treating a release authorisation as proof that disclosure occurred.

And no treating a successful demonstration as evidence of production readiness.

If an experiment disproves our assumptions, that is a valuable result.

Preserve it.

Explain it.

Let the next generation respond to the evidence.

---

# 12. The questions I want answered

At the end of Generation 0.2, answer these precisely.

**Question One**

Can a single human authorise a conditional release lifecycle without personally managing multiple cryptographic custodians?

**Question Two**

Can independent custodians prevent a compromised application operator from decrypting early?

**Question Three**

Can custodians distinguish a genuinely authorised release from an operator-fabricated decision?

**Question Four**

Can an independent witness detect when the acceptance authority has rewritten or rolled back its history?

**Question Five**

Can the protocol make defensible decisions about missing evidence when clocks, networks and services are unreliable?

**Question Six**

What happens when the authorities themselves disagree, collude or disappear?

Do not force affirmative answers.

We want to discover what is possible, under which assumptions, and at what cost.

---

# 13. The larger ambition

Otherwise began with a simple thought:

A person leaves an encrypted message that should be released if they stop checking in.

It has evolved into something more interesting:

**An open protocol for conditional custody, where information is released according to independently evidenced obligations.**

But the simple use case remains our anchor.

We should eventually be able to hand Otherwise to someone with no technical knowledge and let them confidently create a Capsule.

Behind that experience, the protocol may coordinate independent evidence, policy evaluation, custody and release.

The user shouldn't have to care.

That is the engineering challenge.

And there is one principle I want us to carry into every future generation:

> **A promise not to disclose information is only as strong as the mechanisms that prevent the promise-maker from breaking it.**

Generation 0.1 investigated whether the release decision could be made correctly.

Generation 0.2 investigates whether that decision can meaningfully constrain the power to disclose.

Build the experiments. Break the assumptions. Record what survives.

**Otherwise 0.2 — The Bounded Authority.**

*Your message stays yours. Otherwise...*
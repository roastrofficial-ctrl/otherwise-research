# PROJECT OTHERWISE
## Generation 0.1 — The Absent Witness

**An open protocol for conditional information release.**

Professor, welcome to another counterfactual computing experiment.

We're building **Otherwise**.

The premise is deceptively simple:

A person deposits an encrypted payload, establishes a check-in schedule and a release policy, and periodically proves their continued presence.

If they fail to check in within the agreed window, the system may release that payload to predetermined destinations.

The familiar term is *dead man's switch*.

We want to explore something more fundamental:

> Can information be entrusted to a system with a verifiable promise about the circumstances under which it may be released?

We intend to create both:

1. **Otherwise Protocol** — an open, implementation-independent specification for conditional information release.
2. **Otherwise** — a consumer-facing SaaS built on that protocol.

The protocol must be independently useful. The SaaS must be an implementation of it, not its definition.

Our approach is experimental. Build a functioning system, subject it to hostile conditions, document what survives, and let the evidence determine the next generation.

Do not assume this idea is novel. Investigate existing dead man's switches, secret-sharing systems, digital escrow, distributed custody and cryptographic release mechanisms. Identify what we can learn from them and what genuinely remains unexplored.

---

# 1. The research thesis

Most information systems operate on positive instructions:

"When I request an action, perform it."

Otherwise explores a different primitive:

"Unless sufficient evidence arrives before a deadline, authorise an action."

This creates a fundamental asymmetry.

**Presence can be evidenced. Absence cannot necessarily be proven.**

A missing check-in may mean the creator is incapacitated. It may also mean their phone is offline, their notification never arrived, their network partitioned, or the service failed.

The protocol must never confuse a lack of observed evidence with proof of death, incapacity or intent.

Our central question for Generation 0.1:

> Can independent implementations reach the same, auditable release decision from the same policy and authoritative evidence, despite delayed messages, retries, crashes and competing workers?

We are not yet attempting to prove that no custodian can decrypt a payload prematurely.

That is a separate, important research problem.

---

# 2. Product vision

Imagine a consumer application.

A user creates a **Capsule** containing text, documents or other files.

They configure:

- An encrypted payload.
- One or more release destinations: email, SMS, or a hosted publication page.
- A check-in frequency.
- Active days, dates and time windows.
- A response deadline for each check-in.
- Reminder and escalation behaviour.
- A final release grace period.
- Optional trusted contacts and additional verification.

The companion app periodically notifies the creator.

The creator confirms their presence.

Nothing happens.

But if the creator misses a check-in and all required safeguards expire, the Capsule becomes eligible for release.

For this generation, use simulated destinations and test recipients only. No public publishing or real external disclosure is required.

The user experience should eventually be reassuring, straightforward and transparent, despite the rather ominous underlying concept.

---

# 3. Architectural boundaries

Establish three clearly separated components.

### A. Otherwise Protocol

An implementation-independent specification defining:

- Capsule identifiers and versions.
- Immutable policy commitments.
- Check-in challenges.
- Presence evidence.
- Evidence acceptance rules.
- Deadlines and clock assumptions.
- State transitions.
- Release authorisation.
- Cancellation and disarming.
- Audit evidence and replay semantics.

Use versioned, canonical message formats.

Define exactly what each fact means and what it does not mean.

Avoid allowing implementation-specific database behaviour to become part of the protocol.

### B. Otherwise Engine

A reference implementation of the protocol.

Responsible for durable state, evidence validation, deadline evaluation, atomic transitions, concurrency control and release authorisation.

This must be executable independently of the consumer application.

### C. Otherwise App

A thin, practical demonstration application.

Our preferred eventual stack is Laravel for the backend, with a mobile-friendly frontend and a native companion app later.

For Generation 0.1, prioritise the protocol and executable tests over visual polish.

A minimal browser interface or CLI is perfectly acceptable.

Use Docker Compose for a reproducible local environment.

---

# 4. The first protocol vocabulary

Start with a small set of concepts.

**CAPSULE**

A uniquely identified payload and associated immutable release policy.

**POLICY**

A versioned commitment describing check-in requirements, grace periods, evidence authorities and release conditions.

**CHALLENGE**

A particular check-in obligation, with an identifier and explicit validity window.

**PRESENCE**

Authenticated evidence satisfying a specific challenge.

**ARMED**

A durable commitment activating a particular Capsule policy.

**RELEASE_AUTHORISED**

An immutable decision that the protocol's release conditions have been satisfied.

**RELEASED**

Evidence that a delivery adapter has performed a specified release action. Do not equate an attempted delivery with confirmed receipt by a human.

**DISARMED**

A durable, authenticated decision preventing any future release authorisation under the current policy.

Feel free to refine these terms where necessary.

However, distinguish immutable facts from mutable projections.

The event history should explain how a Capsule reached its current state.

---

# 5. The fundamental race

This is the experiment's centrepiece.

A Capsule has a check-in deadline at 12:00:00.

Server A receives authenticated PRESENCE at 11:59:59.

Server B receives the same evidence at 12:00:03.

At 12:00:01, Server B believes the challenge has expired.

Should the Capsule be released?

We need a precise answer.

Do not solve this by casually comparing application-server timestamps.

Design an explicit authority model.

For Generation 0.1, a single durable authoritative acceptance boundary is acceptable. Multiple workers may compete, but they must share an atomic ordering mechanism.

A valid check-in must become authoritative at a well-defined durable threshold.

Define how its deadline eligibility is established, including what happens when a request arrives before the deadline but commits after it.

Define the release decision's atomic threshold.

Ensure that an accepted, timely check-in cannot be overtaken by a competing release decision.

If a valid check-in was not durably accepted before the applicable boundary, explain what guarantee the system can and cannot make.

Document the limitations of the chosen clock model.

We are not claiming to solve distributed consensus in Generation 0.1.

We are making our assumptions explicit.

---

# 6. Safety and failure semantics

This service handles information whose premature disclosure may cause irreversible harm.

Treat release as a security-sensitive operation.

The following should be explicit design requirements:

- A failed push notification must not automatically count as meaningful evidence that the creator is absent.
- A service outage must not silently create an unsafe release.
- A delayed check-in must be handled according to a documented acceptance policy.
- Repeated check-ins must be idempotent.
- Duplicate release jobs must not create duplicate authorisations.
- A valid disarm must prevent any subsequent release authorisation.
- A disarm racing an authorisation must have an unambiguous, auditable outcome.
- A scheduled release must have a substantial configurable grace period.
- Release to third parties must require appropriately verified and consented destinations.
- Public disclosure should be disabled in the initial implementation.
- No release should occur from an ambiguous or corrupted state.

Prefer **fail-closed behaviour** for the first generation: when the system cannot establish that the release conditions have been satisfied, do not authorise release.

Also document the trade-off: a system that delays disclosure during uncertainty cannot promise perfectly timely disclosure.

A release authorisation must never be treated as equivalent to successful external delivery.

---

# 7. Encryption and custody

We want the eventual service to store encrypted payloads without requiring users to trust our administrators with unrestricted plaintext access.

But do not disguise the central cryptographic problem.

If our server can automatically decrypt a payload, it possesses or can obtain the necessary decryption capability.

Client-side encryption alone does not solve this.

For Generation 0.1:

- Encrypt payloads using established authenticated encryption.
- Keep encryption keys and payloads separate.
- Use a clearly labelled development custody model.
- Never invent cryptographic primitives.
- Make the release engine operate on payload references rather than plaintext.
- Do not claim zero-knowledge guarantees.
- Document the threat model and what an administrator or compromised server could do.

Create a research document examining later possibilities:

- Threshold secret sharing.
- Independent custodians.
- Hardware-backed key custody.
- Client-held recovery secrets.
- Distributed release authorisation.
- Verifiable evidence of custody transitions.

Identify which approaches actually prevent unilateral premature decryption and which merely distribute operational responsibility.

The protocol should be designed so custody mechanisms can evolve without redefining the meaning of a valid release authorisation.

---

# 8. Build the executable experiment

Deliver a working local system that demonstrates:

1. Creation of a Capsule with encrypted test content.
2. Commitment of an immutable check-in policy.
3. Arming the Capsule.
4. Issuance of check-in challenges.
5. Submission and durable acceptance of PRESENCE.
6. Expiry of a challenge without accepted evidence.
7. A configurable grace and escalation period.
8. Atomic release authorisation.
9. Delivery to a simulated recipient.
10. A complete audit history explaining the decision.

Use accelerated simulated time or a controlled clock so experiments do not require waiting hours.

The normal successful path should demonstrate repeated check-ins with no release.

The failure path should demonstrate a missed check-in followed by an authorised release.

The disarm path should demonstrate that a valid disarm prevents release.

---

# 9. Adversarial experiments

Build automated experiments rather than merely describing them.

At minimum:

**Experiment A — The Last-Second Witness**

Submit PRESENCE at the deadline while a release worker evaluates expiry.

Repeat with controlled ordering variations.

**Experiment B — Competing Executors**

Run multiple release workers against the same Capsule.

Prove at most one authoritative release decision exists.

**Experiment C — The Forgotten Receipt**

Commit a check-in, then simulate losing the acknowledgement.

Retry the submission and prove the original fact is recovered rather than duplicated.

**Experiment D — The Dead Scheduler**

Stop the scheduler, advance time, restart it.

Prove that downtime cannot bypass required safeguards.

**Experiment E — The Double Release**

Crash after recording release authorisation but before delivery acknowledgement.

Retry and inspect delivery idempotency, including the limitations of external providers that do not support idempotent requests.

**Experiment F — The Emergency Disarm**

Race an authenticated disarm against release authorisation.

Prove the winner is determined by the authoritative ordering rule, not thread timing or arbitrary application logic.

**Experiment G — The Broken Clock**

Introduce clock skew and discontinuities.

Identify precisely which guarantees survive and which depend on the trusted clock.

**Experiment H — The Corrupted History**

Remove, reorder or alter persisted facts in a controlled test fixture.

Verify that corrupted or unverifiable history cannot silently produce release authorisation.

**Experiment I — The Unreachable Creator**

Simulate failed notifications and a creator unable to reach the service.

Demonstrate the limitations of the system's knowledge and the fail-safe behaviour specified by policy.

**Experiment J — Independent Interpretation**

Build a second, minimal policy evaluator that does not reuse the reference engine's decision logic.

Feed both implementations identical canonical facts.

Compare decisions across normal, boundary and adversarial histories.

This is especially important. We want evidence that our specification is implementable independently.

---

# 10. Deliverables

Produce a repository containing:

- `README.md` — concept, motivation, architecture and quick start.
- `PROTOCOL.md` — formal vocabulary, message formats, authority and state semantics.
- `THREAT_MODEL.md` — adversaries, trust assumptions and security boundaries.
- `CONFORMANCE.md` — executable invariants and test expectations.
- `EXPERIMENTS.md` — actual experimental results, failures and observations.
- `CUSTODY_RESEARCH.md` — future cryptographic and distributed custody options.
- A functioning reference implementation.
- A minimal demonstration client.
- Automated adversarial tests.
- A Docker Compose environment.
- A simple script that runs the complete experiment suite.

Include reproducible commands and actual output.

Do not present hypothetical test results as observations.

---

# 11. Engineering philosophy

We have several rules for this project.

**First: evidence over elegance.**

If the architecture looks beautiful but fails under concurrency, the failure is more valuable than the diagram.

**Second: no premature distributed theatre.**

Do not add Kafka, consensus clusters, blockchain, independent custodians or complex orchestration merely because the project involves trust.

Start with the smallest system capable of exposing the actual problems.

**Third: preserve meaningful boundaries.**

The protocol must not become synonymous with a Laravel application, database schema or delivery provider.

**Fourth: make failure interesting.**

When an invariant fails, preserve the counterexample and explain what it teaches us.

**Fifth: resist false security claims.**

Especially around encryption, timing, availability and release guarantees.

**Sixth: keep the product in view.**

This is not purely an academic exercise. The eventual goal is a service that ordinary people can understand and safely use.

---

# 12. What I want back from you

Work autonomously through Generation 0.1.

Make reasonable implementation choices and document them.

Build the working experiment, run the tests, record failures, and improve the design where the evidence justifies it.

Do not stop at an architecture proposal.

At completion, provide:

1. A concise account of what was actually built.
2. The exact protocol invariants established.
3. The results of the adversarial experiments.
4. Any failures, counterexamples or unresolved ambiguities.
5. A clear explanation of what the system does **not** guarantee.
6. Your proposed Generation 0.2, based on the evidence.

And finally, answer this question:

> **Have we built a system that can safely interpret silence, or merely a system that mistakes silence for permission?**

That distinction is the entire experiment.

Welcome to Otherwise.

*Your message stays yours. Otherwise...*
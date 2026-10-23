# OTHERWISE 0.6 — THE HONEST CUSTODIAN

**Research question:** Can Otherwise make authorised disclosure a property of the custody protocol, rather than merely a promise made by servers holding reconstructable secrets?

Professor, welcome back to the laboratory.

We have an established, working system through Generation 0.5. Read the existing implementation, threat model, custody research, conformance suite and retained attack results before modifying anything.

Do not begin with a rewrite. Do not weaken existing security properties to make a new experiment pass.

Our objective is not to demonstrate that distributed cryptography exists. It is to discover exactly what it can—and cannot—guarantee for Otherwise.

## 1. The fundamental problem

The existing static Shamir-share implementation protects against a single compromised custodian below threshold.

However, a colluding threshold can reconstruct the secret without any authorised release. This attack is already demonstrated and must remain reproducible.

Investigate three distinct guarantees:

- **No unilateral disclosure:** A single custodian or SaaS operator cannot decrypt.
- **No key reconstruction during legitimate release:** An authorised operation can disclose a specific Capsule without assembling the underlying long-lived private key.
- **No unauthorised disclosure by a malicious quorum:** Even threshold collusion cannot decrypt before policy authorisation.

These are different properties. Do not imply that achieving the second establishes the third.

In particular, ordinary threshold decryption may protect the distributed private key from reconstruction while still allowing a malicious threshold to collaborate on premature decryption.

If the third guarantee is impossible under our stated software-only trust model, say so explicitly and retain a concrete counterexample.

## 2. Research before implementation

Evaluate established, documented constructions and their assumptions.

Include:

- Threshold public-key encryption and distributed partial decryption.
- Distributed key generation versus trusted-dealer provisioning.
- Verifiable shares, authenticated partial decryptions and ciphertext binding.
- Hardware-enforced policy, including realistic administrator and firmware trust.
- Cryptographic time-lock or delay mechanisms, distinguishing elapsed time from conditional evidence.
- Threshold/MPC approaches that might evaluate an authorisation predicate, including what colluding participants can bypass.

Assess complexity, implementation maturity, security assumptions, recoverability, key rotation, operational costs and compatibility with a decades-long custody obligation.

**Do not invent a cryptographic primitive.**

Select one narrowly scoped, credible candidate for implementation using an established library or clearly documented reference construction.

If no suitable implementation can be responsibly integrated, produce a reproducible research harness instead of pretending a toy construction is secure.

## 3. Build an interchangeable custody provider

Preserve the provider boundary established in 0.4 and 0.5.

The new provider must:

- Accept an immutable, authenticated Capsule commitment.
- Verify the applicable lifecycle state and independent witness evidence.
- Bind partial operations to Capsule ID, ciphertext digest, recipient scope, manifest version, authorisation decision and evidence head.
- Reject stale, contradictory, replayed or cross-Capsule authorisation contexts.
- Preserve existing independent-client and SaaS-offline workflows.
- Expose precise capabilities, distinguishing threshold key protection from cryptographically enforced release policy.

Avoid a hidden coordinator that can independently decrypt, forge evidence or silently substitute recipients.

Ensure legitimate disclosure produces only the information authorised for the specified Capsule and recipients. Identify where plaintext becomes visible and which participant is trusted at that boundary.

## 4. The hostile custody experiment

Construct a reproducible adversarial laboratory with genuinely separate custodian identities and persistent state.

Exercise at least these cases:

1. **Single-custodian compromise:** Attacker extracts everything accessible to one custodian. Attempt premature disclosure.
2. **Threshold collusion:** Attacker controls enough custodians to meet the cryptographic threshold. Attempt premature disclosure without a valid release decision.
3. **Honest release:** Valid independent witness evidence authorises disclosure. Complete the operation without reconstructing the long-lived private key, if the selected construction supports this.
4. **Forged decision:** Malicious SaaS submits an apparently successful but unauthorised decision.
5. **Stale evidence:** One participant sees a superseded or rolled-back evidence head.
6. **Changed Capsule:** Substitute ciphertext, recipient or commitment while reusing genuine partial operations.
7. **Disarm race:** Owner disarms around the release boundary. Determine the exact ordering threshold and whether disclosure can still proceed.
8. **Unavailable custodian:** Remove one custodian, then restore it. Characterise both safety and liveness.
9. **Restart and rollback:** Crash before and after durable partial-operation records. Test replay and recovery.
10. **Compromised client or provisioning:** Establish what can be stolen at creation and whether the system can detect it.

For every experiment, record the attacker's capabilities, attempted action, actual result, preserved evidence and classification:

**Prevented / Detected / Recoverable / Successful / Outside the threat model.**

Never count a merely detected disclosure as prevented.

## 5. Confront the impossibility boundary

I specifically want a rigorous treatment of this question:

> If a threshold of custodians collectively possesses all the cryptographic capability required to decrypt, what prevents that same threshold from exercising the capability early?

If the answer is only that honest software checks authorisation first, we have operational policy enforcement, not cryptographic enforcement against a malicious quorum.

Investigate whether stronger guarantees require additional assumptions: trusted hardware, independent non-colluding participants, external secrets, time-dependent primitives or some other independently justified trust boundary.

Explain any conflict between autonomous release after creator disappearance and requiring a creator-held secret to decrypt.

Do not market conditional secrecy as mathematically guaranteed unless the experiment supports that exact claim.

## 6. Preserve the three independent pillars

The Otherwise Protocol, Consumer SaaS and Infrastructure remain independently replaceable.

The protocol must run without Laravel. The trusted creator client must work without the SaaS. The custody provider must be replaceable without changing the meaning of witness evidence or release authorisation.

No PorterNet integration in this generation.

Use synthetic Capsules and simulated disclosure only.

## 7. Measure the costs

Compare the existing 0.5 static-share provider with the new candidate under equivalent workloads.

Measure provisioning, encryption, check-in impact, authorisation, partial operations, disclosure, recovery, durable storage, network payloads and failure handling.

Report medians and tails where sample sizes justify them, with exact hardware and test conditions.

Do not extrapolate local Docker results to real-world geographic deployments.

## 8. Required deliverables

- Updated threat model and trust-boundary diagram.
- Research decision record comparing candidates and rejected alternatives.
- Working reference implementation or an explicitly limited research harness.
- Reproducible attack scripts and retained successful counterexamples.
- Conformance and regression tests, including all existing generations.
- Performance and operational-cost report.
- A clear guarantee matrix: what is prevented, what is merely detectable, what remains possible.
- An updated roadmap distinguishing protocol, client, custody and deployment concerns.

Finish with a concise report answering:

**What can one malicious custodian do? What can a malicious threshold do? What can the SaaS operator do? What can an honest quorum guarantee? What can no software-only arrangement guarantee under the present assumptions?**

## Success criteria

This generation succeeds if we emerge with a demonstrably stronger custody design **or a convincing experimental demonstration of why the desired guarantee requires stronger trust assumptions**.

An honest negative result is a success.

Do not sacrifice 0.5's independently verified creator authority or the existing witness safety properties.

And above all:

**The custodian holds the secret. That must not mean the custodian gets to decide when the promise is broken.**

Go find the boundary.
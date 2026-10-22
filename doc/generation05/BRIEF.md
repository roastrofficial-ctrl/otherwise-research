# OTHERWISE 0.5 — THE UNTRUSTED OPERATOR

Professor,

Generation 0.4 demonstrated that Otherwise can function independently of its consumer SaaS.

Now we must establish whether it can remain secure when that SaaS becomes adversarial.

The central question:

**Can a creator establish, maintain and revoke conditional custody without trusting the operator of the application they use?**

We are not asking for production hardening. We are asking for a falsifiable security model and an executable implementation.

## 1. Establish the adversary

Assume the SaaS operator controls:

- The Laravel application and its database.
- Its backend services and deployment pipeline.
- Every API response originating from the SaaS.
- The ability to censor, delay, replay, reorder or fabricate application-level requests.
- Any cryptographic material previously exposed to the SaaS.

The operator does not automatically control independently administered witnesses, custodians or a creator's trusted local device.

Explicitly distinguish malicious server behaviour from malicious client-code delivery. A web application whose JavaScript is served by a compromised operator cannot simply claim that client-side cryptography protects against that operator.

Do not hide this problem behind the phrase "end-to-end encryption."

## 2. Establish creator-held authority

Move creator identity, signing and Capsule encryption authority outside the SaaS trust boundary.

Investigate:

- Local key generation and signing.
- Local encryption before submission.
- Independently verifiable receipts.
- Portable recovery capabilities.
- Device loss and replacement.
- Revocation and rotation.
- Replay-resistant authorisation.
- Safe handling of signing keys across clients.

The operator must not be able to impersonate a creator merely by controlling their SaaS account.

Specify how the client software itself is trusted, distributed and updated.

A native client, independently installed CLI or pinned client build may provide a stronger experimental trust boundary than JavaScript freshly delivered by the compromised SaaS.

## 3. Preserve the complete lifecycle

Demonstrate that an independently trusted creator client can:

1. Create an encrypted synthetic Capsule.
2. Commit its release contract.
3. Arm it.
4. Submit a check-in.
5. Verify independently retained presence.
6. Inspect authoritative status.
7. Disarm before irreversible release.
8. Recover from the loss of the consumer SaaS.

Every action must use the same public protocol.

The Laravel product remains a consumer of that protocol, never its authority.

## 4. Attack the operator boundary

Implement retained, reproducible attacks in which the SaaS operator attempts to:

- Steal or substitute creator signing authority.
- Modify Capsule contents or recipient destinations.
- Forge a check-in or disarm.
- Suppress a genuine check-in.
- Present a false successful acknowledgement.
- Replay an old authorisation.
- Substitute stale protocol state.
- Cause premature release.
- Prevent legitimate release.
- Deliver malicious client code.
- Mislead the creator about which witnesses accepted their evidence.

Classify each result as prevented, detectable, recoverable, or successful.

Do not collapse these categories into a single claim of security.

In particular, do not claim protection against censorship unless the creator has an independently reachable submission path.

## 5. Confront malicious custody

The previous generations retained a successful attack: a sufficiently colluding static-share custody quorum can reconstruct the encryption key prematurely.

This is not resolved by strengthening witness quorums.

Investigate alternative custody models and their actual security assumptions, including whether cryptographic enforcement of conditional release is possible without trusting a threshold of custodians.

If the answer requires trusted hardware, stronger cryptographic assumptions, independent organisations, or an unavoidable trust threshold, say so.

Do not invent a cryptographic guarantee that the implementation cannot enforce.

A documented impossibility or trust limitation is a valid research result.

## 6. Maintain radical separability

The protocol, consumer SaaS, transport implementations and hosting architecture remain independent.

Required demonstrations:

- Protocol operation without Laravel.
- Consumer SaaS operation without PorterNet.
- Independent client operation without the consumer SaaS.
- Portable verification of signed evidence.
- Protocol correctness unaffected by transport implementation, subject to explicitly declared delivery and timing assumptions.

Do not implement PorterNet in this generation.

Do not make hosting architecture decisions merely to compensate for an unresolved protocol-security problem.

## 7. The mandatory experiment — The Hostile SaaS

Run a complete Solo lifecycle with a deliberately compromised SaaS.

The creator uses an independently trusted client.

The SaaS attempts to impersonate them, alter their Capsule, forge evidence, suppress valid actions and trigger premature disclosure.

Record exactly what succeeds, fails, becomes detectable and remains unresolved.

Repeat relevant experiments after device loss, witness unavailability and process restart.

Preserve successful attacks permanently as regression cases.

## 8. Deliverables

Provide:

- An updated security and trust-boundary specification.
- A standalone trusted creator client.
- Updated protocol and Laravel integrations.
- Cross-language conformance where relevant.
- Reproducible hostile-operator experiments.
- A documented recovery model.
- A custody-threat analysis with concrete alternatives.
- Measured cryptographic, storage and operational overhead.
- A clear list of guarantees established and guarantees not established.

Use synthetic data and simulated disclosure only.

Do not introduce real-world release destinations.

Do not call the system production-secure.

## Success criterion

At the end of Generation 0.5, we should be able to answer:

**What can a malicious Otherwise operator actually do to a creator's Capsule?**

Not what we hope they cannot do.

What our experiments demonstrate they cannot do, what they can detectably do, and what they can still do successfully.

And we should know which remaining problems belong to:

1. The protocol.
2. The consumer client.
3. The custody implementation.
4. The deployment and hosting architecture.

Those distinctions will determine our next generation.

**Otherwise 0.5 — The Untrusted Operator.**

*The operator runs the service. The operator must not own the promise.*
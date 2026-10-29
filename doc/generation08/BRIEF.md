# OTHERWISE 0.8 — THE LAST WORD

## Finality, revocation, irreversible disclosure and the survival of a promise

Professor, welcome back to the laboratory.

We began Otherwise with a simple question:

*Can someone entrust information to a system that will disclose it only when independently established conditions are met?*

Generations 0.1–0.7 progressively challenged the assumptions behind that question.

We now have independent lifecycle evidence, creator-held authority, distributed custody, a split cryptographic capability and independently verifiable release operations.

Generation 0.7 demonstrated a meaningful improvement: compromising the entire custody domain alone is insufficient to recover the Capsule plaintext, provided the independent authority domain and provisioning assumptions remain intact.

But Generation 0.7 also preserved two significant attacks:

- **Attack U:** Cryptographically related provisioning keys can defeat the apparent independence of custody and authority domains.
- **Attack V:** A finalised check-in window can prematurely prevent the creator from disarming a Capsule even when the Capsule's overall release predicate has not been satisfied.

Attack V is our immediate research target.

However, do not treat it as a mere conditional-branch bug.

It raises a foundational protocol question:

> At what exact point does a creator's authority to revoke a promise end, and a recipient's entitlement to disclosure become irreversible?

This generation must define that boundary, implement it, and test it under adversarial distributed-system conditions.

Our guiding question:

**Can the promise survive the disappearance of the person who made it, without prematurely overruling that person while they are still entitled to change their mind?**

---

# PART I — ESTABLISH WHAT FINALITY MEANS

## 1. Stop conflating different kinds of finality

Identify and formally distinguish at least:

1. **Evidence finality:** A particular observation or witness statement has been durably established.
2. **Window finality:** A check-in window has closed under its defined evidence rules.
3. **Policy satisfaction:** The complete release predicate evaluates to true.
4. **Release authorisation:** An authoritative decision permits disclosure.
5. **Release commitment:** The protocol has crossed its declared point of irreversibility.
6. **Cryptographic disclosure:** Sufficient capability or plaintext has actually been delivered outside the system's control.

These states may be related, but they are not interchangeable.

A finalised historical window must not automatically make an otherwise revocable Capsule impossible to disarm.

Likewise, a release authorisation certificate must not be mistaken for proof that plaintext has already been disclosed.

Specify the permitted transitions, guards, evidence and actors for each state.

Produce an explicit state machine.

Do not use vague statuses such as `final`, `released` or `expired` without precisely defining their meaning.

## 2. Define the creator's last word

Investigate competing semantics:

**Model A — Authorisation wins**

Once the complete release predicate is durably authorised, a later disarm cannot prevent disclosure.

**Model B — Commitment wins**

A release authorisation may exist, but the creator can still disarm until an independently established release commitment.

**Model C — Disclosure wins**

The creator may disarm until the first irreversible cryptographic disclosure operation.

Compare all three.

For each model, analyse:

- Safety.
- Liveness.
- Creator expectations.
- Recipient expectations.
- Evidence requirements.
- Race conditions.
- Operational complexity.
- Recovery after failure.
- Malicious participant behaviour.
- Ability to establish one globally consistent decision.

Recommend one model based on explicit criteria.

Do not silently assume that the most creator-friendly rule is also the safest or most implementable.

A disarm operation cannot retroactively erase information already disclosed.

We must not promise otherwise.

## 3. Define a verifiable ordering rule

Establish how competing release and disarm operations are ordered.

Investigate a durable, independently verifiable per-Capsule decision log or equivalent consensus mechanism.

The ordering rule must not depend on:

- The SaaS database.
- One custodian's local timestamp.
- Client clock accuracy.
- Network arrival order.
- A single privileged coordinator.
- Whichever participant answers first.

Specify quorum intersection and Byzantine fault assumptions.

Determine whether the existing four-witness committee is sufficient for the proposed ordering and finality guarantees.

Do not assume that a 3-of-4 certificate for an individual fact automatically implements Byzantine consensus or a linearizable state machine.

If the current committee cannot provide the desired ordering guarantees, identify the missing assumptions and compare realistic alternatives.

Explicitly address safety versus liveness under network partitions.

A safe system may have to refuse to decide while insufficient trustworthy participants are reachable.

Do not hide this as an implementation failure.

---

# PART II — ATTACK V MUST DIE

## 4. Reproduce the historical failure

Begin by reproducing Generation 0.7 Attack V without modifying the historical fixture.

Show:

- An earlier check-in window becomes final.
- A subsequent window remains open.
- The complete release predicate remains false.
- The creator attempts a valid disarm.
- The old implementation incorrectly rejects it.

Retain the original attack as a permanent regression test.

## 5. Correct the protocol semantics

Implement the chosen finality model so that historical window finality cannot independently revoke the creator's right to disarm.

Demonstrate that the correction does not permit:

- Disarming after the declared irreversible boundary.
- Rewriting finalised evidence.
- Replaying previously accepted lifecycle operations.
- Reopening an irreversibly committed release.
- Forging a disarm through the SaaS.
- Conflicting release and disarm commitments.

The correction must be reflected in protocol specifications, independent clients, evidence validation and custody operations.

Do not fix only the Laravel interface.

---

# PART III — THE HOSTILE FINALITY LAB

## 6. Construct a deterministic race harness

Build a laboratory in which release and disarm requests can be independently scheduled, delayed, reordered, duplicated, partitioned and crashed.

Use a controlled logical scheduler and explicit protocol events.

Avoid flaky tests based on arbitrary sleeps or assumptions about real-time thread scheduling.

For each scenario, preserve:

- Initial state.
- Participant configuration.
- Message schedule.
- Evidence available to each participant.
- Submitted operations.
- Accepted or rejected certificates.
- Final committed state.
- Disclosure outcome.
- Reproducible attack transcript.

## 7. Mandatory adversarial scenarios

### A — Disarm before policy satisfaction

The creator disarms while a historical window is final but the complete release predicate is false.

The disarm must succeed under the selected policy.

### B — Disarm immediately before release commitment

A valid creator-signed disarm competes with a release operation.

Establish which operation wins according to the protocol's ordering rule.

### C — Disarm immediately after release commitment

The creator submits an otherwise valid disarm after the irreversible boundary.

Verify the declared semantics and ensure all independent participants reach compatible conclusions.

### D — Concurrent disarm and release

Deliver the two operations in opposite orders to different witnesses.

Attempt to obtain contradictory finality certificates.

### E — Network partition

Split the committee into incompatible views.

Attempt to finalise release in one partition and disarm in another.

Preserve safety even if liveness is temporarily lost.

### F — Byzantine equivocation

Have dishonest witnesses sign conflicting histories, replay certificates and misrepresent the latest evidence head.

Determine whether conflicting irreversible decisions can be produced.

### G — Delayed valid check-in

A genuine check-in is accepted by some participants but reaches others late.

Determine whether it prevents release under the defined acceptance and finality rules.

Distinguish a valid submitted operation from one merely created locally but never durably accepted.

### H — Malicious SaaS censorship

The SaaS suppresses a disarm, fabricates an acknowledgement and presents stale status.

The independent creator client must detect false claims where evidence permits and retain a direct protocol submission route.

Do not claim censorship is prevented merely because it is detectable.

### I — Restart at the commitment boundary

Crash participants before and after durable release commitment.

Verify recovery without contradictory decisions or duplicate unauthorised disclosure.

### J — Committee replacement

Replace witnesses or authorisation participants during a pending release.

Determine how membership epochs, old certificates and new authority interact.

### K — Malicious custody quorum

Compromise all custody participants.

Verify that 0.7's split-capability confidentiality property remains intact under the stated assumptions.

### L — Combined-domain collusion

Compromise sufficient custody and authority participants.

Retain successful premature-disclosure attacks.

Do not claim that protocol ordering prevents colluding secret holders from bypassing the protocol.

### M — Creator disappears permanently

Stop all creator activity.

Allow the release predicate to become satisfied under the legitimate evidence rules.

Demonstrate that authorised disclosure remains possible without the creator, the SaaS or a surviving creator device.

### N — Creator returns after disclosure

Submit a validly signed disarm after plaintext has already been released.

Document precisely what the system can and cannot revoke.

### O — Contradictory evidence recovery

Restore a participant from an old snapshot while others retain newer finality evidence.

Attempt rollback, replay and forked histories.

---

# PART IV — CRYPTOGRAPHY MUST RESPECT THE DECISION

## 8. Bind disclosure to finality

Integrate the chosen irreversible decision certificate into the Generation 0.7 split-capability custody protocol.

Every legitimate release contribution must be bound to:

- Capsule identity.
- Capsule commitment.
- Policy version.
- Recipient identity.
- Key epoch.
- Evidence state.
- Final release decision.
- Committee membership epoch.
- Release operation identifier.

Independently verify the certificate before honest participants produce release contributions.

But preserve the critical distinction:

**A signed finality certificate can constrain honest protocol participants. It cannot cryptographically restrain a malicious combined quorum already possessing every indispensable secret.**

Document which security properties depend on honest enforcement and which follow from missing cryptographic capability.

## 9. Revisit Attack U

Attack U demonstrated that apparently independent keys can be related in a way that destroys the intended separation.

Investigate whether our selected provisioning process adequately establishes independent secret generation.

Test:

- Related private scalars.
- Reused entropy.
- Malicious dealer.
- Substituted public keys.
- Incorrect share commitments.
- Cross-domain key reuse.
- Backup systems exposing both capabilities.

Do not allow a finality redesign to distract from a known confidentiality weakness.

A full distributed key-generation redesign is not mandatory for this generation, but the attack must remain reproducible and the recommended provisioning boundary must be explicit.

---

# PART V — SURVIVING THE CREATOR

## 10. Define survival as a measurable property

A Capsule survives its creator only if:

1. Its policy remains interpretable.
2. Its evidence remains independently recoverable.
3. Its required cryptographic capabilities remain available.
4. Legitimate release remains possible.
5. Unauthorised release remains constrained by the declared threat model.
6. The intended recipient can verify and recover the disclosed information.

Test these properties separately.

## 11. Long-lived protocol obligations

Investigate what happens when a Capsule must survive years or decades.

Consider:

- Witness retirement.
- Custodian retirement.
- Lost signing keys.
- Cryptographic algorithm deprecation.
- Protocol version upgrades.
- Expired credentials.
- Infrastructure migration.
- Recovery of historical evidence.
- Administrative succession.
- Lost recipient keys.
- Permanent disappearance of the SaaS provider.

Do not solve all of these immediately.

Produce a dependency and recovery matrix identifying which failures are recoverable without creator participation, which require pre-authorised succession rules, and which are fatal.

Avoid introducing a recovery administrator who can unilaterally rewrite the creator's intent.

## 12. Recipient independence

A recipient must not have to trust a SaaS screen claiming that release was legitimate.

Investigate a portable release package containing:

- Capsule and ciphertext commitments.
- Applicable policy.
- Evidence certificates.
- Finality certificate.
- Relevant committee identities.
- Authenticated cryptographic contributions.
- Recipient-bound release material.
- Verification instructions.

The recipient should be able to validate the package independently.

If the release package cannot prove some aspect of real-world truth, state that limitation.

---

# PART VI — AVAILABILITY AND RECOVERY

## 13. Preserve Byzantine-aware collection

Retain the improved concurrent witness and custodian collection introduced in Generation 0.7.

Malformed, duplicated or malicious minority responses must not poison an otherwise valid quorum.

Test bounded timeouts, cancellation, retries, participant replacement and durable recovery.

Do not weaken verification to improve availability.

## 14. Formalise the safety/liveness trade-off

Define at least:

- No conflicting irreversible decisions.
- No disclosure before a valid release commitment by honest participants.
- Eventual release when conditions are met and sufficient honest participants remain reachable.
- Eventual disarm when the creator is authorised and sufficient honest participants remain reachable.
- Recovery from temporary partitions without rewriting finalised history.

For each property, state the exact synchrony, fault and availability assumptions.

If a property cannot be guaranteed simultaneously with the others, document the trade-off.

Investigate formal state-machine modelling using TLA+, PlusCal, Alloy or a similarly suitable method if practical.

A bounded model checker would be especially valuable for discovering contradictory finality states.

Do not treat passing simulation tests as a proof of all possible executions.

---

# PART VII — THE EXPERIMENTAL RECORD

## 15. Retain historical research

Run all existing Generation 0.1–0.7 regression and conformance suites.

Preserve attacks U and V as historical counterexamples.

Preserve the successful combined-quorum disclosure attack.

Do not rewrite old results to make the new architecture look better.

## 16. Measure performance

Compare Generation 0.7 and 0.8 for:

- Check-in.
- Disarm.
- Release authorisation.
- Release commitment.
- Finality verification.
- Cryptographic disclosure.
- Recipient verification.
- Recovery after restart.
- Recovery after partition.
- Witness and custodian response collection.

Record network messages, durable writes, storage overhead and additional administrative dependencies.

Distinguish local cryptographic cost from coordination cost.

Do not extrapolate local Docker performance to geographically distributed deployments.

## 17. Deliverables

Produce:

1. `RESEARCH-0.8.md` — finality models, comparison and selection.
2. `PROTOCOL-0.8.md` — formal lifecycle and irreversible boundary.
3. `FINALITY-LAB-0.8.md` — adversarial schedules and retained outcomes.
4. `SURVIVAL-0.8.md` — long-term continuity and recovery analysis.
5. `SECURITY-0.8.md` — guarantee matrix and remaining attacks.
6. `BENCHMARKS-0.8.md` — measured costs.
7. Updated protocol implementation and independent clients.
8. State-machine diagram and, if feasible, model-checking artifacts.
9. Reproducible test scripts and conformance vectors.
10. Concise executive report identifying what changed, what survived and what remains unsolved.

Follow existing repository conventions where appropriate.

Use synthetic Capsules and simulated disclosure only.

Preserve protocol independence from Laravel and all specific hosting arrangements.

No PorterNet integration.

---

# PART VIII — THE FINAL EXAMINATION

Conclude by answering:

**Q1.** When does a creator definitively lose the ability to disarm?

**Q2.** Can independent honest participants verify that moment?

**Q3.** Can conflicting disarm and release decisions both become final?

**Q4.** What happens if the network partitions at the worst possible instant?

**Q5.** Can a malicious SaaS make a creator believe a disarm succeeded when it did not?

**Q6.** Can the creator disappear permanently without making legitimate release impossible?

**Q7.** Can a recipient independently establish that disclosure was authorised?

**Q8.** What happens when committee members disappear permanently?

**Q9.** Does any new component acquire unilateral power to rewrite or release a Capsule?

**Q10.** What does a malicious combined cryptographic quorum still achieve?

**Q11.** Which security properties have been experimentally demonstrated, which formally modelled, and which remain assumptions?

**Q12.** What is the smallest set of unresolved problems preventing a credible real-world pilot?

---

# SUCCESS CRITERIA

Generation 0.8 succeeds if:

- Attack V is reproducibly corrected.
- The creator's revocation boundary is precisely defined.
- Honest participants cannot finalise contradictory irreversible decisions under the stated fault assumptions.
- Valid release remains possible after the creator disappears.
- The Generation 0.7 confidentiality boundary is preserved.
- Recipients can independently verify release evidence.
- Remaining successful attacks and operational limitations are explicitly retained.

A negative result is acceptable if it exposes an unsatisfied distributed-consensus assumption or an impossible combination of requirements.

Do not hide uncertainty behind an apparently deterministic state machine.

Do not invent global ordering where the network cannot provide it.

Do not confuse an absent creator with a creator who has irrevocably surrendered authority.

And above all:

**The creator must have the last word until the protocol can prove that the last word has already been spoken.**

Go find that boundary.

Then make every participant disagree about where it is.
# Otherwise 0.3 — The Retained Witness

Research run: 19 October 2026. This extends the existing repository. Generations 0.1/0.2, their fixtures, failure reports and successful attacks remain executable. The new implementation is a static, finite-window feasibility profile, not a SaaS or a production independent-administration deployment.

## The result

Three witnesses can prevent the application plus one dishonest/forgetful witness from manufacturing absence after an accepted presence, **if release requires all three witnesses** and honest witnesses retain irreversible per-challenge fences. Two witnesses suffice to acknowledge presence; one silent witness therefore need not prevent check-in, but it prevents release.

We first produced the requested counterexample. With acceptance `{A,B}` and absence `{B,C}`, B can sign both and ordinary 2-of-3 majority overlap does not protect against one Byzantine signer. Both naive certificates verify. The production verifier rejects that quorum configuration. The full signed attack objects are permanent fixtures under `Protocol/vectors/generation03.json`.

The revised model does not claim consensus. There is no shared event sequence, leader, voting round or global “first” observation. The operation identity is stable; a certificate hash identifies a particular proof bundle, not a globally unique ordered authorisation event. Custody responses bind the exact bundle and operation. No exactly-once external delivery claim is added.

## Why the new intersection is sufficient

For N witnesses, presence quorum P and absence quorum A, any two quorums overlap by at least `P+A-N`. To ensure that overlap contains an honest member under at most f dishonest identities, require:

```text
P > f
P + A > N + f
```

An honest witness refuses ABSENT after retaining presence, and refuses a new observation after closing the slot. If both certificates existed, every member of their intersection would have violated such a fence. An intersection larger than f contradicts the fault assumption.

For `N=3, P=2, f=1`, absence therefore needs `A>2`, so A=3 is the minimum threshold in this independent-certificate/local-fence model. This is an instance of the standard honest-quorum-intersection argument, not a new cryptographic result. [Malkhi and Reiter, Byzantine Quorum Systems](https://malkhi.com/files/byzquorums-STOC1997.pdf).

A receipt is a witness's signed statement about retention. Two receipts do not prove two physical disk writes when a signer may lie. With f=1, an accepted two-receipt certificate guarantees at least one honest durable holder; requiring all three for absence forces that holder into any attempted release quorum. We must not confuse the signature with objectively true storage behaviour.

The availability price is decisive. An unavailable or maliciously withholding witness can block release forever. For independent unavailable witnesses u and Byzantine signers that may withhold f, guaranteed progress requires enough honest reachable nodes (`quorum <= N-f-u`). This profile does not provide Byzantine-tolerant release liveness. It chooses safety over timely disclosure.

## Boundaries of a check-in

1. The creator submits a signed, manifest/contract/challenge-scoped proof. The request alone establishes nothing.
2. Each witness validates the proof against its own bounded time sample, appends one immutable receipt/state transition and commits with SQLite synchronous=FULL. Only after commit does it return the signed observation. A lost response does not erase that observation.
3. Two distinct qualifying receipts for the same proof constitute acceptance. They may be recovered and assembled after the deadline; the receipt's original observation window determines eligibility.
4. `CheckInClient.check_in` validates the certificate and fsyncs its aggregate cache before returning a verifiable acknowledgment to the creator. No second human authoriser is involved.

If only one honest receipt exists, the creator cannot demonstrate quorum acceptance, yet that observation may still veto unanimous absence. This conservative pending state sacrifices release liveness. If a Byzantine receipt issuer later refuses to reproduce its receipt and no client copy survives, recovering the original aggregate may be impossible even though the honest holder still prevents absence. Certificate availability and release safety are distinct.

A cached certificate is historical evidence of acceptance. Proof expiry after a timely observation does not erase that fact. A proof already expired at observation is rejected; a correctly signed expired example is in the corpus. An old receipt cannot satisfy another challenge, policy, Capsule, operation or new commitment.

## What the witnesses remember

Each service has a randomly generated identity, a private volume, an independent per-Capsule receipt lineage and immutable per-slot state. Identical retries recover the original signed receipt. Changed bytes under an observed submission ID fail. Slot keys are unambiguous canonical tuples, not delimiter-concatenated identifiers.

Observation receipt sequences are local to a witness. Retaining a peer's receipt does not silently promote it into a new local timely observation. Peer receipts instead expose later forks, conflicting finalisations or restoration of a shorter local history. Conflicting records are retained as evidence and identify the source; a peer's equivocation does not quarantine unrelated honest local state.

The rollback test restores the complete witness SQLite database, including its local anchors, while peers keep their own databases. Sending an independently retained missing receipt back to the restored signer exposes the rollback. That signer quarantines itself and cannot mint new finalisations. Automatic reconstruction/identity rotation is not implemented; operator omission can delay detection. The remaining honest receipt holder still prevents a release certificate while f<=1. Rolling back all independent holders is outside the guarantee.

## Absence and compact custody

Each committed slot closes after its deadline plus the committed discrete-second grace. A witness signs FINAL with its retained proof/value, or a bounded statement that it has no qualifying local observation. Its silence is not a finalisation and cannot fill a certificate slot.

The release object must include finalisations from all three witnesses for **every committed slot**, in manifest slot order. The application cannot present a convenient subset of history. An absence slot is true only with three ABSENT records. Attestation slots require consistent positive proof at final evaluation time; contradictory or missing final support supplies no positive leaf. The existing AND/OR/THRESHOLD expression combines these contract results.

Custodians independently verify this compact proof in Python and JavaScript, including owner commitment, signers, authority proofs, slot coverage, timing, grace, operation, ciphertext and authorisation hash. They do not download the entire observation lineage or accept an application “approved” boolean. Complexity is proportional to committed slots/witnesses, not constant size. Static sharing remains a separate 2-of-3 custody layer.

A custodian holding a valid presence certificate rejects a conflicting absence release even when the witness fault bound is exceeded. A malicious custody quorum can still combine its recoverable shares without policy; the Generation 0.2 successful attack is rerun and remains applicable. This generation has not made shares mathematically conditional on an obligation.

## Observed experiments

See [raw new tests](../results03/tests.txt), [portable results](../results03/conformance.txt), [performance](../results03/performance.json), [full run](../results03/complete-run.txt), and [preserved previous-generation run](../results03/previous-generations.txt).

| Experiment | Actual outcome |
| --- | --- |
| Majority counterexample | Genuine signed 2/3 presence and 2/3 absence objects both passed the deliberately unsafe checker with B equivocating. The supported profile rejected them. |
| A — Lost acknowledgment | A child application process exited after two witness commits, before acknowledging the user. Retry recovered those exact receipts, persisted a verifiable aggregate on a dedicated client volume, verified it in a restarted client process without network access to witnesses, and remained idempotent while the third witness was unavailable. |
| B — Forgotten witness | Whole-database restoration removed local presence. A peer's retained signed receipt exposed the shorter lineage; the restored signer quarantined itself and release failed closed. |
| C — Fabricated absence | The application plus one witness replaced that witness's finalisation with ABSENT. The honest presence holder prevented a positive release result. |
| D — Equivocation | Observation followed by a conflicting signed finalisation was retained as evidence against its source. Honest local state remained usable. |
| E — Partitioned groups | The check-in side obtained two receipts. The release side obtained only two finalisations and could not authorise release. This is controlled endpoint/message-view partitioning, not a kernel network-failure experiment. |
| F — Late witness | Receipt at the inclusive deadline was valid. Another witness receiving after the deadline refused. One timely receipt did not form acceptance, but conservatively blocked unanimous absence; its original receipt remained recoverable later. |
| G — Silent witness | Only two final records existed; no release. No silence-to-absence conversion occurred. |
| H — Identity/replay | Forged signatures, invalid signer identities, changed challenge/Capsule, wrong contract revision and receipt substitutions failed. Identical replay recovered the original evidence. |
| I — Custodian doubt | Two deliberately compromised witnesses produced a cryptographically valid conflicting certificate outside f=1. All informed custodians vetoed it using their retained accepted presence. |
| J — Solo | One human completed acknowledged/repeated presence with no release; a separate missed-next-challenge path completed grace and automatic threshold custody recovery; disarm before finalisation blocked another Capsule. |
| K — Council | A/B true and C false, independently observed and finalised through the same code, satisfied 2-of-3 policy and recovered with two different custody services. |
| L — Hostile recovery | Actual witness processes exited before and after SQLite commit, restarted with persisted identities, and replayed requests. Before-commit facts were absent; committed receipts survived and remained idempotent. No conflicting release formed. |

The new suite has 13 test methods (the counterexample plus A–L). Prior 20+21 tests, previous successful attacks and the earlier portable corpus are rerun. The witness corpus includes fixed keys/signatures, conflicts, complete finalisations, malformed/scoped/expired proofs and reordered receipt checks. No Python/JavaScript disagreement was observed. A receipt-deletion shrinker is present but was not activated by an observed language disagreement.

## The eight answers

**1. Can the creator prove their check-in counted?** Yes: a quorum certificate of scoped signed observation receipts is independently verifiable, and the client persists it before acknowledging success. Lost acknowledgments are recoverable when enough receipt holders or retained copies remain reachable. That is a proof about accepted cryptographic evidence, not life or health.

**2. Can a compromised operator erase accepted presence from effective release history?** Not under the declared f<=1 witness model. An honest holder lies in every attempted release quorum and refuses absence. With two compromised/forgetful witness identities the test demonstrates conflicting certificates; no unconditional erasure resistance is claimed.

**3. How many witnesses must be trusted?** At least two of the three must obey the retention/finalisation/time rules; the client need not know which two. At least one honest durable holder is guaranteed inside an accepted two-receipt quorum. This is an independent-administration assumption, not a property achieved by putting three containers on one laptop.

**4. Can valid presence and absence certificates coexist?** Not for the same slot under f<=1 and the local-fence assumptions. Yes for the naive 2/2 profile with one equivocator, or for the supported thresholds when two witnesses violate the bound. The successful attacks are preserved. Cryptographic validity alone cannot reveal every hidden fault; informed custody has an additional evidence veto.

**5. What if witnesses disagree or cannot be reached?** Acknowledgment requires sufficient matching proof receipts. Release requires every finalisation group; missing, contradictory, quarantined or withheld support blocks release. Multiple accepted attestation statements do not establish one globally ordered truth. No hidden timeout elects absence. Availability and quarantine recovery remain deliberately limited.

**6. Can custody verify eligibility without trusting app interpretation?** Yes for this profile: a complete slot-bound finalisation object is checked independently in both languages, along with retained contradictory presence. This depends on witness honesty/time assumptions and a non-colluding custody quorum. It does not make raw shares non-recoverable by malicious holders.

**7. Same mechanism for Solo and Council?** Yes. The same generic observe/finalise/certificate/custody path handles presence and boolean attestations, and the original expression model selects one absence contract or a Council threshold. Technical witnesses are not extra human trustees.

**8. What does independence cost?** Actual modest-workload costs are tabulated in [PERFORMANCE.md](PERFORMANCE.md): additional durable commits and roughly kilobyte receipts/certificates, optional peer-retention overhead, restart recovery and independently verified custody latency. These local measurements are not Internet/mobile performance predictions. Most significantly, one silent required witness can delay release forever.

## Scope and next generation

The services are separate Docker processes/volumes with distinct capabilities, not independent organisations or hosts. Provisioning/creator code, host/daemon administration and private-network transport remain trusted. The new integration uses controlled clocks; inherited real-clock tests do not turn this profile into a production UTC/partition authority. Tests kill processes at explicit write boundaries, not disks during power failure. No full SaaS, real delivery or sensitive information was introduced.

This generation establishes the smallest tested local-fence/intersection mechanism that protects retained presence at N=3/P=2/f=1: require A=3 and accept the availability loss. Generation 0.4 should investigate whether a larger independent committee can recover availability without weakening retention, while specifying membership, repair, clocks and direct creator receipt distribution. [Proposal](GENERATION_0_4.md).

# Executable conformance profile 0.1

Run `./scripts/experiment.sh`. Expected exit status is zero. Tests use real Ed25519 signatures, authenticated encryption, temporary databases, actual competing threads/connections and a deterministic clock. Conformance is conditional on the authority, clock and storage assumptions in PROTOCOL.md; a passing suite is not a mathematical proof.

## Invariants exercised

1. **Scope:** accepted evidence binds Capsule ID, policy commitment, contract ID/revision, authority, schema and validity window. Sharing an authority does not share evidence across contracts (L, Q, T).
2. **Interpretation:** AND/OR/THRESHOLD consume independently evaluated contract results. Repeated leaves cannot inflate thresholds. Missing, stale, expired, revoked and contradictory proofs provide no positive attestation result (J, K, L, M).
3. **Timeliness:** presence at the authoritative inclusive deadline blocks that challenge's absence result; a message reaching the authority after the boundary is rejected (A, P).
4. **Receipts:** retrying identical accepted evidence returns the original receipt; changing bytes under that ID cannot create another acceptance (C, K).
5. **Grace:** authorisation requires healthy armed state, satisfaction now and continuous satisfaction throughout a persisted grace interval. Recovery or intervening false intervals restart grace (D, G, O, R).
6. **Atomic decision:** multiple workers recover a single authoritative authorisation. A committed disarm and authorisation cannot coexist (B, F).
7. **Delivery separation:** authorisation survives simulated adapter failure, and retry produces one simulated recipient insertion and one RELEASED event (E).
8. **Fail-closed corruption:** altered, deleted, reordered or truncated facts and changed policies cannot silently produce authorisation (H). Altered ciphertext cannot produce delivered plaintext (N).
9. **Independent reading:** a second implementation derives contract results, expression truth and release eligibility without importing reference decision logic; both agree on tested normal, boundary and hostile snapshots (J, plus decision comparisons across the suite).
10. **Transport semantics:** failed notifications are observations only; absence satisfaction occurs only after the contractual deadline (I).
11. **Immutability:** no update operation can replace a committed policy; duplicate Capsule creation fails, invalid expressions fail validation and unsigned owner transitions fail (M).
12. **Per-owner recovery:** an owner's recovery cannot clear another Capsule's uncertainty latch (R).

## Required facts for independent replay

Export includes canonical policy, commitment, complete accepted/rejected/lifecycle history, trusted head, authoritative time and health projection. Verify the commitment, sequence, chain and trusted anchor before treating an export as authoritative. To reconstruct an authorisation, replay only events before AUTHORISED at its recorded time and check the recorded snapshot head and commitment. The independent evaluator deliberately assumes validated authoritative facts; it is an independent **semantic interpreter**, not an independent acceptance service, JSON parser, signature verifier or custodian.

## Scope of experiments

A–J are the founding adversarial experiments. K–T extend them for composed contracts, continuous grace and recovery isolation. Controlled ordering and real SQLite competition are both used. Synthetic multiple entities have independent generated keys in the critical 2-of-3 test; organisational independence is not proven by the engine.

A conforming implementation may use another database but must preserve durable authoritative ordering, the deadline boundary and immutable snapshot semantics. No reliance on SQLite SQL syntax is normative. Unknown semantic versions must be rejected, not interpreted as the latest known version.

---

# Generation 0.2 profile

Run `./scripts/experiment02.sh`. It builds a disposable, uniquely named Docker cluster, reruns all original 20 tests, starts the witness, three isolated custodians and adversarial app, runs `tests02`, checks portable conformance and runs both CLI scenarios. It then removes only its own containers/volumes. Logs are in `doc/results02/`; old `doc/results/` observations remain preserved.

## Fixed corpus and independent implementation

`Protocol/vectors/generation02.json` contains fixed **public test-only** private seeds, public identities, policy/contract versions, signed evidence, owner commands, complete histories, rejected submissions, inclusive deadline and grace cases, disarm-first and release-first states, outage/recovery and the continuous-grace gap. It also includes a signed version-2 custody manifest and a signed witness bundle. Test keys confer no authority over randomly provisioned runtime services.

`Verifier/verify.mjs` is an independent JavaScript prefix state machine using Node's built-in Ed25519/SHA-256 implementation. It does not invoke Python or import its decision code. Its approach reconstructs lifecycle state and partitions time at predicate transitions. Python's separate verifier validates snapshots using its original independent interpreter. Custodians run both and require agreement before releasing a share.

`scripts/conformance02.py` checks the 14 fixed vectors and 180 generated nested/adversarial snapshots, rejects duplicate JSON object names in both parsers and compares complete results/eligibility/authorisation. On disagreement it greedily deletes events while preserving the mismatch and prints the minimal retained counterexample into the captured log. No cross-language disagreement was found in the recorded suite; shrinking exists but was not needed for an observed language mismatch.

Regenerate fixed vectors only intentionally, then review the diff:

```sh
docker compose build experiment
docker compose run -T --rm experiment python scripts/make_vectors02.py > /tmp/otherwise-vectors.json
cmp Protocol/vectors/generation02.json /tmp/otherwise-vectors.json
```

## Required scenario conformance

**Solo Witness:** one owner/absence authority, timely first presence, missed second challenge, observed grace, witnessed permission, two automatic custody responses and simulated delivery. Separate branches cover disarm and same-owner outage recovery. No second human or trustee approval occurs.

**Council:** A and B submit positive signed evidence; C submits negative/contradictory evidence. Policy authorises 2-of-3 after grace. A different pair of custody services releases the shares. The policy participants' keys differ from custody service keys.

## Additional invariants

- A local prepared fact is not an external 0.2 acceptance/authorisation until witness commit; loss of its acknowledgment is idempotently recoverable.
- New witness publications extend its retained prefix and cannot backdate candidates or remove accepted presence.
- An operator-supplied decision/history/URL cannot replace the custodian's pinned witness and independently verified facts.
- Recovery binds the current history head, resets grace and cannot clear another owner's uncertainty.
- Clock discontinuities, cumulative drift, restart, restored state and observation gaps block confident absence-based release until recovery.
- Incomplete custody enrollment cannot arm; retry resumes the same immutable shares; crashes leave only documented prepared/orphan states.
- Valid pre-release history is retained by custodians as well as the witness; contradictory later prefixes fail closed.
- Policy authorisation, share issuance, reconstructed capability and synthetic delivery are distinguishable audit/experiment events. Two colluding share holders are explicitly outside conditional-enforcement guarantees.

These are finite tests under the documented boundary. The real clock adapter is tested with actual system sampling and deterministic injected failures; the full custody scenarios use accelerated controlled service time. No claim of a production real-time acceptance authority follows.

---

# Generation 0.3 retained-witness conformance

Run `./scripts/experiment03.sh`. It reruns all prior generations, including their successful attacks, then starts three independent-storage witness processes and three custody processes in a new disposable Docker project. Actual outputs and measurements are in `doc/results03/`.

Mandatory A–L experiments cover lost acknowledgments, whole-database rollback, fabricated absence with one compromised witness, equivocation evidence, partitioned observer groups, exact/late deadlines, a silent witness, signature/domain attacks, custodians with contradictory retained presence, Solo, Council and actual process exits before/after SQLite commit. An additional signed counterexample establishes that ordinary 2/2 quorum overlap is insufficient with one Byzantine intersection signer. Controlled partitions are represented by restricted reachable endpoint sets/API refusals; this is not a kernel packet-loss or Internet deployment experiment.

`Protocol/vectors/generation03.json` adds fixed signed observations, acknowledgments, finalisations, unsafe and fault-budget-exceeded conflicts, invalid identities, expired observations, wrong challenges/Capsules, rollback lineage, unsigned extensions and custody-operation replay. Keys in the corpus are public TEST-only seeds. Runtime service keys are independently random.

`Verifier/retained.mjs` independently validates proof objects and policy truth in JavaScript without invoking Python. It reuses the established JavaScript canonical-wire helpers, not the Python decision logic. Both interpreters must reject unsafe configurations, duplicate signer identities, incomplete slot coverage, unclosed windows and contradictory retained presence. The conformance runner additionally reorders receipts. On disagreement a receipt-deletion shrinker prints the reduced object to captured output; no observed language mismatch is claimed unless recorded.

Reference Solo: one creator is also the sole presence authority, a timely first check-in receives a durable verifiable acknowledgment, a later missed slot closes after grace, and automatic custodians release to a synthetic recipient. Another branch disarms before closure. Council: three independent contract authorities use the same observe/finalise/certificate/custody machinery; A/B true and C false satisfy the existing threshold expression.

The safety invariant is conditional: accepted presence cannot coexist with an absence-based release certificate for the same slot while at most one of three witness identities forgets/equivocates and honest local fences/time bounds hold. Under a larger fault budget the cryptographic verifiers can accept both; retained custody evidence must still veto that particular conflict. This is an explicit boundary fixture, not a successful enforcement claim.


## Generation 0.4 — independence is executable

Run `./scripts/experiment04.sh`. The standalone image excludes Consumer/PHP/Composer and tests its import graph. Tests cover one-member refusal, two-member failure, retained acknowledgement recovery, whole-DB rollback repair, fresh-checkpoint replay rejection, scope/expiry/duplicate/reordering, independent Council contracts, owner disarm versus competing release workers, explicit custody capability rejection and adapter substitution over real certificate-verifying HTTPS. The external driver stops the actual SaaS/database/adapter containers, isolates a witness network, and restarts a witness process. Fixed version-4 signed objects are checked by Python and Node using `scripts/conformance04.py`; old counterexamples remain in earlier suites.


## Generation 0.5 — hostile operator, preserved success cases

Run `scripts/experiment05.sh`: hostile actual Laravel/courier responses, independent encrypted-vault CLI, fresh signed status, copied/stolen capability attacks, custody reconstruction, interrupted rotation, offline device restoration and real process restart. Fourteen fixed version-5 envelope cases are checked by Python and Node in addition to the unchanged wire-v4 certificate corpus. `Protocol/client05-build.json` is an independently authenticated source-manifest input, not self-authenticating software.

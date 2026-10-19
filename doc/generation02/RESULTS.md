# Generation 0.2 — actual findings

Executed on 15 October 2026 in Docker. Runtime: Python 3.12.15, SQLite 3.46.1, cryptography 46.0.3, PyCryptodome 3.23.0, Node v22.23.3. Shell/openssl prepare disposable service capabilities on the host; all engine, verifier, custody and test execution occurs inside Docker.

```sh
./scripts/experiment02.sh
```

The final run preserved all **20 Generation 0.1 tests** and passed **21 Generation 0.2 tests**. The new suite reported:

```text
Ran 21 tests in 3.608s

OK
```

Portable conformance actually reported:

```text
Fixed signed vectors: 14
Generated nested/adversarial snapshots: 180
Python / JavaScript disagreements: 0
Duplicate-key parser rejection: both implementations
Conformance OK
```

Evidence: [baseline rerun](../results02/generation01.txt), [new tests](../results02/latest-tests.txt), [portable verifier](../results02/conformance.txt), [both demos](../results02/demo.txt), [full run](../results02/complete-run.txt), [runtime](../results02/runtime.txt). Random identities, signatures, Capsule IDs and decision hashes vary; outcome expectations are deterministic. Fixed corpus identities and bytes do not vary.

## Mandatory attacks A–J

| Attack | Observed outcome | Meaning |
| --- | --- | --- |
| A — Compromised operator | App files, database bytes, public manifest and ciphertext supplied to the adversarial app; concrete guessed-key decryptions fail; all three services refuse unsupported release. No bootstrap capability, custody mount or Docker socket is present there. | App compromise alone supplies no decryption key under the stated separation assumptions; finite guesses are not a cryptographic proof |
| B — Forged release | Unsupported AUTHORISED event rejected even after the attacker supplies a matching hash chain; custody refuses. | Operator's asserted policy result is insufficient |
| C — Replayed authorisation | Another Capsule, changed commitment/epoch/payload, modified response and unrelated manifest fail request/recipient checks. | Honest participation is scope-bound; this does not make raw static shares inherently snapshot-specific |
| D — Missing custodian | Service 2 is deliberately made unavailable at its protocol API; the client encounters the refusal and automatically recovers using 1 and 3. One share and repeated indices fail. | A live honest pair suffices; two missing services block recovery |
| E — Colluding custodians | Two administrator-compromised services export their shares; direct reconstruction decrypts **before authorisation**. | Successfully bypassed conditional software policy; this is a retained limit, not a passing security claim |
| F — Rewritten history | Restore the entire pre-presence app database; a new locally valid absence/release history is rejected by the witness; custodians refuse. Reconciliation restores the accepted presence prefix. | Independent retained history catches what local hashes cannot |
| G — Solo Witness | One human's timely first presence, missed second obligation, grace, release and recovery run automatically through custody; separate disarm path prevents release. | One authoriser can use multiple custodians without trustee approvals |
| H — Council | A/B positive, C contradictory; policy authorises after grace; custody services 2/3 release independently of policy authorities A/B. | Policy threshold and custody threshold are distinct |
| I — Emergency disarm | Disarm, authorisation and a custody request compete. A disarm winner issues no capability; an externally authorised winner can recover. Later disarm fails, and a retained first share plus later second share still decrypts. | External permission and possession of a quorum are separate irreversible thresholds |
| J — Broken authority | Simulated unavailable witness refuses new recovery. After explicitly compromising the witness as well as the app, a fabricated complete absence history obtains shares if custodians never saw the accepted presence. | Signatures/semantic consistency do not prove completeness against a corrupt observation authority |

## Additional evidence

Lost witness acknowledgments recover the original accepted fact. Partial enrollment cannot publish/arm; retry resumes the same shares. Custodian enrollment committed before its lost acknowledgment is idempotently recoverable.

Actual child processes exit after ciphertext fsync, during the pre-commit SQLite transaction, and after local commit. Reopening confirms orphan-only states before commit and a valid prepared Capsule after commit. These are real process exits, not power-loss/storage-controller tests.

The real clock adapter is sampled against the system clock and tested with injected backwards motion, forward jumps, cumulative drift, negative monotonic movement, long pauses, restart and restored state. A functioning witness clock with app heartbeats absent across entire windows blocks release until fresh owner recovery. Another owner's recovery cannot clear a Capsule's latch. Old head-bound recovery commands are rejected.

A local prepared authorisation lost before witness publication is refused by custody; restoring the witnessed projection allows disarm first. This distinguishes local SQLite success from 0.2 authoritative permission.

Two custodians that observed valid presence retain that prefix even when release was refused. A subsequently compromised witness offering a rewritten absence history cannot persuade those two; the uninformed third may supply one share but not a sufficient quorum. This directly contrasts with J's successful attack on previously uninformed custodians.

Grace is measured from the **latest possible independent observation**. With first observation interval `[t,t+2]` and grace 5, release is withheld at `t+5` and allowed at `t+7`. The witness retains/signs the candidate observation upper bound; a local endpoint comparison cannot shorten it.

## Failures found and corrected

**History-reference counterexample.** The stricter verifier rejected the inherited continuous-grace reset history with `ValueError: unsupported candidate`. After recording CANDIDATE_RESET, the next candidate still referenced the pre-reset head. The engine now references the actual immediate pre-candidate head. Its original grace delay was enforced, but its audit snapshot reference was wrong. [Preserved failure](../results02/history-binding-counterexample.txt). Fixed-vector continuous-grace histories now pass both verifiers.

**Recovery ordering counterexample.** A paused app correctly blocked release, but the first recovery implementation cleared its latch and then re-applied the same prior heartbeat gap. Recovery failed with `witness uncertainty requires recovery`. The fix observes the gap first, then applies the fresh recovery. [Preserved failure](../results02/recovery-counterexample.txt). The real-adapter regression now passes.

**Recovery freshness review.** Legacy action-only owner signatures did not identify a particular outage. Version-2 owner commands now bind the current history head; the witness refuses legacy recovery for this profile, and a replay after another outage is tested and rejected. This was an interface review finding, not a reported cross-language disagreement.

No Python/JavaScript semantic disagreement was observed. An automatic event-deletion shrinker is implemented and would print a minimized mismatch into captured output; it was not exercised by a real language disagreement. Neither successful malicious-quorum reconstruction nor compromised-witness fabrication is “fixed” by the above corrections.

## The six research answers

**1. Can one human use conditional release without managing several custodians?** Yes in the demonstrated integration: the client automatically provisions infrastructure custody; only the creator's policy/presence/recovery actions are human authorisation. The trusted provisioner still manages infrastructure capabilities behind the CLI. No production consumer onboarding is claimed.

**2. Can independent custody prevent the compromised application operator decrypting early?** In this bounded model, app storage contains no complete key, and honest services refuse early shares. This relies on trusted client provisioning, protected separate custody/witness state and fewer than two colluding custodians. The common Docker host administrator can defeat the experiment; genuine independent organisations and protected transport were not deployed.

**3. Can custodians distinguish valid release from an operator-fabricated decision?** They reject unsupported signatures, lifecycle, scope, time, policy, grace and conflicting retained histories. They cannot establish the completeness of a fabricated absence history when every relevant observation authority is compromised and no independent previous checkpoint survives. Experiment J demonstrates that negative answer.

**4. Can a witness detect rewritten/rolled-back history?** Yes when its independent prefix remains intact: the complete app rollback is detected. Informed custodians add additional surviving anchors. If all relevant retained states/signing authorities are compromised or restored consistently, there is no unconditional detection guarantee.

**5. Can missing evidence be decided defensibly under unreliable clocks/networks/services?** Only relative to explicit bounds and observation assumptions. The adapter and heartbeat model can identify tested uncertainty and withhold/restart grace; they do not authenticate UTC, bound physical fsync latency, or detect a partition affecting only the creator. Full integration uses accelerated controlled time; source-injected real-adapter tests are not a production timing proof. Availability and prompt release are sacrificed during uncertainty.

**6. What if authorities disagree, collude or disappear?** Conflicting retained prefixes, verifier disagreement, witness unavailability or insufficient shares withhold new recovery. One missing custodian is tolerated. A malicious custody quorum decrypts early. A compromised witness plus app can fabricate unobserved absence. Already issued capabilities cannot be recalled, and infrastructure/terminal restart recovery is incomplete. These are distinct outcomes, not one general “distributed safety” guarantee.

## What survived

The one-human product anchor survives alongside Council policies. The application can operate on ciphertext without holding the complete key. Honest custody services can enforce independently verified, witnessed decisions and reject a lying app. Independently retained history makes full local rollback observable. Cross-language interpretation is feasible across the checked corpus.

What did not survive as an unconditional claim is that distributing static shares forces policy, or that an internally valid absence history proves no evidence was concealed. Generation 0.3 should distribute retained acceptance receipts before relying on silence, establish real administrative independence/protected transport, and close the clock/recovery gaps. [Proposal](GENERATION_0_3.md).

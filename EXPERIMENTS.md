Generation 0.3 results, quorum counterexamples and actual measurements are in [doc/generation03/RESULTS.md](doc/generation03/RESULTS.md). All prior experiments remain below and executable.

Generation 0.2 results are recorded separately in [doc/generation02/RESULTS.md](doc/generation02/RESULTS.md). The original Generation 0.1 observations below remain preserved.

# Observed results — Generation 0.1

Run date: 14 October 2026. Execution: Docker Desktop, Linux ARM64 container, Python 3.12.15, SQLite 3.46.1, cryptography 46.0.3. No test or demo software was installed or executed on the host. Host Python was used only to edit source files. See [runtime output](doc/results/runtime.txt).

Reproduce:

```sh
./scripts/experiment.sh
docker compose run --rm experiment python scripts/grace-counterexample.py
```

The final suite actually reported:

```text
Ran 20 tests in 3.827s

OK
```

[Full final test output](doc/results/latest-tests.txt), [demo and complete audit](doc/results/latest-demo.txt), [build and full run output](doc/results/complete-run.txt). Timings, generated public keys, signatures and decision hashes naturally vary across runs.

## Founding experiments

| Experiment | Actual observation | What it establishes in this laboratory |
| --- | --- | --- |
| A — Last-Second Witness | Presence accepted at t=10 blocks absence; second timely round also blocks absence. Submission reaching authority at t=21 for deadline 10 is rejected; grace then permits release. | Inclusive authoritative deadline; front-end arrival is not acceptance |
| B — Competing Executors | 24 calls on eight competing workers recover the same decision; one AUTHORISED event exists. | At most one authoritative decision under SQLite ordering |
| C — Forgotten Receipt | Retry recovers original acceptance sequence; changed bytes under same ID raise an error; one acceptance exists. | Durable receipt recovery and collision rejection |
| D — Dead Scheduler | Declared outage at t=30 blocks release after engine reopen; owner recovery requires a new grace, releasing at t=35 rather than t=34. | Explicit outage uncertainty and fresh observation/grace; not automatic real outage detection |
| E — Double Release | Injected crash after durable inbox insertion but before audit acknowledgement; reopened engine retries and yields one insertion and one RELEASED event. | Idempotency for this simulated recipient, not arbitrary real providers |
| F — Emergency Disarm | Both controlled serial orders and a concurrent attempt end with exactly one terminal outcome. Disarm first blocks release; authorisation first rejects disarm. | Durable authority order determines the winner |
| G — Broken Clock | Negative time/rollback rejected; excessive forward jump blocks authorisation; signed recovery restarts grace. | Limited controlled-clock fault handling; no gradual-drift/freeze protection |
| H — Corrupted History | Deletion, alteration, reordering, tail truncation and policy alteration all raise errors before authorisation. | Tested corruption fails closed against unchanged trusted anchors |
| I — Unreachable Creator | Failed notification changes no contract result. Missing presence becomes an absence result after the deadline and ultimately permits release. | The engine does not know why the creator is silent; availability can affect disclosure |
| J — Independent Interpretation | Two separately written interpreters agree over 40 seeded AND/OR/THRESHOLD histories, each observed at four times. Release eligibility is also compared independently across worker calls elsewhere in the suite. | Tested semantic agreement from identical authoritative snapshots |

## Composed-contract extensions

K tests all six A/B/C submission orders and duplicates. A and B are positive; C is negative, then contradictory. C remains unsatisfied while A/B authorise the 2-of-3 result. C cannot veto unrelated positive contracts.

L tests wrong-authority signature rejection, authority revocation, proof expiration, stale rejection and final contract expiration. Both evaluators agree on unsatisfied results where insufficient positive contracts remain.

M rejects invalid/repeated-leaf expressions, replacement Capsule creation and invalid owner signatures. N flips an encrypted payload byte; AES-GCM authentication fails and no simulated inbox record appears.

O preserves the continuous-grace regression described below. P repeats actual concurrent deadline presence/evaluation twelve times, each with an isolated authority; every timely accepted witness prevents absence. Q uses the same key for two contracts and verifies that separately scoped evidence is necessary; thresholds intentionally count contracts, not unique keys.

R verifies that one owner's recovery leaves another Capsule's uncertainty latch set, including after a later healthy tick. The second owner must recover its own Capsule and wait fresh grace.

S executes **36 histories**: all six submission orders for stale C, contradictory C, revoked C, revoked B, expired C and expired B. Accepted messages are duplicated and eight release calls compete on four workers in each history. Explicit outcomes: stale/contradictory/revoked/expired C still permits A+B release; revoking or expiring B blocks release when C supplies no usable positive support. Each history compares both contract interpreters and independent release eligibility. Authorisation counts never exceed one.

T rejects cross-Capsule evidence, wrong commitments, contract revisions, authorities, future/stale windows, boolean version numbers, invalid claim types, extra schema fields and invalid signatures. A corrected properly signed message is accepted and satisfies A alone.

## A real counterexample and correction

The initial image passed 14 tests in 2.487 seconds ([first output](doc/results/first-run.txt)). It nevertheless contained a grace bug: a worker checked policy truth only at the candidate start and at its return.

Reproduced against the initial local Docker image `sha256:a48877ad23da1039d74685c5250e2107bb1adaac2e10130444b199a3c10d1723`:

- Policy is `A OR B OR C`; A has positive evidence until t=2.
- B is an absence contract whose challenge deadline is t=3, so it becomes satisfied at t=4.
- Candidate is created at t=0, with grace 5.
- Worker returns at t=5. The policy was false at t=2 and t=3.
- Initial engine nevertheless authorised release at t=5.

[Preserved observed counterexample](doc/results/grace-counterexample.txt):

```text
Observed authorisation: True
COUNTEREXAMPLE REPRODUCED
```

Correction: evaluate every intervening contract/proof validity boundary and absence deadline transition. A false interval resets the candidate. The regression fixture now produces:

```text
A expires at 2; B becomes satisfied at 4; worker returns at 5.
Authorised at 5: False
Authorised at 10 after fresh grace: True
```

[Actual corrected output](doc/results/grace-regression.txt). The old image is local historical provenance, not a published reproducible distribution. The checked-in fixture recreates the hostile history against current code; raw old output preserves the original failure.

## Limits and conclusions

All founding A–J and added K–T tests pass. These are finite hostile executions under one durable authority, not proofs of all concurrency schedules. Failure injection is at specified application boundaries; no OS power-loss experiment or independent custody system was run. Independent evaluators implement separate semantic logic in the same language and runtime and trust the same validated acceptance facts.

The experiment establishes composition and audited ordering, not the objective truth of an attestation or the meaning of a missing response. The failed-notification/unreachable-creator experiment authorises release after a missed obligation. That is a visible policy consequence, not a finding that the creator died or intended disclosure.

We have built a system that interprets **agreed conditions over observed evidence**. It does not safely infer intent from silence. Whether silence should grant permission remains an explicit policy and custody decision. Generation 0.2 should first address real-time/outage authority and independent custody, as proposed in [doc/GENERATION_0_2.md](doc/GENERATION_0_2.md).


## Generation 0.4 — Available Witness and First Human

The bounded four-witness protocol, Laravel HTTP lifecycle, real HTTPS adapters, Docker network partition and disappearing-SaaS experiment are reproducible with `scripts/experiment04.sh`. See [results and explicit limits](doc/generation04/RESULTS.md), [raw evidence](doc/results04), and [the owner runbook](doc/generation04/RUNBOOK.md). A separate real wall/monotonic-clock lifecycle is retained in `doc/results04/realtime.txt`. This is not independent multi-host or WAN validation.


## Generation 0.5 — The Hostile SaaS

The [retained classification ledger](doc/results05/attacks.json), [integrated outage/device/restart sequence](doc/results05/hostile-lifecycle.txt), conformance and measured overhead distinguish actual outcomes. In particular, censorship can produce policy-authorised absence despite an attempted check-in; malicious executed client code and colluding custody still win. All content is synthetic and delivery is simulated.

## Generation 0.6 — The Honest Custodian

The [research harness](doc/generation06/README.md) compares static-share reconstruction with verifiable partial-point decryption. `./scripts/experiment06.sh` retains both honest release and malicious threshold early decryption, plus actual process crash/rollback, substitution, stale witness state, disarm and independent CLI experiments. `./scripts/performance06.sh` runs fresh candidate/baseline workloads sequentially. `python3 scripts/regression06.py` preserves all prior attacks and redirects new regression evidence into `doc/results06`. No real delivery or production secrets.

## Generation 0.7 — The Missing Piece

The [two-domain research harness](doc/generation07/README.md) tests custody-only and authority-only extraction, successful combined collusion, signed invalid arithmetic, independent recipient verification, malformed/delayed/oversized replies, real process crashes, independent journal recovery and correlated provisioning/admin failures. An inherited early-window finalisation attack against cancellation is retained. Run `./scripts/experiment07.sh`, `python3 scripts/regression07.py`, then `./scripts/performance07.sh` for sequential fresh-cluster comparison with 0.6. Synthetic content only.

## Generation 0.8 — The Last Word

[Research and reproduction](doc/generation08/README.md) cover corrected historical-window cancellation, explicit terminal ordering, Byzantine proposals/view changes, partitions, durable vote/decision crashes, authenticated recovery, creator-independent work and a network-disabled recipient. Original U/V and combined-quorum attacks remain preserved. Run `./scripts/experiment08.sh`, `python3 scripts/regression08.py`, then `./scripts/performance08.sh` for sequential fresh-cluster comparison. No real disclosure or PorterNet.

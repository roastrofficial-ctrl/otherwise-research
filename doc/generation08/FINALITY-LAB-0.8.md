# Hostile finality laboratory

The unchanged 0.7 U/V fixtures ran first (`results08/before07/tests.txt`, `attacks.json`). The complete 0.1–0.7 suites later reran under `history/` and `history07/`; old source, fingerprints, fixtures and result directories remain intact. In v8, Attack V is corrected by a **new terminal protocol**, not by making a Laravel button ignore a witness error.

## Deterministic schedules

`tests08/scheduler.py` runs the actual `Replica` transition functions with separate FULL SQLite state files and an explicit logical event sequence. Each event records participant, input, accepted/error result, and known consensus state before/after. No sleep, thread race or wall-clock timestamp chooses a winner. Tests obtain synthetic witness signing keys only through private LAB_FAULTS instrumentation; those extraction routes are not normal protocol authority.

The logical scheduler abstracts transport/clock/crypto-guard availability and uses real signed valid evidence fixtures from the service laboratory. Separate live Docker tests exercise TLS, bounded concurrent collection, actual process exits, fresh checkpoints, worker/CLI operation and recipient isolation. These two forms of evidence are complementary, not a claim that arbitrary live scheduling is deterministic.

| Directive scenario | Schedule / outcome | Classification and retained test |
|---|---|---|
| A: disarm before policy satisfaction | Close all earlier PRESENT windows, leave later window open, verify false complete predicate, order valid owner DISARM | Prevented historical cancellation-denial; A succeeds in v8 while old V remains successful |
| B: immediately before release commitment | Order DISARM first while a valid RELEASE candidate exists; subsequent RELEASE cannot acquire terminal permission | Prevented conflicting later release; B. Pending prepared-release overlap is separately retained in F |
| C: immediately after release commitment | Commit RELEASE, submit otherwise valid owner cancellation, collect/decrypt later | Late revocation cannot undo the authorised commitment; C |
| D: concurrent opposite orders | Byzantine leader signs opposing proposals to different replicas; honest per-view fences prevent double prepare; only compatible prepared/commit proof succeeds | Prevented conflicting certificates; D |
| E: network partition | Deliver to two replicas, withhold the rest; no quorum. Heal and carry messages through a new view to one terminal decision; stale old-view vote rejected | Recoverable; E. Safety sacrifices progress under2/2 split |
| F: Byzantine equivocation/head replay | D exercises contradictory proposals; T supplies a signed false high view, bad proposal and wrong-scope view change; valid three-source quorum excludes poison | Prevented false decision; T. A prepared release can constrain a later disarm even before a creator sees a certificate (F), recorded as uncertainty rather than cancellation success |
| G: delayed accepted checkin | Three observations are durable before cutoff; fourth witness can close ABSENT before late copies arrive. Accepted presence prevents the complete predicate. Separate locally generated/unsubmitted proof does not | Recoverable accepted evidence; G. Never-submitted presence supplies no authoritative protection |
| H: SaaS censorship/false success | Drop the signed operation, forge a success object, replay stale status; only real terminal certificate accepted; independent direct route succeeds | Recoverable where direct routes exist; H/S. Censorship is not claimed prevented |
| I: restart at commitment boundary | Real exits before/after COMMIT vote SQL write, and after terminal installation; no prewrite vote reply, postwrite vote retained; restart quarantines until fresh peer recovery | Recoverable; R/I plus SQLite-backed schedules. Actual exit hooks, not timing sleeps |
| J: membership replacement pending release | Owner-signed altered epoch is refused; existing registry cannot be amended or old proof applied to a new commitment | Prevented unsafe substitution; J. Hot membership/key replacement remains unsupported |
| K: malicious entire custody domain | Extract custody-local state and compute A offline; wrong-domain unwrap/DEK attempt fails without independent B | Missing-capability protection preserved under secure setup; K part of K/L |
| L: combined domains | Extract enough A/B shares, compute raw points, unwrap components and decrypt before any terminal certificate | **Successful** retained bypass; L part of K/L. No master-scalar reconstruction required |
| M: creator permanently absent | Remove owner and recipient secrets from public worker input while window still open; advance logical evidence clock; independent child worker evaluates/orders/collects | Recoverable legitimate release; M. No SaaS service or surviving creator capability is needed by the worker |
| N: creator returns after disclosure | Recipient recovers plaintext; owner subsequently signs cancellation; committed RELEASE remains final | Knowledge cannot be revoked; N. Certificate is not mislabelled as a plaintext-delivery receipt |
| O: contradictory/old evidence recovery | Restore one replica's old SQLite state; quarantine blocks old signing; merge three fresh checkpoints and preserve terminal decision | Recoverable; O. Global rollback or additional withholding recovery peers are outside this simple recovery guarantee |

Additional records P/Q/R/S/T/U/V cover signed-invalid crypto minority replies, related/private-reused entropy and incorrect share commitments, durable vote crash hooks, stale status, Byzantine view-change collection, retained decisions after all witness routes fail, and policy-only/legacy endpoint downgrade attempts.

The machine-readable `schedules.json` contains initial registries/evidence, participant configuration, full message schedules and known states, accepted/rejected results, terminal certificates and disclosure outcomes. Some directive scenarios share one compound trace (I/J, K/L, M/N); the table separates their meanings and classifications. These are not security percentages. All contents and intentionally compromised capabilities are synthetic.

## Bounded model exploration

`tests08/modelcheck.py` is an independent finite exhaustive abstraction of two values, two views, four replicas, each Byzantine position, all honest per-view prepare choices, prepared-proof delivery subsets, view-change quorums and subsequent commit subsets. It checks58,880 combinations with no contradictory committed values under its assumptions. A deliberately broken variant that drops prepared evidence in view change yields a retained conflicting-commit counterexample.

The model assumes valid signatures/values and durable honest vote/promise fences. It does **not** model arbitrary views, implementation refinement, actual cryptography/parsing/FS, clock/timer behaviour, membership change, global rollback or complete liveness. The result is useful bounded verification, not a formal proof of this entire implementation. Its exact output and exclusions are in `modelcheck.json`.

## Independent conformance and clients

Python and the separate Node checker evaluate21 fixed terminal certificate objects:6 positive and15 negative, including typed booleans masquerading as epochs, wrong phases/views, changed registry/recipient/policy, invalid owner signature, duplicate/insufficient voters and missing ARM proof. The retained0.7 proof/canonical corpus and all previous conformance cases rerun separately. Full primitive/library review is not inferred from agreement.

The public worker receives no owner or recipient secret. The separate recipient verifies its encrypted configuration and portable package in a Docker service with `network_mode: none`, read-only state, no provider volumes, no fault token and no owner seed. The normal creator CLI supports `create`, `arm`, `checkin`, `policy`, `status`, `recover`, `disarm`, `commit` and `disclose`. Its encrypted vault is updated before printing success. `policy` explicitly reports a predicate proof, not terminal authorisation. A missing quorum/acknowledgement is an uncertain outcome requiring recovery.

## Reproduction

```sh
./scripts/experiment08.sh
python3 scripts/regression08.py
./scripts/performance08.sh
```

Docker Desktop/Compose is required. Host Python only orchestrates containers/generates documentation. Profiles use unique disposable project names, separate state volumes and ten TLS protocol endpoints; no Laravel, real data, external disclosure or PorterNet. `.env05` and `.tls08` hold ignored local laboratory secrets/CA material. The local fault profile must not be deployed as a service for real secrets.

Default new and comparison subnets are10.208.8.0/24 and10.208.9.0/24; inspect local allocations on a different host. `OTHERWISE_08_SUBNET` can override the new profile. Cleanup removes only that experiment's resources, leaving previous demos and evidence intact. A source review fingerprint is recorded separately; authenticate a release/digest independently. The fingerprint does not authenticate itself or supply signed updates/reproducible binaries.

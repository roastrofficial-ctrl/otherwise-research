# Laboratory decisions

- Python and SQLite minimise orchestration while preserving transactional ordering and executable independence from the app. Laravel remains an eventual client choice, not the protocol's definition.
- Docker Compose builds one minimal runtime; test/demo execution has no network. The base image is currently a version tag, not a permanent digest pin. Cryptography is version-pinned; transitive build dependencies are not fully locked. Exact long-term binary reproducibility remains future work.
- Evidence uses Ed25519 public-key authentication rather than shared HMAC secrets, so different authorities can be independently verified. Test keys are generated anew; signatures and decision hashes differ across runs while outcomes are reproducible.
- Policy truth is positive support. Contradictions disable the affected leaf; they do not grant an unrelated participant a global veto. An OR or threshold may still be satisfied by other leaves.
- Repeated expression leaves are rejected. Independence means distinct contractual obligations; separate keys are necessary but insufficient to prove independent entities.
- Finite immutable challenges expose the deadline problem without embedding calendar/scheduler complexity. Missing a challenge remains historical even if a later challenge is answered; redefining that relationship requires a new contract semantic version.
- Grace starts on durable observation and must stay valid continuously. The first implementation checked only the endpoints; an actual preserved counterexample justified evaluating intervening validity boundaries.
- New accepted evidence conservatively resets grace. This may delay release more than strictly necessary and can be used by an authorised entity to defer it; liveness is not promised. An identical retry does not reset grace.
- Revocation disables every contract scoped to the revoked authority in that Capsule. It does not create absence. Owner-signed recovery is Capsule-local so one owner's action cannot clear another owner's uncertainty.
- Delivery has a durable recipient operation separate from its audit acknowledgement. The simulated inbox has an idempotency key; real provider semantics cannot be inferred from that result.
- No policy amendment endpoint: changing conditions means a successor Capsule, disarming the predecessor and arming the successor. No silent revisions or atomic cross-Capsule migration are claimed.
- Hash-chain validation and database anchors catch the tested corruptions. An operator capable of rewriting all anchors remains trusted and dangerous; independent witnesses are future work.

Composing contracts does not eliminate all unilateral influence. An AND policy deliberately gives every required obligation a veto; a 2-of-3 policy can tolerate one unsatisfied obligation but one vote can still be decisive depending on the others. The established property is that one positive leaf alone is insufficient for 2-of-3, and one unrelated negative leaf cannot invalidate two positive leaves. Owners govern the committed policy and operators remain custodians; neither is made cryptographically powerless by this experiment.

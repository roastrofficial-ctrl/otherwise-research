# Generation 0.4 results

Latest completed run: **23 new test methods pass**, plus **54 preserved generation 0.1–0.3 tests** (77 total). All **66 version-4 portable proof objects** agree between Python and Node, including 48 quorum permutations and 15 negative cases. The previous 194 generation-0.2 and 48 generation-0.3 proof objects also passed their original checks. New regression output is retained in `doc/results04/regression/`; earlier checked-in raw artifacts were preserved.

The latest local accepted-check-in median was **100.554 ms** with all four members (10 samples, p95 nearest-rank 188.333 ms), including durable receipt distribution; complete acknowledgement plus holder proofs averaged **13,518 bytes**. With one fast refusal, the median was **94.041 ms** (5 samples, p95 198.622 ms), averaging **9,151 bytes**. Fast refusal is not a black-hole timeout or WAN comparison.

Runtime: Python 3.12.15, SQLite 3.46.1, cryptography 46.0.3, Node 22.23.3; consumer PHP 8.4.26 / Laravel 13.37.0 with committed Composer lock. `real-web.txt` additionally confirms the current localhost Laravel build completes real-clock create/arm/check-in/status/disarm without fault-clock endpoints.

Raw results are in `doc/results04/`. The experiment runs in its own temporary Docker Compose project and deletes only its own volumes. The previous three-witness implementation, original unsafe-quorum fixture and earlier engine/custody counterexamples remain runnable with `scripts/experiment03.sh`.

| Requirement | Executable evidence | Boundary |
|---|---|---|
| Standalone protocol without Laravel | `test_protocol_image_and_import_graph_exclude_saas` and full CLI lifecycle | Protocol image physically excludes Consumer, PHP and Composer |
| One faulty member, useful availability | Iterate all four possible refusing members for accepted presence and missed-window release | Reachable honest three, healthy clocks/storage, same request before deadline |
| Quorum safety beyond arithmetic | Durable first-write/final locks, authentic equivocation and future-dated peer-closure tests, repair, stale/scope/duplicate checks | Static epoch; at most one faulty witness; bounded clocks required |
| Partition | Actual Docker network disconnect/reconnect of one live witness | Single host, not independent routing/administration or WAN loss |
| Durable acknowledgement and repair | Whole witness DB rollback, recovered aggregate, authenticated three-peer repair, rejected checkpoint replay | Target identity retained; all three other members needed for repair |
| Competing release workers | Concurrent disarm/evaluation and repeated custody requests | Fixed operation idempotency; no global exactly-once delivery |
| Council remains supported | A/B independent TRUE attestations; C FALSE or conflicting, reordered and duplicate submissions | Authenticated assertions do not establish objective truth |
| Laravel full Solo flow | Actual HTTP GET/static JavaScript, CSRF create/arm/check-in/status/disarm/evaluate/simulate, PostgreSQL writes | Browser rendering/accessibility not interactively audited |
| No optimistic check-in success | Exact served JavaScript verified with Node WebCrypto; valid ack accepted, signature forgery rejected | Browser localStorage is not independently established power-loss storage |
| Disappearing SaaS | Actual Laravel + PostgreSQL + adapter stop; independent CLI recovery/new check-in/disarm; safe disarm and live missed-window simulation | Independently exported owner capability/payload and reachable protocol providers required |
| Transport substitution | Two separately coded adapters over actual HTTPS; untrusted certificates rejected; same signed bytes and decisions | Same underlying Python TLS stack; no availability-equivalence claim |
| Custody compatibility | Two injectable evaluator gates plus positive/negative capability checks locally and remotely | Both use static shares; neither cryptographically enforces policy |
| Real-clock lifecycle | Real wall/monotonic clock, first check-in, missed second window, release and synthetic decryption | One host's UTC and storage; not independent trustworthy time |
| PorterNet absent | No dependency, service, import or adapter; correspondence comparison is design only | No claim about unverified PorterNet properties |

Two adversarial boundaries are explicit tests. A Byzantine member can sign a future-dated FINAL, but that peer record must not close the three honest members before their own clocks/locks permit closure; they still accept presence and owner disarm. Separately, contradictory C attestations close as CONFLICT/false, allowing valid A and B to authorise a 2-of-3 policy. Malformed peer replies are filtered before aggregation, and eight equivalent honest slot quorums are evaluated without exponential repetition.

The disappearing-SaaS run uses test-clock advancement to make schedules reproducible, not an ownership bypass. New check-in and disarm still require the independently exported owner key; certificate and custody verification still execute. The adapter is also stopped, exceeding the requested application/database outage. Recovery does not read or restore the product database.

The availability improvement is scoped: unlike generation 0.3 P=2/A=3 over three members, a healthy three-member subset of the four-member committee can accept presence and authorise legitimate absence. It cannot repair a fourth member if an additional required peer refuses. It cannot revive a committee-wide cold restart under the shipped recovery rule. It cannot enforce secrecy against two malicious static-share custodians.

Local timings and acknowledgement sizes are recorded in `performance.json`; they include sequential witness observation, direct durable receipt-holder acknowledgements and attempted custody distribution. Ten all-member samples and five fast-refusal samples are a small local cost envelope, not a WAN tail/uptime claim. The real process-restart run establishes a process/volume recovery path, not host power-loss durability. SQLite FULL durability depends on the filesystem and hardware honouring flushes, as described in the [SQLite documentation](https://www.sqlite.org/pragma.html#pragma_synchronous).

No production user data or real disclosure destination was introduced. The central result is conditional but executable: **removing the consumer service did not remove a successfully retained presence certificate or the owner's independent ability to act.** Losing the owner capability, enough independent retained state, functioning clocks or a reachable committee remains an explicit failure boundary.

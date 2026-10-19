# Observation before absence

A deadline is an obligation under an observation model, not a fact about human health. The witness must have a defensible time interval, retained history and adequate application observation before asserting absence-based permission.

The real adapter compares UTC wall time and monotonic elapsed time, including cumulative drift from its session anchor. Backwards movement, excessive disagreement, long gaps and restart latch uncertainty. The witness also tracks per-Capsule app heartbeat gaps, bounded by half the shortest challenge window or 30 seconds. Its own clock can keep working while the app is unavailable; these are separate faults.

The real default radius is one second, divergence budget one second. Presence must be valid across the full uncertainty interval. A sample of `[109,111]` cannot establish unambiguous timeliness for a deadline of 110. A valid but boundary-ambiguous attempted proof latches uncertainty. Candidates must be observed, and the lower time bound must pass the candidate's latest possible witnessed observation (`candidate_upper`) plus the entire grace interval. A two-second uncertainty interval therefore cannot shorten grace by two seconds. If clocks disagree, wait.

This does not authenticate UTC. A bad initial wall clock, correlated false wall/monotonic readings, bad configured uncertainty bounds or a dishonest witness can violate real-time assumptions. The suite does not discipline NTP or alter the host's clock. It exercises the adapter with actual samples plus injected skew, drift, pauses and restart state; accelerated integration uses a clearly marked controlled clock.

The exact acceptance threshold is the witness's durable database commit; eligibility is determined from its bounded sample while serialising the publication. A request arriving before the deadline may become non-qualifying if it reaches this authority later. Conversely, a valid pre-deadline sample followed by slow storage may commit after the physical deadline; it remains ordered ahead of subsequent decisions. Bounding sampling-to-commit latency in physical time is not solved.

Outage recovery is part of the committed manifest, not a hidden policy amendment. It does not move challenge deadlines or resurrect expired evidence. It clears only the owner's Capsule latch and restarts observed grace. Effective release may therefore be delayed indefinitely. Other Capsules remain uncertain even after the global sampling clock recovers.

One useful failure was reproduced: recovery originally cleared the block and then re-applied the already-observed preceding app gap, making recovery impossible. The fix accounts for the gap before the fresh signed recovery. A separate review exposed replayable action-only recovery; version-2 commands now bind the current history head. Raw failure output is retained alongside the regression tests.

A creator-only network partition can remain invisible while the app keeps heartbeating. Such a Capsule can still reach its committed absence condition. Clock/gap handling does not convert missed evidence into objective proof of incapacity. Recovery after terminal authorisation/service restart and fully automatic policy-governed infrastructure recovery remain Generation 0.3 work.

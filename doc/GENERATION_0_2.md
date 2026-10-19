# Proposed Generation 0.2 — The Bounded Authority

The 0.1 experiments show that explicit authoritative ordering and independently replayed policy semantics are feasible, but not sufficient for real-world custody or interpreting silence.

Priorities, in order:

1. **Real clock and outage authority.** Specify drift budgets, receipt-versus-commit thresholds, monotonic time, authenticated health observations, process-restart uncertainty and owner recovery. Test pauses that span deadlines, clock freeze, slow drift, crashes during acceptance and storage restoration. The controlled clock deliberately cannot establish these guarantees.
2. **Portable conformance corpus.** Publish fixed keys, signed canonical vectors and expected lifecycle decisions; build another language's interpreter and verifier. Add generated nested-policy histories and shrink failures to small counterexamples. Preserve the continuous-grace gap as a regression case.
3. **Acceptance durability and replay witnesses.** Kill processes at real commit/fsync points; pin externally witnessed history heads and test rollback of whole database backups. Make creation/orphan cleanup and recovery semantics explicit.
4. **Small independent custody trial.** Two-of-three genuine custodians, with an established threshold scheme and independent implementation review. Require snapshot-specific partial decryptions; demonstrate that the service operator alone cannot decrypt. Do not claim the general AND/OR grammar automatically maps to a simple threshold key.
5. **Human decision and destination safety.** Add a thin Laravel client only after the engine boundary is stable. Explain absence versus attestation, show acceptance receipts, make disarm accessible, configure substantial real-time grace, and verify/consent actual recipients before enabling any real delivery.

Do not add consensus clusters or blockchains without an experiment showing a specific need. Production recurrent schedules, DST handling, reminders, peer availability, key rotation, revocation governance and recovery must have their own tested semantics.

The thesis to test next: can independent custodians enforce a policy decision **without** giving the acceptance operator an alternative decryption path? This is different from whether independent semantic evaluators agree, which 0.1 already exercises.

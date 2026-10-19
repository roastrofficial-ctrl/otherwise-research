# Generation 0.3 results

Executed in Docker on 19 October 2026:

- **20** Generation 0.1 tests passed.
- **21** Generation 0.2 tests passed, retaining both successful attacks.
- **13** new tests passed: the signed quorum counterexample plus mandatory A–L.
- **22 fixed + 26 reordered witness proof objects** agreed between independent Python/JavaScript verifiers.
- Both Solo and Council used the same observe/finalise/certificate/custody machinery.

The final new suite reported `Ran 13 tests in 2.833s — OK`. All 54 test methods passed; this is finite experimental evidence, not a formal verification of every network/storage schedule.

Raw evidence: [tests](../results03/tests.txt), [portable conformance](../results03/conformance.txt), [performance](../results03/performance.json), [previous generations](../results03/previous-generations.txt), [full run](../results03/complete-run.txt). The old observation directories and earlier counterexamples remain in place. Timing and runtime identities naturally change on rerun.

The unsafe attack is permanently represented by genuine signed fixture objects. Presence `{A,B}` and absence `{B,C}` both verify with a malicious B under naive 2/2 thresholds. The supported 2-presence/3-finalisation/f=1 profile rejects that configuration. A separate test deliberately exceeds f with two malicious witnesses and produces conflicting valid-looking objects; informed custodians refuse them. Neither result is hidden by an all-green test report: these attacks are expected outcomes in the suite.

The new invariant is conditional but concrete: accepted presence cannot be erased into an absence-based release by the app plus at most one faulty witness, while static membership, honest retained fences and observation assumptions hold. The price is that a single silent required signer can block release forever. A minority observation may also block release without creating a complete acknowledgment.

Read [RESEARCH.md](RESEARCH.md) for the model, the full A–L observations, limitations and all eight requested answers; [PERFORMANCE.md](PERFORMANCE.md) for measured costs; and [GENERATION_0_4.md](GENERATION_0_4.md) for the proposed next experiment.

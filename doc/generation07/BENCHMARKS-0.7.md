# Benchmarks — measured 0.6 versus 0.7

Fresh clusters run sequentially on the same local Docker host, after the conformance/regression work. Eight primary Capsules each use two check-in windows: one accepted presence, one missed window, authorisation, contribution collection and recipient disclosure. Eight additional rotations each retire one active Capsule and provision/arm a fresh one, for **24 Capsule rows per service**. Both reuse initial key generations for the primary workload; fresh generations are included in rotation. Pure crypto costs use 40 samples. New profile has two domains/ten persistent protocol services; 0.6 has one custody domain/seven services. No Laravel or public disclosure destination runs in either measured cluster.

Host: Apple M3 Pro, 18 GiB RAM; Docker Desktop engine 27.2.0, aarch64, 12 CPUs, VM memory 8,219,254,784 bytes. Other existing demo/unrelated containers remained running; no CPU pinning or independent physical hosts. Witness clocks are controlled laboratory clocks, not a UTC or WAN experiment. TLS uses separate local test-CA credentials. Dependencies/base tags and actual versions are recorded; mutable base tags do not imply bitwise reproducibility.

Runtime: Python 3.12.15, Node v22.23.4, SQLite 3.46.1, cryptography 46.0.3, PyCryptodome 3.23.0; Linux-6.10.4-linuxkit-aarch64-with-glibc2.41.

Cells are **median / observed maximum milliseconds**. Primary/rotation n=8; pure computation n=40. There are too few samples for trustworthy p95/p99 estimates, so no tail-distribution claim is made.

| Operation | 0.6 | 0.7 |
|---|---:|---:|
| Draft discovery and content encryption | 22.793 / 58.196 | 4.890 / 17.542 |
| Wrapping and enrollment | 38.093 / 81.419 | 110.801 / 217.135 |
| Total create/provision/arm | 225.198 / 323.232 | 181.405 / 293.197 |
| Checkin and authoritative retention | 172.693 / 395.172 | 48.214 / 94.361 |
| Fresh inspection | 150.578 / 325.643 | 44.109 / 56.814 |
| Authorisation and finalisation | 60.649 / 97.223 | 90.662 / 205.697 |
| Contribution quorum collection | 159.891 / 190.606 | 492.685 / 811.201 |
| Recipient verification / combine / decrypt | 19.031 / 46.306 | 183.601 / 310.179 |
| Complete honest disclosure | 389.664 / 650.838 | 917.050 / 1182.966 |
| Encrypted backup open | 59.801 / 65.460 | 59.157 / 222.952 |
| Fresh state recovery | 143.938 / 235.279 | 43.907 / 169.633 |
| One unavailable participant per domain | 271.624 / 461.695 | 829.684 / 861.854 |
| Retire and arm fresh-key Capsule | 385.592 / 648.955 | 203.342 / 234.689 |
| Pure key generation (1 vs 2 domains), n=40 | 1.144 / 1.907 | 2.392 / 3.366 |
| Pure one-partial generation, n=40 | 4.817 / 8.130 | 4.952 / 6.797 |
| Pure one-partial verification, n=40 | 4.932 / 6.929 | 5.076 / 6.812 |
| Pure wrapping (1 vs 2 components), n=40 | 3.992 / 6.556 | 8.194 / 12.590 |

Additional operations introduced by 0.7:

- Encrypted response journal retention: median 195.694 ms, observed max 356.828 ms, n=8.
- Fresh retained-operation recovery: median 237.292 ms, observed max 247.720 ms, n=8.
- One individually scoped encrypted contribution verification: median 24.703 ms, observed max 26.240 ms, n=16.
- Disclosure with one malformed responder per domain: median 935.579 ms, observed max 1100.600 ms, n=8.

0.6 additionally requires its record-union head agreement stage; 0.7 names the immutable finality certificate and independently checks fresh veto evidence. Full-disclosure numbers include each profile's real validation/persistence path. 0.7 collects six contributions concurrently, selects at least2/domain, and retains verified encrypted replies at3/4 witnesses; 0.6 uses its preserved sequential path and no independent v7 journal. These are different protection boundaries and costs, not merely faster/slower curve arithmetic. Content encryption adds a 16-byte encrypted commitment salt in 0.7, and custody wrapping adds an independently necessary component. Neither standalone provision column includes hidden DKG: it is trusted dealer setup.

Latency instrumentation does not enable tracemalloc over timed work. CPU and maxrss cover the client process; child Node CPU is not included in that client-only counter. A separate one-partial Python memory probe runs outside latency measurements. Holder/witness cgroup CPU includes their processes and child verifiers; diagnostics/startup and faults also contribute. Resource snapshots below are not dedicated per-operation CPU attribution or geographic capacity forecasts.

| Client resource | 0.6 | 0.7 |
|---|---:|---:|
| Parent CPU seconds | 5.428 | 35.744 |
| Process max RSS, Linux KiB | 73148 | 77908 |
| Separate one-partial Python traced peak, bytes | 4121 | 4121 |

## Durable storage and service resources

Resource totals are not identical-operation CPU ratios: the new profile additionally runs journal retention/recovery, individual scoped verification and eight malformed-member disclosures that the baseline cannot complete. Shared-operation latency rows compare their stated workloads; whole-process totals include these extra new-profile exercises.

0.6: 7 protocol containers, each24 Capsule rows; aggregate SQLite files 1396736 bytes; aggregate cgroup CPU usage 14.239 seconds; sum of per-container observed memory peaks 191959040 bytes. The sum of peaks is not simultaneous aggregate RAM usage. Cgroup counters include startup and diagnostic overhead; database lengths include pages/overhead, not just logical secrets.
0.7: 10 protocol containers, each24 Capsule rows; aggregate SQLite files 3973120 bytes; aggregate cgroup CPU usage 49.166 seconds; sum of per-container observed memory peaks 324292608 bytes. The sum of peaks is not simultaneous aggregate RAM usage. Cgroup counters include startup and diagnostic overhead; database lengths include pages/overhead, not just logical secrets.

0.7 stores additional domain commitments, fresh witness anchors, invalid-response evidence and independently replicated encrypted operations. DB growth is not merely private-share size. Metadata retention, journal reconciliation/limits and long-term storage costs need further operational design. Physical files and cgroup observations are in `resources.jsonl` and `baseline-resources.jsonl`.

## Logical network payloads

Captured last-sample canonical JSON bytes exclude TLS/HTTP/IP framing and retransmission:

| Payload | 0.6 | 0.7 |
|---|---:|---:|
| Selected contribution replies | 3816 | 9256 |
| Payload ciphertext | 66 | 82 |
| Encrypted creator backup | 34979 | 38979 |

0.7 sidecar: 4329 bytes. Four selected journal bundle bodies total 54764 bytes before replication; sending to four witnesses multiplies those request bodies by four, plus acknowledgements. Six holder requests and responses are attempted in the healthy quorum round, while the table counts only four selected replies. Each holder also requests four witness snapshots concurrently. Thus at least24 fresh witness requests occur inside the six-holder collection, independently of creator/recipient inspections and journal rounds. No claim is made that the selected-reply count measures all network traffic. The baseline similarly has separate head-agreement and fresh provider reads.

## Failure and long-term limits

The unavailable workload has one refusing holder in the one-domain baseline and one refusing holder in **each** new domain. A separate v7 malformed-member measurement demonstrates valid quorum survival; the 0.6 batch-poisoning limitation remains recorded rather than assigned an invented latency number. Full tests additionally cover signed bad arithmetic, oversized messages, delayed/missing/duplicate sources, actual process crashes, restored DBs and an actually stopped witness. Those correctness scenarios are not latency distributions.

Rotation timings mean retirement plus a new immutable Capsule and fresh keys; no safe proactive share refresh, full committee replacement or hot migration has been implemented. Old copied ciphertext/combined secrets remain usable. Either domain permanently losing threshold blocks useful release. Secure backups, independent administrators, successor organisations, cryptographic review/migration and long-term funding are additional costs not priced by this local microbenchmark.

Raw data: [0.7 measurements](../results07/performance.json), [0.6 measurements](../results07/baseline-performance.json), [runtime](../results07/runtime.json), and resource JSONL/attack/recovery transcripts in the same directory.

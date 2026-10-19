# Measured cost — 19 October 2026

Actual output: [performance.json](../results03/performance.json). Reproduce with `./scripts/experiment03.sh`.

Environment: one local Docker host, six separate service containers on an internal HTTP network, SQLite synchronous=FULL, named persistent witness and client-cache volumes, controlled service clocks, sequential synthetic operations and real `perf_counter` timing. The runtime inherited from the verified baseline is Python 3.12.15, SQLite 3.46.1, cryptography 46.0.3, PyCryptodome 3.23.0 and Node v22.23.3. These are not independent machines or a WAN/mobile benchmark.

| Operation | Samples | Median | Nearest-rank p95 |
| --- | ---: | ---: | ---: |
| Check-in + durable client certificate, three available | 20 | 10.260 ms | 14.867 ms |
| Check-in + durable client certificate, one refusing service | 10 | 7.913 ms | 10.047 ms |
| Optional post-acceptance receipt gossip, three observations | 20 | 16.171 ms | 17.956 ms |
| Optional gossip, two observations, unavailable peer restored first | 10 | 11.457 ms | 13.797 ms |
| Python compact release verification | 100 | 0.737 ms | 1.431 ms |
| Custody HTTP request including Python + new Node process | 10 | 25.368 ms | 30.086 ms |
| Gen0.2 fixed-history Python verification | 100 | 0.289 ms | 0.338 ms |

A witness process crash after commit, Docker restart and recovery of the original receipt took **1,280.143 ms** in the measured recovery sample. This includes container restart/backoff and HTTP lookup, not just database recovery.

| Encoded/state metric | Three observations | Two observations |
| --- | ---: | ---: |
| Mean signed receipt | 1,139 bytes | 1,139 bytes |
| Mean acknowledgment including signed manifest | 4,911 bytes | 3,771 bytes |
| Aggregate witness logical state growth per Capsule | 5,253 bytes | 3,502 bytes |
| Additional aggregate retained peer-anchor bytes | 10,251 bytes | 6,834 bytes |
| Observation-state SQLite commits per check-in | 3 | 2 |
| Clock-file checkpoints per check-in | 3 | 2 |
| Durable client aggregate-cache writes | 1 | 1 |

The implementation sends each receipt to all three witnesses for optional retention, including its issuer: nine new anchor inserts for three observations, six for two. These are additional logical database transactions outside the measured acknowledgment path. Certificate caching and clock-file checkpoints use file/directory fsync. We did not count physical disk/controller writes or infer their number from logical commits.

The measured one-slot absence release certificate was **3,423 bytes**. The selected Gen0.2 full-history fixture was **4,350 bytes**. These are different proof shapes/histories: encoded size and Python CPU time are illustrative comparisons, not evidence of universal compression or speed improvement. In this small example the compact verifier actually used more Python CPU, while avoiding a dependency on an app-selected full history. Certificate size still scales with committed slots and retained proofs.

The one-unavailable case uses an immediate protocol/API refusal, not a blackholed TCP connection. The client currently contacts witnesses sequentially and can wait for a request timeout on a silent network. The offline peer is restored before optional gossip; its gossip timing is not a claim of gossip delivery during partition. No release is possible while any required finalisation remains unavailable.

Logical storage counts canonical serialized per-Capsule state/anchor payloads, excluding SQLite page allocation, filesystem metadata, caches, private identities and backups. Real deployment/storage costs would be larger. Samples are modest and warm, and p95 at ten samples is the maximum observed sample. No production SLA, peak throughput, Internet availability or hardware durability guarantee follows.

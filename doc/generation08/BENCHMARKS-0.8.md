# Benchmarks0.8 — coordination versus local verification

The final comparison ran sequentially on fresh Docker clusters after regression/conformance work. Both profiles use eight two-window synthetic Capsules: accepted first checkin, missed second window, evidence evaluation, disclosure and state retrieval; eight separate still-revocable Capsules measure disarm. Three additional recovery/partition samples are reported separately. No Laravel or external disclosure service participates. Witness clocks are controlled laboratory clocks; HTTPS/SQLite/crypto and measured wall-clock durations are real local operations.

Runtime: Python 3.12.16, Node v22.23.4, SQLite 3.46.1, cryptography 46.0.3, PyCryptodome 3.23.0; Linux-6.10.4-linuxkit-aarch64-with-glibc2.41. Host Apple M3 Pro,18GiB RAM; Docker Desktop/aarch64,12 visible CPUs and about8GB VM memory. Existing unrelated/demo containers remained running; no CPU pinning or geographic network was modelled. Mutable base tags are not bit-for-bit reproducibility.

Cells are **median / observed maximum milliseconds**; lifecycle n=8, local verification n=100, recovery n=3. Sample maxima are not tail guarantees; n=3/8 cannot justify p95/p99.

| Operation | 0.7 | 0.8 |
|---|---:|---:|
| Checkin with authoritative retention | 40.018 / 46.843 (n=8) | 35.498 / 36.455 (n=8) |
| Complete predicate evidence | 76.471 / 89.830 (n=8) | 69.636 / 76.813 (n=8) |
| Disarm on a fresh revocable Capsule | 34.709 / 42.060 (n=8) | 108.902 / 113.429 (n=8) |
| Cryptographic contribution collection | 531.299 / 561.396 (n=8) | 415.100 / 420.686 (n=8) |
| Recipient verification / disclosure | 225.098 / 301.478 (n=8) | 77.786 / 78.835 (n=8) |
| Decision/evidence retrieval | 63.807 / 70.686 (n=8) | 29.800 / 30.331 (n=8) |
| Local finality/evidence certificate check | 1.366 / 1.614 (n=100) | 5.404 / 6.503 (n=100) |
| Authenticated recovery after quarantine | 39.695 / 41.093 (n=3) | 88.559 / 112.880 (n=3) |
| Progress after write-partition healing | 31.548 / 32.381 (n=3) | 61.660 / 62.188 (n=3) |

0.8's separate terminal authorisation/commitment stage: median248.795ms, observed max254.105ms, n=8. 0.7 has no independent consensus-commitment stage: its complete window-evidence proof is treated as irreversible. Assigning a fictitious0ms consensus cost to it would obscure the different semantics.

The 0.8 recipient verifies the terminal package offline; the 0.7 recipient obtains fresh live witness snapshots. The v8 public collection phase checks outer identities/context and exports all six candidates without a recipient secret; v7 decrypts/verifies inner contributions during collection and selects four. Mathematical checking in v8 happens at the recipient. Those different stage boundaries must not be advertised as an intrinsic crypto speedup. The “local finality” row compares differently sized/meaningful certificates, not two interchangeable security guarantees. Registry cryptographic validation is memoised by immutable canonical bytes in v8, with defensive copies; repeated local checks are warm-cache measurements. This optimisation does not cache mutable evidence/terminal truth.

Recovery samples have different triggers and must not be read as a pure speed contest. V8 actually exits/restarts a witness, then times fresh3-peer recovery without creator signature (boot waiting excluded). The preserved v7 service lacks that crash endpoint in this benchmark; its DB is saved/restored through its original fault API, which quarantines it, then owner-authorised3-peer repair is timed. Actual v7 process restarts remain covered by its original regression scenario. Partition samples use two unavailable write endpoints, restore them, then time successful disarm/consensus progress. The deterministic full-message-cut schedules separately test safety; these samples are not WAN partition experiments.

## Messages, writes and storage

The healthy v8 terminal path queries4 statuses, sends1 proposal to the current leader, collects4 PREPARE and4 COMMIT replies, notifies4 witnesses, then attempts terminal-certificate retention at6 key holders. Each RPC has a request and response; additional view-change/catch-up/repair and retries add messages. The certificate can become valid before notification/retention completes; those extra acknowledgements do not create another authority. The measured v8 authorisation/commitment method includes that holder-retention round after the certificate first exists; its return latency is not the exact abstract linearisation instant.

Measured witness-log SQLite row updates per ordinary release: [13, 13, 13, 13, 13, 13, 13, 13]. Expected normal path is13 (one proposal, four prepares, four commits, four terminal installs). Each is committed with SQLite FULL; this is a measured row-write count, **not an OS/fsync trace**. Key holders additionally persist retained decisions and partial responses. Evidence/checkin/window retention uses the preserved store and adds its own writes. Registration, retries, view changes and restart quarantine add further storage operations.

Canonical JSON bytes, excluding TLS/HTTP/IP framing:

| Artifact | 0.7 | 0.8 |
|---|---:|---:|
| Finality/evidence certificate | 7009 | 14604 |
| Portable proof/contribution package | 16329 | 35342 |

The v8 registry is4923bytes. Repeated full proposals, prepared proofs, terminal certificates and replies incur additional wire/storage overhead; package size alone is not total traffic. Every witness retains its per-Capsule proposal/vote/promise/prepared/terminal log in a separate FULL SQLite DB. Those records are not garbage-collected in this bounded harness. Key holders retain full certificates and cached encrypted partials. Allocated database-file lengths after the equivalent workload are reported below; they include SQLite page overhead and are not inferred from JSON sizes. Package sizes also differ because v8 carries six candidate replies and v7 four selected replies.

Local verification is separated from coordination, evidence collection and cryptographic contribution collection in the table. The v8 client process peak RSS was 43552 LinuxKiB and parent CPU time 11.683s over its complete benchmark; this excludes other containers/child verifier CPU and is not a throughput forecast.

## Operational cost and limitations

V8 adds durable decision state, prepared-proof view-change handling, authenticated creator-independent signer recovery, terminal archives at holders and offline recipient proof handling. It does not add a larger witness committee, a new crypto domain, SaaS authority or paid infrastructure claim. It does add maintenance and review obligations. Frozen membership, finite views/retries, no production gossip/pacemaker or global rate/storage admission, and incomplete succession remain serious costs.

The new disarm success after a historical window is not assigned an old-profile success latency: historical V shows that v7 operation is rejected. The fresh-disarm row compares operations both can perform. Likewise, no latency is invented for safe hot committee replacement, which is unsupported. Bounded model/race tests establish safety evidence separately from these local measurements.

Raw data: [v8](../results08/performance.json), [v7](../results08/baseline-performance.json), [runtime](../results08/runtime.json), [schedules](../results08/schedules.json) and recovery/crash transcripts in the same result directory.

## Allocated storage after equivalent workloads

0.7: ten protocol services, each19 Capsule rows; aggregate database files 1957888 bytes, including 0 bytes of separately retained v8 decision logs. These include prior operation/recovery histories, not only current key material.
0.8: ten protocol services, each19 Capsule rows; aggregate database files 5537792 bytes, including 2277376 bytes of separately retained v8 decision logs. These include prior operation/recovery histories, not only current key material.

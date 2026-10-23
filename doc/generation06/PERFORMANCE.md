# Performance and operating costs — 0.6

These are sequential runs on fresh eight-Capsule Docker clusters, using the same 38-byte synthetic payload, two check-in windows, one accepted presence, one missed window, 2-of-3 custody and the same four-witness policy. Each cluster performs the full lifecycle eight times. The new provider reuses one dealer-generated public key across those Capsules; dealer setup is measured separately. Tests/regressions were completed before these final measurements. Existing unrelated/demo containers remained running on the shared host; no CPU isolation or geographic network is simulated.

Host: Apple M3 Pro, 18 GiB RAM. Docker Desktop engine 27.2.0, aarch64, 12 visible CPUs and 8,219,254,784 bytes VM memory. Runtime: Python 3.12.15, Node 22.23.4, SQLite 3.46.1, cryptography 46.0.3, PyCryptodome 3.23.0, Linux 6.10.4-linuxkit. Images use mutable base tags; this is an executable experiment with captured versions, not a bit-for-bit reproducible binary build. HTTPS validates the local test CA. SQLite uses FULL durability. No WAN, independent-organisation or production latency claim follows.

Lifecycle cells below are **median / observed maximum milliseconds**, n=8 per provider. Eight samples do not justify p95/p99 estimates; maxima are observations, not tail guarantees. Pure crypto rows use n=40.

| Equivalent operation | Static 0.5 | Threshold-DH 0.6 |
|---|---:|---:|
| Create, provision and arm | 200.949 / 387.134 | 251.791 / 369.393 |
| Check in and retain authoritative receipts | 149.406 / 293.272 | 175.177 / 319.896 |
| Fresh owner inspection | 149.913 / 189.617 | 147.004 / 160.724 |
| Authorisation with witness finalisation | 51.340 / 77.784 | 48.084 / 106.794 |
| Two custody response requests | 62.569 / 96.664 | 164.967 / 248.896 |
| Recipient verify/combine/disclose | 2.382 / 2.513 | 19.796 / 21.070 |
| Open encrypted backup | 60.476 / 70.860 | 59.489 / 61.984 |
| Recover fresh protocol state | 146.741 / 224.025 | 136.539 / 277.338 |
| Release with one unavailable custodian | 65.705 / 79.530 | 180.769 / 276.441 |
| Pure payload encryption and custody wrapping (n=40) | 0.004 / 0.022 | 3.820 / 6.566 |

New-only costs are not hidden in the common-operation table:
- `custody_provision_wrap_enroll`: median 47.576 ms, observed max 63.699 ms, n=8.
- `fresh_custody_snapshot_agreement`: median 148.524 ms, observed max 349.894 ms, n=8.
- `pure_dealer_setup`: median 1.075 ms, observed max 2.714 ms, n=40.
- Baseline pure Shamir setup: median 0.012 ms, observed max 0.040 ms, n=40.

Baseline arm includes share enrollment; new enrollment/wrapping happens before its arm call. Compare **total create/provision/arm**, not the isolated arm numbers. The reused long-lived group setup is excluded from per-Capsule total and reported above. Both paths currently use the existing creator AES/temporary Shamir draft; the new adapter consumes that material locally to wrap the AES key. This deliberately preserves old creator semantics rather than optimising a new encryption client.

The new partial operation includes fresh signed witness collection, prefix/fork/lifecycle checks, the independent Node policy verifier, group exponentiation, a correctness proof, recipient encryption and a durable response commit. Baseline responses run the old certificate gate/Node verifier and return static bearer shares over TLS. Thus the numbers compare the actual providers and their different protection boundaries, not isolated curve speed. Check-in evidence/witness semantics are unchanged; measured check-in variation is host/adapter overhead, not improved safety.

## JSON traffic and durable storage

Counts below are last-sample canonical JSON bytes, excluding HTTP headers/TLS/IP framing and retransmission. Fresh scan bytes are sampled from the same stable finalised state, not packet captures.

| Quantity | Static 0.5 | Threshold-DH 0.6 |
|---|---:|---:|
| Two partial request bodies | 14490 | 20522 |
| Two partial responses | 1164 | 3816 |
| One four-witness snapshot scan, requests + responses | 40244 | 40244 |
| Ciphertext | 66 | 66 |
| Encrypted creator backup | 29553 | 34979 |

Baseline release performs no fresh witness network scan inside its custody services (it uses retained records/certificate). New head agreement scans four witnesses at each of three custodians; the two partial requests each scan again: **five scans / twenty witness round trips** in the measured healthy path. Multiply the sampled scan bytes by five for an approximate additional logical traffic budget; omit no such cost when comparing the providers. Source response counts may differ during faults. Owner check-in/inspection and repair add their own traffic.

Static 0.5: eight Capsule rows in each of three custodians; SQLite files [94208, 94208, 90112] bytes, total 278528 bytes. Each identity JSON is 75 bytes. These are actual allocated database file lengths after the equivalent workload, not logical JSON lengths.
Threshold-DH 0.6: eight Capsule rows in each of three custodians; SQLite files [77824, 77824, 61440] bytes, total 217088 bytes. Each identity JSON is 75 bytes. These are actual allocated database file lengths after the equivalent workload, not logical JSON lengths.

These DB sizes include different retained state: the static services store copied signed witness receipts, whereas the new provider stores witness hash anchors, sidecar commitments and encrypted partial receipts. They are not a claim that threshold cryptography intrinsically saves disk. The third custodian has different response history because the measured two-response path selected members 1 and 2. Raw benchmark JSON separately records logical material/row sizes; baseline whole share objects and new scalar hex counts have different framing and should not be compared as equivalent private-material encodings. Raw secret material is 16 bytes per static AES share versus a 32-byte P-256 scalar per new share; both require backups, access control and migration.

## Failure and operational budget

One unavailable custodian is measured with an endpoint refusing operations; tests also remove two, restore availability and kill/restart a process before/after a durable response. The other two can release under the tested conditions. These fault tests do not supply a failure-latency distribution. A hanging witness can exceed the sequential provider read/owner timeout budget; authenticated conflicting records can conservatively block progress. See SECURITY.md before claiming useful availability.

No DKG/refresh/committee replacement, multi-host disaster recovery or secure backup retirement is implemented. Custody rollback can invalidate exact response persistence; a surviving recipient receipt can detect a changed retry, while fresh independent witness reads constrain a new operation. Operating for decades additionally requires independent operators, clock and evidence monitoring, durable backups, succession/funding and reviewed cryptographic migration. Provider threshold collusion remains a successful early-decryption attack at any measured performance level.

Raw evidence: [candidate](../results06/performance.json), [baseline](../results06/baseline-performance.json), [container runtime](../results06/runtime.json), [Docker resources](../results06/docker-runtime.json), and physical-storage JSONL files in the same directory.

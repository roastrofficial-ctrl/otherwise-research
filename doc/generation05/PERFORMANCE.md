# Measured overhead

One Docker host, synthetic content, verified TLS to all providers. These are small local samples, not production/WAN latency guarantees.

| Operation | Samples | Median ms | Maximum observed ms |
|---|---:|---:|---:|
| Vault seal (scrypt + AES-GCM) | 10 | 61.097 | 75.605 |
| Vault open (scrypt + AES-GCM) | 10 | 59.979 | 74.003 |
| Ed25519 sign | 200 | 0.037 | 0.096 |
| Ed25519 verify | 200 | 0.078 | 0.125 |
| Direct check-in and receipt retention | 5 | 149.877 | 198.013 |
| Fresh signed status + independent Node verification | 5 | 169.82 | 208.721 |

Encrypted vault: **29,485 bytes**; public projection: **11,195 bytes**; serialised local decrypted capability: 14,645 bytes. Per-witness logical state byte sizes are in `doc/results05/performance.json`; these are JSON logical state, not allocated SQLite pages or host-volume durability measurements.

Scrypt uses approximately 32 MiB (N=32768, r=8, p=1). Seal/open timings include KDF, serialisation and AES-GCM, but exclude disk fsync. The library-level direct check-in/status measurements exclude CLI process startup and encrypted-vault I/O; normal CLI actions add vault open/seal and durable file/directory updates. Status includes separate Node verification processes. Repeated same-slot check-in samples include idempotent original receipts and repeated retention writes; they are not five new independent schedules. No percentile extrapolation is made from five samples.

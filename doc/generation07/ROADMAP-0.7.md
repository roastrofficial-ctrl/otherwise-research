# Work still required, separated by pillar

| Pillar | Next work | Evidence required before increasing claims |
|---|---|---|
| Protocol | Version a lifecycle that distinguishes per-slot closure from final Capsule release commitment and permits well-defined cancellation before that commitment | Model/check adversarial schedules, quorum intersection, recovery and the retained V counterexample; do not silently alter wire4 |
| Protocol / conformance | Independently specify the split capability suite, journal bounds/retention, consistent finality-head cuts and membership migration | Independent implementation beyond public arithmetic vectors; exhaustive/context-fuzz testing and bounded-state recovery analysis |
| Cryptographic custody | Replace trusted-dealer research integration with reviewed threshold encryption/DKG/resharing; analyse adaptive/accumulated compromise and correlated setup | External review, actual malicious-generation tests, backup/refresh/epoch security and clear long-lived secrecy assumptions |
| Creator / recipient clients | Independently authenticated releases/updates/pins; hardened creation memory; distinct recipient installation and backup UX; durable creation journals | Malicious update/client and enrollment-crash tests, key-loss/stolen-device handling, verified release installation and no product-owned keys |
| Availability / storage | Global resource admission, full fault-model analysis, independent journal replica reconciliation and committee replacement | Byzantine/partition tests across real hosts, bounded storage/rate behaviour, restore/migration and service continuity measurements |
| Infrastructure | Deploy genuinely separate domain administrators, clouds/roots/backups/update authorities and documented succession/funding | Correlated-compromise drills; one host/CI key must not silently own both domains; no extrapolation from Docker role counts |
| Consumer SaaS | Continue public projection/orchestration only; accurate uncertainty and cancellation boundaries | Creator and separate recipient must keep working with app/database gone; no real disclosure or production data introduced by this generation |

Decades-long obligations require algorithm migration (including quantum threats), periodic restore/refresh tests, cryptographic/OS maintenance, funded operators, backup retirement and organisational replacement. A permanently inaccessible secret is not a successful service. A new epoch cannot make copied old secrets unknown. PorterNet remains outside this implementation and is not necessary for any workstream.

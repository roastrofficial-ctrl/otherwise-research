# Survival is six separate measurable properties

| Required property | Executable evidence | Boundary |
|---|---|---|
| Policy remains interpretable | Registry contains immutable policy and referenced signed evidence; independent Python/Node validators | Only the bounded reference policy/suites are implemented; future readers need maintained specifications/software |
| Evidence independently recoverable | Witness records, fresh pinned checkpoints, immutable terminal certificates at witnesses and key holders | No SaaS DB authority; global loss/fork of every anchor is not recoverable by assertion |
| Cryptographic capabilities available | Custody2/3 AND authority2/3; recipient-bound contributions | Either domain losing threshold or recipient key can be fatal without legitimate pre-authorised backup |
| Creator-independent legitimate release | Public worker receives no owner/recipient secret, waits for missed-window evidence, orders RELEASE and exports portable package | A functioning independent worker/relay, committees and legitimate evidence remain operational dependencies |
| Unauthorised release constrained | Custody-only extraction still lacks B; policy-only/legacy downgrade cannot obtain honest v8 partials | Related provisioning, malicious creator, combined domains and shared admin still defeat secrecy |
| Recipient verifies/retrieves information | Separate encrypted configuration; package verified in network-disabled recipient container | Pinned expected commitment and recipient secret must survive; no SaaS screen can substitute |

## Dependency and recovery matrix

| Failure / transition | Without creator participation | Required prior authority / fatal condition |
|---|---|---|
| SaaS provider permanently disappears | Protocol/worker/recipient run without Laravel/accounts/database | No SaaS-owned keys or truth; independent endpoints/configuration must remain reachable |
| Creator device permanently disappears | Existing ARM/policy/registry and public worker suffice for release | Cancellation cannot be fabricated without the owner key; lack of a current device is not permission by itself |
| One witness retires or is unavailable | Remaining3 can provide evidence and consensus; failed leader can be replaced by view change | Further unavailable/Byzantine peers may remove quorum; membership does not auto-shrink |
| One witness restarts/restores an old snapshot | Fresh three-peer authenticated recovery preserves terminal/prepared proofs without owner signature | All3 other peers must be ready/cooperative; cold4-node restart or simultaneous extra withholding stalls uncommitted work |
| All witnesses inaccessible **after** RELEASE commitment | Retained full certificate at any holder/recipient is independently verified; providers need no new live witness authorisation | Certificate must be retrievable, both capability thresholds and recipient key must remain; absence of a retrieved certificate is uncertainty |
| All witnesses inaccessible **before** terminal decision | No new RELEASE or DISARM can be safely manufactured | Ready quorum or pre-authorised succession/state transfer needed. This prototype cannot bootstrap an entirely quarantined committee |
| One custodian and one authority holder retire | Remaining2/domain permit existing Capsules to release | Secrets/backups must remain independent; new creation currently provisions all configured holders |
| Losing a domain threshold / signing keys | Only legitimate backups or previously issued valid material can help | Otherwise release unavailable. A recovery admin with both complete components would collapse the trust model |
| Committee identity replacement during pending release | Refused by immutable registry; replay of old certificate into a new registry fails | Needs old/new quorum continuity and pre-authorised reconfiguration, not a mutable SaaS key list |
| Infrastructure migration with same identities | Can carry authenticated ciphertext/records and independently protected own keys to replacement hosts | Protect against rollback, key-copy accumulation, transport-directory substitution and common backup administration; no reviewed migration tool supplied |
| TLS credentials expire | Offline verification of historical Ed25519 proofs does not depend on an expired TLS leaf; renewed transport can restore access | Certificate/CA governance and independently authenticated endpoint changes need succession. Test CA validity is not a decades-long plan |
| Protocol version upgrade | Old proofs retain their original interpretation; portable package remains versioned | No silent upgrade of armed Capsules. Pre-authorised successor rules or explicit creator/recipient migration required |
| Cryptographic algorithm deprecated | New secure profiles can protect new ciphertext under authorised migration | Old copied classical ciphertext/keys cannot be made unknown; current P-256/Ed25519/AES assumptions are not post-quantum longevity guarantees |
| Administrative succession / shared update channel | Only if successors inherit constrained, independently governed roles | A shared host/backup/update administrator can steal both domains. Containers are not independent organisations |
| Recipient key permanently lost | No unilateral account reset or administrator substitution | Fatal unless an independently justified recipient recovery/multi-recipient scheme was committed in advance; not implemented |
| All state and backups rolled back/lost | No universal reconstruction of truth or secrets | Fresh independent anchors/checkpoints are necessary; total compromise/loss remains outside recovery guarantees |

The promise survives the tested disappearance scenario, not every disaster for decades. Current policies have bounded finite windows and the consensus harness has bounded views/retries. Autonomous operational pacemaking/gossip, safe membership reconfiguration, durable archival replication, long-lived key management and funded administration remain necessary. An inaccessible secret is a failure of useful service even when confidentiality survives.

No recovery actor gains unilateral authority to change policy, choose a new recipient or sign terminal permission. Recovery moves authentic surviving evidence and carries valid prepared/terminal proofs forward; it cannot turn an unsigned assertion or backup timestamp into creator intent.

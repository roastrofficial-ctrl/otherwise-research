# Reproduce the 0.6 laboratory

From the repository root, with Docker Desktop/Compose and an installed trusted checkout:

```sh
./scripts/experiment06.sh
./scripts/performance06.sh  # sequential fresh candidate and baseline clusters
python3 scripts/regression06.py
```

The Python regression command is a host-side Docker orchestrator; application/test code executes in containers. Each script creates a unique project, uses synthetic content, retains raw results in `doc/results06`, and removes only its own containers/networks/volumes on exit. Earlier outputs and existing demo projects are left intact. No global pruning is performed. Default explicit lab subnets use 10.206.6.0/24 through 10.206.12.0/24; inspect local routing/network allocations before moving this laboratory to another host. The 0.6 main subnet can be changed with `OTHERWISE_06_SUBNET`. The first script bootstraps ignored local test TLS certificates and secrets using the existing lab05 helper if needed. Certificates/CA are laboratory infrastructure, not a production identity service.

`Dockerfile.protocol06` contains only protocol/client/test dependencies. Compose starts four witness containers and three new custodian containers; no Laravel, database, mail, SMS or PorterNet service is started. Each custodian has only its own state volume and TLS private key; the client has the public CA and encrypted recovery volume. Existing lab05 fault capabilities are explicitly enabled for synthetic extraction, crash and rollback experiments. Never expose these profiles as production services.

## Interactive independent CLI

In a manually retained compose06 project (use a unique `COMPOSE_PROJECT_NAME`, `.env05`, compose05 + compose06, and test or real witness clocks deliberately), create an independently pinned public trust file. The tests discover pins locally only to bootstrap a trusted isolated experiment; production trust establishment is unresolved. Use an independently authenticated copy of that file, never a SaaS-provided replacement.

Inside the CLI container, where `/recovery/trust.json` contains those pins:

```sh
python -m Honest.cli --vault /recovery/owner.ovault --trust /recovery/trust.json create
python -m Honest.cli --vault /recovery/owner.ovault --trust /recovery/trust.json arm
python -m Honest.cli --vault /recovery/owner.ovault --trust /recovery/trust.json checkin
python -m Honest.cli --vault /recovery/owner.ovault --trust /recovery/trust.json status
python -m Honest.cli --vault /recovery/owner.ovault --trust /recovery/trust.json disarm
```

On a separate Capsule with a missed window, `evaluate` and `disclose` perform synthetic release. The recipient key is in this trusted local demonstration vault; no real recipient messaging is implemented. `OTHERWISE_CREATOR_PASSPHRASE` is supplied only to the local CLI (or entered interactively), never to SaaS. Keep an encrypted backup plus independently authenticated trust configuration and passphrase. Restoring clones authority; it does not revoke a stolen device. The 0.5 client/recovery/rotation workflows remain available unchanged, with their full regression.

`Honest.client.Client` is the experimental protocol adapter. Enrollment and partial-decryption endpoints are distinct from the static provider. Calling the 0.5 CLI against this provider fails capability negotiation; migration is explicit, not silent. Provisioning and arming are separate: a failed creation can leave an unarmed orphan enrollment. A failed arm/check-in/disarm is uncertain until independent recovery confirms a sufficient receipt quorum. A head mismatch calls for fresh collection, never trusting a server success string.

`scripts/fingerprint06.py` records a review fingerprint of the source in `Protocol/client06-build.json`. It is not a signature, secure updater, immutable installation or supply-chain proof. Authenticate a release/fingerprint out of band before granting the installed client access to keys. The earlier 0.5 source manifest is preserved unchanged and does not cover the new module.

## Recovery limits

Custodian normal restart retains its identity/share and requires fresh independent witness reads before any partial. Process crash tests use actual exit + Compose restart. Single-member availability faults additionally exercise live endpoints refusing operations. No proactive share refresh, DKG, committee replacement, provider secret backup restoration or cross-generation migration is implemented. Lost two shares means unavailable custody unless a separately trusted backup exists; such backups also count as compromise opportunities. Retained response substitution can be detected by an independently stored old receipt, not by a rolled-back database alone.

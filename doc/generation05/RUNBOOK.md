# Run 0.5 locally

Use synthetic data only. Docker/Compose and host OpenSSL are sufficient; PHP, Composer, Python dependencies, Node and PostgreSQL run in containers. This generation is separate from the 0.4 demo and uses port **8050**.

```sh
./scripts/lab05.sh up -d --build aw1 aw2 aw3 aw4 ak1 ak2 ak3 hostile product-db laravel
```

Open http://localhost:8050. This is deliberately an **operator-controlled public view**, not a trusted signing interface. It has no private-kit upload or browser key creation. Creator actions run in the independent CLI container, whose recovery volume and passphrase are absent from SaaS mounts/environment. `scripts/verify_isolation05.py` checks this configuration without exposing credentials.

The helper generates ignored mode-600 `.env05` lab credentials. Its creator passphrase goes only into the local client container. Do not use this convenience file, fault-injection setup or trusted shared Docker host as a production key-management design. Provider connections use certificate-verified HTTPS in this generation, including in the lab. The first `up` generates `.tls05` under a local test CA, with separate per-provider private-key mounts. The public CA is available to the client and SaaS courier; the CA private key is not mounted into either. Internal SaaS HTTP carries public signed material only. The one-year laboratory certificates and local host remain trusted setup, not a production PKI. No PorterNet setup is required.

## Trusted installation comes first

Review an independently obtained source copy and authenticate its expected source-manifest digest through a channel independent of the SaaS. The release experiment's manifest is `Protocol/client05-build.json`; its canonical-JSON SHA-256 is recorded in `doc/results05/client-build.txt`. Do **not** treat fetching those two files from the same compromised website as authentication.

From an already trusted toolchain/installation, verify the expected digest and included file hashes:

```sh
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.install_check --expected EXPECTED_INDEPENDENT_DIGEST
```

This is source/dependency-manifest verification, not secure boot or a cryptographically authenticated binary-release/update system. The Docker daemon, launch configuration, verification toolchain, dependency acquisition and device remain trusted. There is no client auto-update or code downloaded from SaaS during owner actions.

## Laboratory trust bootstrap

The lab can discover direct local provider identities into `/recovery/trust.json`:

```sh
./scripts/lab05.sh run --rm --no-deps cli python -c 'from tests05.helpers import configured; configured()'
```

This step trusts the isolated direct network. Authenticate provider keys and addresses independently for any stronger model; do not replace this file with identities returned by an untrusted SaaS account or courier. The same configuration travels with the encrypted backup.

## Solo lifecycle

```sh
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault create --rounds 2 --seconds 120
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault backup --out /recovery/offline-backup.ovault
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault arm
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault checkin --challenge 1
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault status
```

A real clock uses conservative intervals; immediately after creation an observation may be too early, so retry within the open window. A network error/failed quorum is uncertain, never a confirmed check-in. A successful command prints only public results after the updated encrypted vault has been durably written. Check-in generation/signing/encryption are local. The vault/passphrase is never a command argument or SaaS upload.

Copy the encrypted backup **off the shared Docker host** and retain its passphrase separately to model actual device/host loss. `/recovery` isolation alone does not survive host destruction. To publish only public material:

```sh
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault publish --saas http://laravel:8000
```

Disarm before closure, or miss the second window, wait for closure plus grace/clock uncertainty and request simulated release:

```sh
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/owner.ovault disarm
# On a separate missed-window Capsule, instead:
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/missed.ovault simulate
```

Status directly obtains fresh signed witness responses. Use `--transport httpclient` before the action to select the second adapter. `--relay http://laravel:8000` deliberately places the hostile courier in the witness path; independent direct paths remain the default. Custody enrollment never passes through that courier.

## Loss, replacement and rotation

Restore an encrypted backup to a **new** local vault path, then obtain fresh retained status:

```sh
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/replacement.ovault restore --out /recovery/offline-backup.ovault
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/replacement.ovault recover
./scripts/lab05.sh run --rm --no-deps cli python -m Untrusted.cli --trust /recovery/trust.json --vault /recovery/replacement.ovault rotate --out /recovery/new-owner.ovault
```

Restore clones the old signing authority. Rotation disarms the old Capsule, persists that result, creates a fresh key/Capsule and **persists the new encrypted capability before attempting arm**. A censored/failed replacement arm can be retried directly without losing that key. It is not an atomic in-place policy edit or remote revocation of a stolen device. See [recovery limits](RECOVERY.md).

## Reproduce hostile experiments

```sh
./scripts/experiment05.sh
./scripts/regression04-for05.sh
./scripts/experiment03.sh
```

The 0.5 script owns a unique temporary Compose project, uses controlled fault clocks, runs attacks/conformance/measurements, stops the actual Laravel/backend/PostgreSQL containers, deletes the experimental working-device vault, restores an older encrypted backup, repeats check-in/disarm/rotation, stops and restarts a witness, repairs it and demonstrates independent simulated release. It then removes only its own project/volumes. Results go to `doc/results05/`.

If the demo occupies port 8050, stop just its Laravel container before the full experiment and start it afterward. The separate 0.4 regression script starts only protocol providers, so it does not disturb the 8040 consumer. Earlier counterexamples remain in their original suites.

The reference witness restart rules are inherited: repair each affected Capsule with `repair --index N` and three other healthy peers. Committee-wide cold restart and custodian identity recovery are unsupported; stopping everything and starting it again is not automatically safe recovery. For a fresh synthetic demo use a distinct project name; do not delete existing volumes unless that loss is intended.

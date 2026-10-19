# Run the local consumer demonstration

Requires Docker Compose and host OpenSSL only for generating local lab credentials. PHP, Composer, Python dependencies, Node and PostgreSQL run in containers. No PorterNet installation or connection is involved.

```sh
./scripts/lab04.sh up -d --build aw1 aw2 aw3 aw4 ak1 ak2 ak3 protocol-adapter product-db laravel
```

Open **http://localhost:8040**. The default named project is `otherwise04`; `.env04` is generated once, ignored and mode 600. Do not publish this development server. The four real-clock witnesses must remain running. Create a synthetic Capsule, save its private recovery kit, arm, and click “I'm here” during a displayed window. Conservative real-clock intervals can require a short wait immediately after creation. Save the updated kit. Refresh to inspect evidence. To see release, miss the final check-in, wait through its deadline plus grace and clock uncertainty, evaluate, then simulate delivery. For the cancellation branch, create a fresh Capsule and disarm before closure begins.

This finite schedule allows one to eight windows. A checked-in first window plus a missed second window demonstrates the intended Solo transition. The engine conservatively closes every committed window before deciding release. The UI labels delivery simulated; the plaintext is a fixed synthetic sentence. There are no real disclosure destinations.

## Independent owner client

The client container has an independent `/recovery` volume; neither Laravel nor the adapter mounts it. A full CLI lifecycle needs no web application:

```sh
./scripts/lab04.sh run --rm --no-deps cli python -m Available.cli --kit /recovery/solo.json create --rounds 2 --seconds 120
./scripts/lab04.sh run --rm --no-deps cli python -m Available.cli --kit /recovery/solo.json arm
./scripts/lab04.sh run --rm --no-deps cli python -m Available.cli --kit /recovery/solo.json checkin --challenge 1
./scripts/lab04.sh run --rm --no-deps cli python -m Available.cli --kit /recovery/solo.json status
./scripts/lab04.sh run --rm --no-deps cli python -m Available.cli --kit /recovery/solo.json disarm
```

Choose `--transport httpclient` before the action to substitute the second adapter. On real clocks, wait until the full bounded observation interval is inside the first window before retrying an early check-in. A failed aggregate response does not imply no witnesses committed.

To use a browser-exported kit, mount its containing directory read/write into the CLI container and use that path as `--kit`:

```sh
./scripts/lab04.sh run --rm --no-deps -v "$PWD/recovery-export:/owner-kit" cli python -m Available.cli --kit /owner-kit/capsule.json status
```

Place your private JSON download at `recovery-export/capsule.json` first; keep it out of source control. The kit contains an owner signing seed and creator shares and is deliberately unsuitable for production secrets. The Docker host and local adapter are trusted for this synthetic demo.

## Repeat the research experiments

```sh
./scripts/experiment04.sh
./scripts/experiment03.sh
```

The first command builds a unique temporary Compose project, uses deterministic fault clocks, runs conformance, exercises real Laravel HTTP/CSRF, stops Laravel + PostgreSQL + adapter, operates the CLI independently, stops/restarts a witness, repairs it and removes only its own experiment volumes. The second reruns preserved 0.1–0.3 experiments and known counterexamples. They can be run independently. The 0.4 experiment currently publishes the same local port as the demo; stop the demo's Laravel container before running it if the port is occupied, then start it again afterward.

```sh
./scripts/lab04.sh stop laravel
./scripts/experiment04.sh
./scripts/lab04.sh start laravel
```

All raw outputs live in `doc/results04/`. `tests.txt` includes protocol-image exclusion and actual HTTPS adapter tests; `product.txt` verifies the actual frontend acknowledgement verifier under Node WebCrypto, not an interactive browser rendering audit.

A restarted **witness** requires owner-authenticated same-identity repair for each Capsule it serves:

```sh
./scripts/lab04.sh run --rm --no-deps cli python -m Available.cli --kit /recovery/solo.json repair --index 4
```

Three other healthy members must provide fresh checkpoints. A committee-wide stop/restart cannot self-bootstrap with this repair rule; do not claim it can. Identity loss and custodian recovery are unsupported and fail closed. Retain exported kits and keep enough independent witnesses online. For a clean synthetic reset, `./scripts/lab04.sh down -v` deletes the demo's protocol, custody, recovery and product volumes; use it only when that deletion is intended. Normal `stop` preserves volumes but triggers the explicit repair requirement when witnesses restart.

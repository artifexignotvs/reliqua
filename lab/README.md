# Disposable package-upgrade comparison

Start with the [field-test instructions](../docs/FIELD_TEST.md) and the
[comparison method](../docs/COMPARISON.md). This is an amd64 Ubuntu 24.04 experiment,
not an instruction to modify a production service.

```sh
python3 lab/build.py
python3 lab/run.py
```

The first command verifies pinned downloads, then builds an image. The second
creates a uniquely named container with no network, host mounts, published ports,
Docker socket, or host PID namespace. It copies diagnostic evidence out before
removing the container. The image remains available for subsequent runs; remove
it with `docker image rm reliqua-comparison-lab:1` when finished.

The executable source and lab configuration are fingerprinted at build time.
The runner refuses an image that no longer matches the checkout, and creates its
container from the verified image ID rather than a mutable tag. After changing
the source, rebuild before repeating the experiment.

## Controlled transitions

1. Start a real FPM master and two workers from Ubuntu package
   `8.3.6-0ubuntu0.24.04.12`.
2. Install five hash-pinned `.13` PHP packages using `dpkg`, with service restart
   suppressed. Prove that the same three process identities retain the deleted
   older executable, whose SHA-256 differs from the new executable.
3. Run both checkers sequentially against these retained workers. The worker
   identities must match before, between, and after the two commands.
4. Stop and restart FPM, then repeat the comparison with the new executable.
5. Drop `SYS_PTRACE` for both checkers. Verify that known FPM processes really
   cannot be inspected, rather than simulating permission errors in a fixture.
6. Evaluate the current report against a two-node manifest containing one absent
   node. The comparison checker does not implement this fleet feature.

No exploit or HTTP request is sent. Installing packages, executing PHP, and
restarting FPM are explicit actions of this disposable harness. RELIQUA collection
itself remains read-only. The comparison checker executes local PHP for version
and configuration observations; that execution trust differs from RELIQUA.

## Inputs, capabilities and output

`pins.json` records the base-image digest, immutable Ubuntu snapshot dates, old
and new PHP package SHA-256 values, and the comparison script commit and hash.
The comparison project's MIT license is fetched and retained with its script.
The initial CA certificate package is also verified before it bootstraps TLS
inside the base image. Repository signature verification stays enabled.

Runtime memory is capped at 768 MiB, CPU use at two CPUs and processes at 192.
All Docker capabilities are dropped, then only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`,
`KILL`, `SETGID`, `SETUID`, `SETPCAP`, and `SYS_PTRACE` are added. They permit the
isolated package upgrade, FPM user transitions and shutdown, and process
observation. The denied-inspection check removes `SYS_PTRACE` for both tools.
`no-new-privileges` remains enabled. No privileged container mode is used.

The run has a five-minute execution limit, with separately bounded setup and
cleanup. Cleanup attempts removal even if stopping or copying evidence fails;
an unsuccessful cleanup makes the run fail. New result directories under
`reports/lab-<random>/` are private and never overwrite an earlier run.

Only `shareable-summary.json` is designed for public review: it contains input
versions and hashes, scenario outcomes, counts and fixed labels. It omits raw
process identities, host details, paths and finding text. Inspect it before
sharing. The `raw/` directory and other diagnostic files remain private. Nothing
is uploaded automatically, and a maintainer run is not an independent field test.

The comparator's overall result and process finding are displayed separately.
A stale-process warning must not be hidden behind its overall result. This lab
does not assign a general winner, reproduce exploitation, or establish that a
production rollout is complete.

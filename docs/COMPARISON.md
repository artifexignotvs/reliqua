# Reproducible comparison: a PHP update and its remaining workers

This lab asks one operational question: **can a completed package update be
treated as evidence that the expected PHP workers are current?** It compares
observations from two tools on the same controlled PHP-FPM deployment. It is
not an exploit test, a performance benchmark or a general ranking of PHP tools.

## Independent comparator

The comparator is [EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check),
version `2.0.0`, pinned to commit
[`06aee3de3e2a9d612331edaffd86552b7df4b01e`](https://github.com/EXT-IT/php2shell-check/tree/06aee3de3e2a9d612331edaffd86552b7df4b01e).
The reviewed script SHA-256 is:

```text
79780b2fba67b1aad6725f354fc273a03899edadba17348b2c9a6c66c30d47b8
```

Its scope is broader than RELIQUA: it checks PHP installations, distribution
package versions, configuration and deployment details. Its process check
already identifies deleted PHP executable and module mappings. We selected it
because that overlaps the question under test, rather than comparing with a
version-only check. [Pinned source](https://github.com/EXT-IT/php2shell-check/blob/06aee3de3e2a9d612331edaffd86552b7df4b01e/php2shell-check.sh)

The comparator is independently maintained by EXT IT GmbH under the
[MIT license](https://github.com/EXT-IT/php2shell-check/blob/06aee3de3e2a9d612331edaffd86552b7df4b01e/LICENSE).
This repository does not copy its implementation. The lab obtains the exact
upstream script separately and verifies its checksum before execution. Its
copyright notice is retained. No endorsement is implied.

The local invocation is:

```sh
bash /opt/comparison/php2shell-check.sh --json --no-containers --no-logs
```

No URL or origin is supplied. Container discovery is disabled because both
tools run inside the same test container. Log history is outside this experiment.
The comparator invokes installed PHP binaries to read version/configuration;
RELIQUA reads process and package evidence without invoking PHP. The lab uses a
trusted vendor binary in a disposable environment for this reason.

## Four cases and an observation rule

| Case | Controlled condition | Question |
| --- | --- | --- |
| Current workers | Reviewed Ubuntu package; master and workers can be inspected | Do the observed mappings match current files? |
| Retained pre-update workers | Vendor package is updated while service restart is inhibited | Is the old loaded file identity reported? |
| Restricted inspection | Current workers exist, but inspection of workers is denied | Does the result expose this evidence gap? |
| Missing declared node | A manifest expects two aliases; only one fresh report is supplied | Does the evidence set cover the declared deployment? |

Both tools run in the same case before any restart or further state change.
The lab records the PHP PID/start identities around the pair of observations.
An unexpected worker restart invalidates that comparison instead of being
silently accepted as equivalent input. Each tool gets the same permissions.

The rollout case uses genuine Ubuntu packages before and after the fix in a
disposable, isolated container. No service is exposed and no exploit payload is
sent. It checks the update/restart boundary; it does **not** demonstrate an
exploit or establish whether a host was previously compromised.

The missing-node row is a RELIQUA contract test. The comparator does not consume
our manifest or claim that all declared nodes supplied reports. Its result for
that row is **outside scope**, never a failure or a claimed competitive win.

## Read the whole outcome

Record these separately for every observed case:

- command exit code;
- tool's unmodified overall status;
- individual process findings and warnings;
- observed process count and any inaccessible process evidence;
- declared-node coverage where the tool supports it.

Do not equate the tools' status vocabulary. The comparator's process warning
does not itself force a nonzero exit code. Therefore a result of
`not-vulnerable` can coexist with a stale-process warning. Reporting only its
exit code would conceal useful detection and misrepresent the comparison.
[Pinned summary logic](https://github.com/EXT-IT/php2shell-check/blob/06aee3de3e2a9d612331edaffd86552b7df4b01e/php2shell-check.sh#L1847)

RELIQUA's `OBSERVED_CURRENT` also has a limited meaning: the collected, recognized
processes and reviewed package records matched during the observation. It is
not proof of absence of compromise, complete memory integrity or full service
discovery. Its conservative result for an unreviewed build is not proof that
the build is vulnerable.

## Reproduction and reporting

Use the pinned lab instructions with an isolated test container. Do not run the
package-upgrade case on a production server. Host access to Docker Engine is
required to build and run the lab. No public ports, host PID namespace, host
credentials or container-management socket are exposed inside the lab container.
No exploit requests are sent. Runtime observations run with networking disabled;
building the test image and obtaining the comparator require downloads.

Keep raw reports private. Share the lab summary and a short account of any
blocker; do not send production hostnames, process arguments or customer data.
If your result differs, include the lab revision, operating system, architecture,
container runtime, case name and exact error after removing identifying data.

Passing our own lab is internal validation. A second run by the same maintainer
is still internal validation. Independent reproduction requires another person
to run the published procedure and supply their own outcome. We do not count
downloads, invitations or consent alone as completed reproductions.

This first comparison covers one Ubuntu PHP-FPM layout. Container discovery,
RPM distributions, web-server configuration, unusual embedded runtimes and
remote checks are not evaluated here. A useful next change should follow an
observed blocker or a confirmed discrepancy, not a larger feature checklist.

## Observed results, 2026-10-22

This is an internal run, not an independent reproduction. The lab used Linux
amd64, Ubuntu 24.04 and the real vendor upgrade from
`8.3.6-0ubuntu0.24.04.12` to `8.3.6-0ubuntu0.24.04.13`. The master and two
workers retained their identities across the package upgrade. Each tool pair
observed the same three FPM process identities without a restart between tools.
The [reviewed machine-readable result](comparison-result.json) records exact
input hashes and observation counts. Raw process evidence remains private.

| Case | RELIQUA result / exit | Comparator result / exit | Comparator process finding |
| --- | --- | --- | --- |
| Current workers | `OBSERVED_CURRENT` / `0` | `not-vulnerable` / `0` | `ok` |
| Retained pre-update workers | `ACTION_REQUIRED` / `1` | `not-vulnerable` / `0` | **`warn`: retained old executable detected** |
| Restricted inspection | `INCOMPLETE` / `2` | `not-vulnerable` / `0` | `ok`, despite three unreadable executable links |
| Missing declared node | `INCOMPLETE` / `2` | Outside scope | Outside scope |

Both tools detected the retained old executable. The difference in that row is
the exit policy, not detection. The comparator also produced configuration
warnings; the table separates its process finding from the overall result so
those warnings are not mistaken for an undetected condition.

For the restricted-inspection row, the process list still contained three FPM
processes, and the checking process still had effective UID 0. Dropping
`SYS_PTRACE` made the executable links and maps of all three inaccessible. The
comparator's process check skipped those reads and emitted its `ok` finding.
That is a concrete inspection gap in this pinned version, rather than evidence
that every run of the comparator gives an incorrect result.

A narrow local correction was then tested against the same live FPM processes.
With the same denied reads, it returned a process `unknown` finding and exit 2;
with inspection permission restored it retained process `ok` and exit 0. The
patch and regression tests can be reviewed by the upstream maintainer; local
validation does not mean upstream acceptance.

To reproduce the comparison from this repository:

```sh
python3 lab/build.py
python3 lab/run.py
```

The original pinned comparator is used for the comparison; the proposed
correction is not silently substituted. The runner saves a shareable summary
separately from private raw evidence under `reports/`. See
[the field test instructions](FIELD_TEST.md) for the requested feedback and
privacy boundary.

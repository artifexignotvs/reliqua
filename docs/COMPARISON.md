# Reproducible comparison: a PHP update and its remaining workers

This lab asks one operational question: **can a completed package update be
treated as evidence that the expected PHP workers are current?** It compares
observations from two tools on the same controlled PHP-FPM deployment. It is
not an exploit test, a performance benchmark or a general ranking of PHP tools.

## Independent comparator

The comparator is [EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check),
version `3.0.1`, pinned to commit
[`1279546c98631b86ccc59d880281a25fe59f6453`](https://github.com/EXT-IT/php2shell-check/tree/1279546c98631b86ccc59d880281a25fe59f6453).
The reviewed script SHA-256 is:

```text
35fae5bce152630248edce9de4a73791dda4ba542924c276b7ba1368c7b2b51f
```

Its scope is broader than RELIQUA: it checks PHP installations, distribution
package versions, configuration and deployment details. Its process check
already identifies deleted PHP executable and module mappings. We selected it
because that overlaps the question under test, rather than comparing with a
version-only check. [Pinned source](https://github.com/EXT-IT/php2shell-check/blob/1279546c98631b86ccc59d880281a25fe59f6453/php2shell-check.sh)

The comparator is independently maintained by EXT IT GmbH under the
[MIT license](https://github.com/EXT-IT/php2shell-check/blob/1279546c98631b86ccc59d880281a25fe59f6453/LICENSE).
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
[Pinned summary logic](https://github.com/EXT-IT/php2shell-check/blob/1279546c98631b86ccc59d880281a25fe59f6453/php2shell-check.sh#L1868)

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

## Current observed results, 2026-10-23

This is an internal run against upstream `3.0.1`, not an independent reproduction.
The lab used Linux amd64, Ubuntu 24.04 and the real vendor upgrade from
`8.3.6-0ubuntu0.24.04.12` to `8.3.6-0ubuntu0.24.04.13`. The master and two
workers retained their identities across the package upgrade. Each tool pair
observed the same three FPM process identities without a restart between tools.
The [current machine-readable result](comparison-result.json) records exact
input hashes and observation counts. Raw process evidence remains private.

| Case | RELIQUA result / exit | Comparator 3.0.1 result / exit | Comparator process finding |
| --- | --- | --- | --- |
| Current workers | `OBSERVED_CURRENT` / `0` | `not-vulnerable` / `0` | `ok` |
| Retained pre-update workers | `ACTION_REQUIRED` / `1` | `not-vulnerable` / `0` | **`warn`: retained old executable detected** |
| Restricted inspection | `INCOMPLETE` / `2` | `undecided` / `2` | **`unknown`: three visible processes cannot be inspected** |
| Missing declared node | `INCOMPLETE` / `2` | Outside scope | Outside scope |

Both tools detect the retained old executable and expose the restricted-inspection
gap. The difference for retained workers is the exit policy, not detection. The
comparator also produces configuration warnings; this table separates its process
finding from the overall result. The missing-node case remains outside its scope.
This run does not establish that RELIQUA is necessary for an operator who already
has an adequate process with the updated checker.

The lab runner verifies both tools' expected statuses, exits and process findings.
A changed comparator outcome makes the run fail for review rather than silently
being accepted as a favourable comparison. All four cases completed in this run;
this is functional validation, not a speed claim.

## Historical result and upstream correction

The [unchanged historical summary](comparison-result-v2.0.0.json) records the
2026-10-22 run against version `2.0.0`, commit
[`06aee3de3e2a9d612331edaffd86552b7df4b01e`](https://github.com/EXT-IT/php2shell-check/tree/06aee3de3e2a9d612331edaffd86552b7df4b01e).
Its script SHA-256 is
`79780b2fba67b1aad6725f354fc273a03899edadba17348b2c9a6c66c30d47b8`.
The historical lab source fingerprint is retained inside that summary. To recover
its exact harness, use RELIQUA revision
[`69267210df93173ef8531b371145d9c0fb595351`](https://github.com/artifexignotvs/reliqua/tree/69267210df93173ef8531b371145d9c0fb595351).

In that earlier restricted-inspection case, the process list contained three FPM
processes and the checker still had effective UID 0. Dropping `SYS_PTRACE` made
all three executable links and maps inaccessible. Version `2.0.0` skipped those
reads and emitted process `ok`, overall `not-vulnerable`, exit `0`. The other
three rows were unchanged from the outcomes above.

The upstream maintainer reproduced the gap, incorporated the contributed fix in
[version 3.0.0](https://github.com/EXT-IT/php2shell-check/releases/tag/v3.0.0),
and refined the Apache maps-read check in
[version 3.0.1](https://github.com/EXT-IT/php2shell-check/releases/tag/v3.0.1).
The [maintainer's response](https://github.com/EXT-IT/php2shell-check/pull/1#issuecomment-6361957236)
records acceptance. The current lab uses the released upstream code without a
local patch. **The old inspection gap is fixed in the version now tested.**
The historical file is retained for provenance, not presented as current behaviour
or evidence of an ongoing advantage.

## Repeat the current comparison

```sh
python3 lab/build.py
python3 lab/run.py
```

The runner saves a shareable summary separately from private raw evidence under
`reports/`. See [the field-test instructions](FIELD_TEST.md) for the requested
feedback and privacy boundary. If you ran the earlier harness, record that
revision with its result; do not relabel an old observation as a `3.0.1` run.

# An unreadable PHP worker is not a clean result

*23 October 2026 · Reproduction, upstream fix and follow-up*

During RELIQUA's package-update comparison, an existing PHP checker reported
that no process was running a replaced PHP binary. Three PHP-FPM processes
were visible, but their executable links could not be read. The process check
had skipped failed reads and reached its clean-result branch.

We sent a small correction and eleven regression cases to the maintainers of
[EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check). They reproduced
the problem, incorporated the change and released it in
[version 3.0.0](https://github.com/EXT-IT/php2shell-check/releases/tag/v3.0.0).
The contributed cases then exposed a separate BusyBox compatibility problem,
which the maintainer corrected in
[3.0.1](https://github.com/EXT-IT/php2shell-check/releases/tag/v3.0.1).

## The condition we could reproduce

The original comparison used Ubuntu 24.04 and real PHP-FPM packages inside a
disposable container. A master and two workers were observed before, between
and after each pair of checker invocations. The harness verified their process
identities so a restart could not silently change the comparison.

For one case, both checkers lost the `SYS_PTRACE` capability. The inspecting
process still had effective UID 0, but reads of the known workers' executable
links and maps were denied. Container root did not imply unrestricted access
to those process records.

The pinned 2.0.0 checker treated a failed executable-link read as a reason to
skip that process. With no stale executable recorded, it emitted process
`ok`. RELIQUA reported `INCOMPLETE`. This was an inspection-coverage problem;
it did not show that the workers were vulnerable or that exploitation occurred.

There was also a separate retained-worker case. **Both tools detected the old
executable in that case.** A process warning and an overall exit code are
different outputs. An exit of zero alone was never evidence of missed detection.

## The correction

The patch distinguishes an inspected process from a visible process whose
restart state cannot be determined. It uses available process metadata to
recognize relevant PHP/Apache processes when executable inspection fails,
retains existing stale-process warnings, and reports an `unknown` process
finding when relevant reads remain unavailable. Exited processes and zombies
are handled separately.

The eleven regression cases cover current and deleted executables, denied
reads, mixed stale and unreadable workers, Apache mappings, unrelated
processes and process-lifecycle cases. They test the narrow decision boundary;
they do not prove that all PHP processes can be discovered.

[The original pull request](https://github.com/EXT-IT/php2shell-check/pull/1)
was incorporated under a different
[upstream commit](https://github.com/EXT-IT/php2shell-check/commit/afdfc06eb769f6c599a0965400dde2042a5c360b).
Its closed status is therefore not a rejection. The commit retains Artifex
Ignotvs as author, and the release credits the contribution.

## What independent review added

The maintainer [reported reproducing the original condition in a normal PHP
container](https://github.com/EXT-IT/php2shell-check/pull/1#issuecomment-6361957236).
Our regression cases also uncovered a portability difference: BusyBox `grep`
can return a no-match status for an unreadable mapping input. The maintainer's
3.0.1 follow-up adds a separate readability check before matching. That follow-up
is their correction, prompted by the contributed tests.

The released 3.0.0 and 3.0.1 shell scripts were checked against their tagged
source and published checksums. Both contain the incomplete-inspection logic.
The original pinned comparison remains historical evidence; it must not be
presented as a defect still present in those releases.

## What remains worth testing

The [current comparison](COMPARISON.md) includes the fixed upstream version.
RELIQUA's separate question is whether a declared set of nodes has supplied
fresh, consistent runtime reports. Missing-node coverage is outside the other
checker's claimed scope, not a failed test for that checker. Neither tool's
result proves that a system was never compromised.

Upstream acceptance confirms one useful contribution. It is not a completed
independent RELIQUA trial or a customer endorsement. If you maintain PHP
deployments, the [isolated field test](FIELD_TEST.md) asks whether the remaining
evidence workflow adds anything to your existing procedure. Setup failures and
“my current process already does this” are useful answers. No production data,
credentials, star or positive review is requested.

*Quod non videtur, non probatur.*

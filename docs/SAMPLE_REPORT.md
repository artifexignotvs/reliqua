# Sample operator report: PHP update evidence

**Observation date:** 2026-10-22  
**Evidence source:** maintainer-operated, isolated lab on Ubuntu 24.04, Linux amd64.  
**Status:** internal validation; no customer deployment or independent reproduction.

## Decision summary

The installed package update alone did not establish that the running PHP-FPM
processes used the updated executable. A master and two workers retained their
old mappings after the real vendor package upgrade. Both RELIQUA and the comparator
detected the retained executable; RELIQUA required action, while the comparator
reported a process warning alongside overall `not-vulnerable` and exit `0`.

For an operator, this supports reviewing the restart or rollout before closing
that update task. Denied inspection and a missing declared-node report instead
require more evidence. Neither can be treated as a successful observation.

## Recorded outcomes

Each paired observation used the same three FPM process identities with the same
permissions, without a restart between tools. The missing-node case is a separate
manifest check, with one of two declared reports absent.

| Controlled case | RELIQUA result / exit | Comparator result / exit | Evidence and operator decision |
| --- | --- | --- | --- |
| Current workers | `OBSERVED_CURRENT` / `0` | `not-vulnerable` / `0`; process `ok` | Three recognized processes had current components. Accept this bounded observation; retain separate service and coverage checks. |
| Retained pre-update workers | `ACTION_REQUIRED` / `1` | `not-vulnerable` / `0`; process **`warn`** | Three processes produced `ARTIFACT_GAP`, `BUILD_UNVERIFIED` and `RESTART_REVIEW`. Review the retained master/workers, complete the normal rollout, then recollect. |
| Restricted inspection | `INCOMPLETE` / `2` | `not-vulnerable` / `0`; process `ok` | All three known processes had unreadable executable links. RELIQUA recognized no web processes and reported collection gaps. Resolve visibility before deciding whether those processes are current. |
| Missing declared node | `INCOMPLETE` / `2` | Outside scope | One required report was missing. Obtain a fresh report for that declared node, or reconcile the declaration with the actual inventory. |

The comparator detected the old executable despite its zero exit code; the
difference there is exit policy, not detection. Its overall warning counts were
four, five and four for the first three rows, respectively. Read the individual
process finding separately from configuration warnings. The restricted-inspection
gap applies to the pinned version and tested condition. A declared-node manifest
is outside the comparator's stated scope and is not scored as a failure.

## Reproducible artifact record

| Item | Recorded value |
| --- | --- |
| RELIQUA source version | `0.1.0a1` |
| Lab | `ubuntu24-fpm-package-upgrade-v1` |
| Vendor package transition | `8.3.6-0ubuntu0.24.04.12` → `8.3.6-0ubuntu0.24.04.13` |
| Comparator | EXT-IT/php2shell-check `2.0.0`, commit `06aee3de3e2a9d612331edaffd86552b7df4b01e` |
| RELIQUA source SHA-256 | `18f35a5ea75c890374ae5a4ab6fa629ab553045defc7371be24c8e9a16d6c27e` |
| Lab source SHA-256 | `e6d500fa73f337e4e59154994677b6c380feeb83535179a60aa856317af41199` |

The [machine-readable evidence](comparison-result.json) also pins the base image,
comparator script and both FPM executable digests. These source digests identify
the tested inputs; they are not a claim about a later download. The original
comparator was used, without substituting a proposed correction. Its independent
maintainer and MIT license attribution are recorded in the
[comparison method](COMPARISON.md#independent-comparator).

## Limits and next action

This was one disposable Ubuntu PHP-FPM layout, with runtime networking disabled
and zero requests sent. It was not a production assessment, exploit test or
performance benchmark. Raw process evidence remains private; this report contains
no customer identity, network addresses, process identifiers or private paths.

`OBSERVED_CURRENT` means the collected, recognized processes and reviewed package
records agreed at observation time. It does not establish whole-fleet discovery,
request routing, service availability, memory integrity or absence of prior
compromise. The [evidence model](EVIDENCE.md) and [collector contract](CONTRACT.md)
define those boundaries. An unfamiliar build is not thereby proven vulnerable.

**Next action:** obtain an independent run using the
[field-test procedure](FIELD_TEST.md). Record setup blockers and whether any
finding changes the operator's update decision. This maintainer run supplies a
sample deliverable for the pilot; it does not count toward independent validation.

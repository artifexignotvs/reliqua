# Evidence model and trust boundaries

RELIQUA is an observational remediation aid. It does not enforce access, prevent
code execution, authenticate vendor binaries or certify that a host is clean.

## Four separate questions

1. **Package record:** does a locally installed binary/source package match an exact
   reviewed fix record for this distribution release?
2. **File consistency:** does the current artifact match the local package manifest?
3. **Running correspondence:** does the loaded artifact still refer to that current
   file, with stable observed process and file identities?
4. **Declared coverage:** is fresh evidence present for every operator-declared
   node, without unresolved findings inside each observed scope?

The result `OBSERVED_CURRENT` means these observations agree. It never means
"all PHP on this machine is safe" or "all requests reach a patched worker".
`complete` in JSON means no known evidence gaps within the declared observation,
not exhaustive discovery or a service-level guarantee.

## What is trusted

The kernel, collector, clock, local package manager/database, downloaded tool and
administrative transport are trusted. A malicious root user or compromised kernel
can forge observations. A repackaged binary and matching modified package metadata
can impersonate a vendor version. RELIQUA does not independently check repository
signatures or reconstruct package provenance. Use your established package trust
and host-integrity controls.

The local package manifest commonly uses MD5. That comparison detects ordinary
file divergence; it is not an authenticity mechanism and is not suitable for
establishing resistance to deliberate collision attacks. SHA-256 in a report
identifies the current file; it does not identify the live process's private memory.

## Running code is not the same as installed files

The collector inspects executable and PHP module mappings. It compares device and
inode identifiers, reads current artifacts, and rechecks process start identity,
executable and mappings. A replaced/deleted mapping is a convergence finding, even
when the old build might already have been fixed. A worker's recent start time is
not sufficient: a newly forked worker can inherit a master's old mappings.

These checks reduce common races but are not atomic. They cannot establish that
private mapped memory is unchanged, or rule out in-place modifications, runtime
instrumentation or a later deployment. A busy process changing mappings can
produce incomplete evidence. Quiesce deployment churn and recollect when practical.

Read restrictions, transient PIDs and recognized foreign mount/root namespaces are
reported as gaps. The collector does not enter foreign namespaces or resolve their
package databases. Run it inside each relevant container instead.

Discovery is a bounded heuristic over visible processes, known executable names
and `libphp` mapping names. A differently named static PHP runtime can be missed.
PID namespaces and proc visibility settings can hide processes without permission
errors. Stopped services, disk-only installations, endpoints, virtual hosts and
remote nodes are outside discovery. The manifest is your inventory declaration,
not an automatically discovered proof of completeness.

## File format

A private report is a JSON envelope with `schema`, `payload` and `sha256`. The
checksum is SHA-256 over sorted-key, compact, ASCII JSON for the payload. JSON
numbers must be finite and duplicate keys are rejected. See `reliqua/evidence.py`.

An attacker who can edit a report can recompute its checksum. There is no digital
signature, secret key, remote attestation or independent timestamp authority.
Use a trusted collection/transfer channel. Imported labels are never authoritative;
assessment is recomputed using the verifier's current bundled policy.

Evidence records node alias, timestamp, boot/process identity, operating-system
release, artifact paths/digests and selected package metadata. It excludes process
arguments, environment variables, request bodies, application files, hostnames and
network addresses. Local paths and aliases can still be sensitive. Output files use
mode 0600, must be new regular files, and are never overwritten.

Raw reports are limited to 8 MiB. Fleet evaluation supports at most 256 declared
nodes with an evidence age of 60–86400 seconds; the default is 900 seconds. A
five-second future-clock tolerance is allowed. Duplicate evidence for one node is
rejected even if one file is newer. Provide exactly one current report per alias.

## Snapshot comparison

`compare` requires the same alias and scope, and a newer second timestamp. It
compares `(boot_id, pid, start_ticks)`, so PID reuse after reboot is not counted as a
retained process. It does not infer process lineage, successful restart commands,
request-route coverage or service availability. It re-evaluates both snapshots
against the installed policy; it is not a record of older policy decisions.

## Policy maintenance

The bundled table uses exact reviewed native package versions. It rejects other
versions conservatively, including newer fixes and binary rebuild revisions, until
reviewed. No broad greater-than comparison is used to turn an unfamiliar package
into a passing result. Adding support requires an authoritative vendor notice,
source/binary mapping, fixtures and a reviewed release. Old or unmatched versions
are not automatically classified as vulnerable because custom backports exist.

Primary records:

- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Debian CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [Debian CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619)
- [Linux process information](https://docs.kernel.org/filesystems/proc.html)

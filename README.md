# RELIQUA

**After the PHP update, what still runs?**

Read-only terminal evidence for PHP2Shell remediation: compare loaded PHP artifacts
with current files, check exact reviewed vendor package builds, and require fresh
reports from every node you declare.

**Public alpha · Linux · Python 3.11+ · no runtime Python dependencies · MIT**

> An installed update is one piece of evidence. A remaining old worker is another.
> RELIQUA keeps them separate. It does not block exploits or replace the PHP update.

[Download the alpha](https://github.com/artifexignotvs/reliqua/releases/tag/v0.1.0-alpha.1)
· [Evidence and limits](docs/EVIDENCE.md) · [Incident response workflow](docs/OPERATIONS.md)

## Try the decision model

Download `reliqua.pyz` and `SHA256SUMS` from the release, then:

```sh
sha256sum --ignore-missing -c SHA256SUMS
python3 reliqua.pyz demo
```

```text
RELIQUA  /  synthetic decision demo

Patched package, old worker               ACTION_REQUIRED
Reviewed backport, current image          OBSERVED_CURRENT
Custom build without vendor evidence     INCOMPLETE
Unreadable process coverage              INCOMPLETE
Only CLI PHP observed                    INCOMPLETE
One declared node missing                INCOMPLETE
```

These examples are synthetic. `demo` does not inspect your computer or send requests.
Checksums detect download corruption; obtain the checksum file through a trusted channel.

## Inspect your own Linux node

Run in the host or container namespace you intend to inspect, with permission to
read its process metadata. Use an operator alias rather than an identifying hostname.

```sh
mkdir -m 700 reports
python3 reliqua.pyz scan --node edge-a --out reports/edge-a.json
python3 reliqua.pyz inspect reports/edge-a.json --json
```

Without sufficient `/proc` access, the result will be incomplete. Administrators
may run the reviewed artifact with elevated local read access when appropriate.
RELIQUA never elevates privileges itself, runs PHP, executes discovered binaries,
changes configuration, restarts a service, installs patches, or sends network requests.

`--pid 123 --pid 124` restricts inspection to selected processes. Such reports
cannot satisfy the fleet gate. A snapshot covers recognized processes visible
in the collector's namespace, **not every PHP application on a host or network**.

## Require evidence from every declared node

Create a manifest with a separate alias for each host/container you need to review:

```json
{"schema": 1, "nodes": ["edge-a", "edge-b"], "max_age_seconds": 900}
```

Collect one report inside each declared node, transfer the files over your trusted
administrative channel, and evaluate them together:

```sh
python3 reliqua.pyz fleet --manifest fleet.json \
  reports/edge-a.json reports/edge-b.json --out reports/summary.json
```

Missing, expired, future-dated, duplicate, conflicting or unexpected reports prevent
completion. Assessments are recomputed from raw evidence; an imported status label
is ignored. The summary omits local paths, process IDs and boot identifiers. Node
aliases remain, so review them before sharing. Reports are unsigned and must come
from a trusted operator/channel; their checksum is not proof of origin.

## Interpret the result

| Result | Meaning | Exit |
|---|---|---:|
| `OBSERVED_CURRENT` | Within the observed scope, PHP core file identities match disk and the locally trusted package record matches a reviewed vendor fix. | 0 |
| `ACTION_REQUIRED` | A replaced/deleted loaded artifact or a package-file mismatch needs investigation. This is not itself proof of exploitation. | 1 |
| `INCOMPLETE` | Evidence is missing, unreadable, unsupported, outside the reviewed catalog, or otherwise insufficient. | 2 |
| Input/operating error | Invalid evidence, failed checksum, inaccessible output or another input failure. | 64 |

A clean result says nothing about past compromise, load-balancer routes, effective
application configuration or future attacks. An empty inventory never passes.
`inspect` describes a historical snapshot; `fleet` enforces freshness.

## What the alpha checks

- PHP-FPM and CGI executables; Apache `libphp` mappings; recognized embedded runtimes.
- Deleted or replaced executable/module mappings, device/inode correspondence,
  process start identity, namespace/root differences and observation races.
- Local dpkg ownership, source package, exact full version, installed status and
  package-file checksum. MD5 here is the package manager's file-consistency check,
  not cryptographic authenticity. A separate SHA-256 describes the observed file.
- Reviewed fixes for Ubuntu 22.04/24.04/26.04/26.10 and Debian 12/13, including
  backports whose PHP version remains older than an upstream fixed release.
- Before/after process identity comparison, checksummed JSON evidence, bounded
  inputs and private output files that are never overwritten.

```sh
python3 reliqua.pyz policy
python3 reliqua.pyz compare reports/before.json reports/after.json --json
```

**Deliberately conservative:** only exact vendor builds in the bundled policy
qualify. A newer build, private rebuild, other distribution or legacy backport
returns incomplete until reviewed; it is not automatically called vulnerable.
No live advisory feed or custom policy bypass is included in this alpha.

Discovery uses known executable names and `libphp` mapping names. Renamed/static
embedded PHP, hidden PIDs, stopped services and other PID namespaces may be missed.
CLI-named PHP is unresolved because it can itself serve HTTP. Inspect each relevant
namespace and reconcile the declared-node manifest with your actual deployment.
See the [full trust model](docs/EVIDENCE.md).

## Why this exists

The October 21 PHP advisory covers CVE-2026-109618 and CVE-2026-109619. Application
middleware cannot be a complete answer to a failure that may occur before the
application starts. Apply the vendor patch; use runtime evidence to review the
rollout. [PHP advisory](https://www.php.net/archive/2026.php)

Stale-process detection is not new. Useful neighboring tools include
[php2shell-check by MakFly](https://github.com/MakFly/php2shell-check) and
[php2shell-check by EXT-IT](https://github.com/EXT-IT/php2shell-check).
RELIQUA focuses on a small offline evidence format and a conservative declared-node
gate. It does not claim to replace vulnerability management, WAFs or incident response.

## Develop and review

```sh
python3 -m unittest discover -s tests -v
python3 -m reliqua demo
python3 tools/build_zipapp.py
```

Tests cover vendor records, stale mappings, permission failures, process churn,
namespace mismatches, evidence corruption and fleet coverage. Live replacement
tests use a benign local process; no exploit payloads or crash probes are included.
Please report unsupported layouts with a **sanitized** example and reproduction
steps. Do not attach raw production snapshots to a public issue.

*Quod restat, observa.*

# PHP rollout evidence pilot

**Find the remaining old workers and the gaps in your update evidence.**

For administrators and hosting teams who need to review a PHP update across a
small, declared set of Linux services. The operator runs RELIQUA locally; the
maintainer helps interpret a deliberately limited, sanitized result.

Start with the free [isolated field test](FIELD_TEST.md). Read the
[sample report](SAMPLE_REPORT.md) to see the kind of output this pilot aims to
produce. The sample is a maintainer laboratory run, not a customer result.

## Proposed scope

The first assisted pilot covers one agreed PHP deployment layout, one update
review, and at most five operator-selected host or container aliases. A container
namespace is a separate observation scope. The operator confirms that the
declared inventory represents the services they intend to review.

Before starting, agree the supported OS/package build, intended runtime,
collection permissions, scope, operator availability and the exact deliverable.
The bundled `policy` command lists the exact reviewed package builds. An
unreviewed or newer build is incomplete until reviewed; this is not a claim that
it is vulnerable. The initial reproducible lab covers Ubuntu 24.04 PHP-FPM on
amd64. Other layouts require a fit check rather than an assumed pass.

## Who does what

| Operator | Maintainer |
| --- | --- |
| Reviews the tool and authorizes its local use. | Explains the evidence contract and checks whether the proposed scope fits it. |
| Runs the collector with locally approved permissions. | Helps diagnose sanitized setup blockers. |
| Keeps credentials and raw process reports in their own environment. | Reviews only the agreed, minimized summary. |
| Applies updates and restarts through their existing process. | Identifies which observations need follow-up; does not operate the service. |
| Checks application health and any evidence of compromise separately. | Records these as separate operator checks, never as conclusions from RELIQUA. |

No remote shell access, cloud account, inbound service or production report
upload is required. Do not add privileges solely to make a result green. Missing
permissions and unavailable nodes are valid incomplete results.

## Deliverable

One short report containing:

- The agreed scope, collection period and reviewed tool revision.
- One outcome for each declared alias: observed current, action required, or
  incomplete, with the evidence supporting that conclusion.
- Retained workers, missing reports, unsupported builds and other coverage gaps.
- A follow-up list owned by the operator, plus the result of an agreed recheck
  if fresh evidence is available.
- Installation, collection, review and support time recorded separately.
- A comparison with the operator's existing process: what changed a decision,
  what added no value, and whether they would use it again.

The report is a bounded observation. It is not an audit certificate, incident
response service, application-health guarantee, or proof that a system has never
been compromised. RELIQUA does not patch, restart, block requests or take other
active actions.

## Evidence stays with the operator

Use non-identifying aliases and keep their mapping local. Raw reports and
`compare` output may contain process identifiers, paths and finding details;
do not share them publicly. Even the minimized fleet summary retains aliases
and must be reviewed before sharing. Sharing is optional and must stay within
the operator's permission to disclose information.

The public issue form is for fit and setup questions only. Do not attach
production evidence, credentials, addresses, customer names or private paths.
If an engagement needs private operational evidence, agree a suitable private
channel, permitted contents and retention before sending anything. We do not
need that material for the isolated field test.

## Decide whether to continue

Agree the success criteria before a customer trial. Record the existing process's
time and outcome on the same scope, then record RELIQUA's result and additional
effort. Keep a useful finding, an incomplete observation and an installation
failure separate. A result that adds no value is a valid reason to stop.

The isolated laboratory test and its feedback are free. A paid continuation, if
useful, would have its scope, fee, availability and deliverables agreed separately
before work starts. There is no charge for expressing interest. The public tool
remains available under its existing MIT license.

To discuss fit, [open a pilot-interest issue](https://github.com/artifexignotvs/reliqua/issues/new?template=pilot-interest.yml)
with non-sensitive details, or reply to an existing invitation. A request is not
a confirmed engagement; no successful customer pilot is claimed here.

*Primum observa.*

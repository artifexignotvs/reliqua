# Independent field test

**Does this add useful evidence to your PHP update procedure?**

This pilot asks for a small comparison and an honest account of what got in the
way. A result that shows no useful difference is valuable. No endorsement,
production access or customer data is requested.

## Optional first step: review the existing results

You can start without installing anything: read the
[four-row result table and its limits](COMPARISON.md#current-observed-results-2026-10-23).
These are maintainer results, not an independent reproduction.

Reply to the invitation with a short answer to one question: **Which, if any,
of these results would change a PHP update or restart decision beyond what
your existing checks already tell you?** "None" is a useful answer.

This is feedback on documented results. It does not imply agreement to test
and does not count as an independent run. Continue below if you want to
reproduce the comparison in the isolated lab.

## What you will run

A disposable Ubuntu 24.04 container starts PHP-FPM on an older package, installs
the reviewed fixed package without restarting its workers, and checks it again
after a restart. RELIQUA and the pinned EXT-IT `php2shell-check` version `3.0.1` inspect the same
test environment. Additional cases restrict process inspection and omit one
declared node from a fleet report. There is no exploit payload or attack traffic.

Read the [comparison method and limits](COMPARISON.md) before interpreting the
results. A missing-node gate is a RELIQUA feature; it is not a capability that the
other checker claims to provide. Its warning text matters separately from its exit
status. Version `3.0.1` includes the upstream fix for the inspection gap found
in the earlier comparison; both tools now report that gap in this lab. This is
a narrow experiment, not a ranking of security products.

## Requirements and time

- Linux on amd64, Python 3.11 or newer, and a working Docker Engine accessible to
  your account. Other architectures and emulation have not been validated.
- About 2 GB of free disk space. Initial downloads and the image build need
  internet access; duration depends on your connection and machine. The Docker
  build stage stops after 20 minutes. Setup time is **additional** to the trial.
- Allow 10 minutes for the comparison after the image is built. The runner has a
  five-minute execution limit and reports failures instead of waiting indefinitely.

The image build downloads pinned sources and packages. During the comparison the
container has no network, published ports, host directory mounts or host process
namespace. It uses explicitly limited resources and capabilities. Docker access
is itself a privileged facility: review `lab/build.py`, `lab/run.py`, and the
Dockerfile before running them. The test changes packages only inside its disposable
container; do not transplant its setup commands into a production system.

## Run it

Clone the public repository or use an existing checkout. Record the revision so
another reviewer can repeat your result:

```sh
git clone https://github.com/artifexignotvs/reliqua.git
cd reliqua
git rev-parse HEAD
python3 lab/build.py
python3 lab/run.py
```

If setup fails, stop there. A precise setup blocker is a useful pilot result;
there is no need to grant extra privileges or spend an afternoon debugging it.

The runner prints its result directory under `reports/`. The file named
`shareable-summary.json` contains an allowlisted summary of the lab, versions and
outcomes. The `raw/` directory contains local diagnostic evidence; do not attach it
to a public issue. Nothing is uploaded automatically. Inspect even the shareable
summary before publishing it.

## Tell us what happened

Reply to the invitation or [open a field-test issue](https://github.com/artifexignotvs/reliqua/issues/new?template=field-test.yml).
The useful minimum is:

1. The revision, whether setup and the four cases completed, and approximate time
   spent on setup and on the comparison separately.
2. The first blocker, if any: the step and a short sanitized error. No hostnames,
   IP addresses, process IDs, credentials, customer names or private file paths.
3. Which result would change an operational decision, and what your existing
   process or checker already makes equally clear.
4. One concrete reason you would use this again, or why you would not.

You may attach the reviewed `shareable-summary.json`. Do not send production
snapshots. No star, follow, testimonial or positive result is required. Being
contacted, agreeing to try, and completing an independent run are counted
separately. A maintainer run is not an independent run.

## What this pilot decides

The initial target is three independent runs, with setup failures and confusing
results recorded alongside successful runs. We will fix the first repeatable
blocker before expanding scope. A useful outcome is evidence that operators need
this distinction in their actual rollout process; attention metrics alone do not
establish that need.

*Experimento, non fama.*

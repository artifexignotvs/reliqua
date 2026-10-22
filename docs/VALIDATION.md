# Alpha validation

Validation date: 2026-10-22. Results describe the tested artifact, not a general
security certification.

- 84 automated tests exercise decision boundaries, package metadata, mapping
  changes, process races, namespace gaps, corrupt/malformed/oversized evidence,
  FIFO rejection, private output handling and declared-node coverage.
- A benign live process test replaces a copied executable while it runs and checks
  that collection and assessment produce a restart-review finding.
- An isolated Ubuntu 24.04 container installed the real vendor package
  `php8.3-fpm 8.3.6-0ubuntu0.24.04.13`. Default container permissions produced an
  incomplete result for inaccessible workers. With the inspection permission needed
  in that test container, the FPM master and two workers matched their current
  artifacts and reviewed package record; the visible-process assessment returned
  `OBSERVED_CURRENT` with exit 0.
- A second isolated Ubuntu 24.04 test used Apache with
  `libapache2-mod-php8.3 8.3.6-0ubuntu0.24.04.13`. All six observed Apache processes
  matched their current PHP module and vendor package record. The visible-process
  assessment returned `OBSERVED_CURRENT` with exit 0.
- The source-only application archive is reproducible. An isolated installation of
  the wheel passed the offline demo.

No exploit payloads, crash probes or requests to third-party PHP services were used.
Test containers exposed no host ports and were removed afterwards. Raw operational
reports, boot identities and local validation paths are not published.

Version support records for other listed releases are covered by policy and parser
fixtures; those records do not imply live integration testing on every distribution
or architecture. CI runs the Python tests on 3.11, 3.12, 3.13 and 3.14.

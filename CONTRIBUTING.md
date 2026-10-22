# Contributing

A useful change should include a reproducible failure case and a bounded fix.
Run `python3 -m unittest discover -s tests -v` before proposing it.

For vendor records, link the official notice for both CVEs and add a test of the
exact OS release, binary/source identity and native version. Do not loosen unknown
results into passing states based only on a version banner or custom assertion.

Keep collection read-only, avoid untrusted executable discovery, retain uncertainty,
and keep operational data out of fixtures. Synthetic aliases and paths are preferred.
Source comments may use short Latin phrases when their meaning remains clear.

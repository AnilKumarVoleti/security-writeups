# Security write-ups

Independent vulnerability research, published after coordinated disclosure with the maintainers.

| Advisory | Product | Severity | Status |
|---|---|---|---|
| [DRXStore 2.0.0 — broken authorization to remote code execution](drxstore-2.0.0/) | DRXStore (PHP, self-hosted pharmacy system) | 8.8 High | fixed in 3.0.0, CVE pending |

Each directory contains the write-up, the proof-of-concept scripts, the raw evidence and the
verification of the fix. Every report here was produced against a local installation only, disclosed
privately to the maintainer first, and published after a fix shipped.

## How these are verified

Claims are reproduced with real requests, and patches are checked by running the same probe against
both the vulnerable and the fixed version — a proof of concept that fails because it broke would
otherwise look the same as one that fails because the bug is gone.

## Contact

Anil Kumar Voleti — [LinkedIn](https://www.linkedin.com/in/voleti-anil/) ·
[GitHub](https://github.com/AnilKumarVoleti)

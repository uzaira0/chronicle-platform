# Chronicle Hetzner Security Exceptions

No open exceptions.

CVE-2026-54369 (`libacl`, HIGH) was accepted on 2026-07-19 and closed on 2026-10-21: the
`percona-distribution-postgresql:18.6.1-4` base no longer reports it in the HIGH/CRITICAL
trivy scan. Before the next Hetzner deployment, rebuild the hardened Percona image, rerun
that scan, update the allowed image ID in the NixOS policy, pass the isolated backup
restore drill, and pass `verify-stack.sh`.

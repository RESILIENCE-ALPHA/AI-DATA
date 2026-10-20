# Runbook: brute force on the login (auth_bruteforce)

Draft written by IA/DATA so the RAG step has context. CYBER owns the real
remediation runbooks; replace or complete this file with theirs.

## Signs

One source IP produces many failed logins in a short time: dozens of failures in
10 to 60 seconds, almost no success, often on a few targeted accounts or on many
different accounts (password spraying), at a regular machine-like pace.

## Action: block_ip

Block the source IP first. It stops the attack at once and protects the accounts.
Never block a protected IP (demo laptop, jury, traffic generator, venue network).

## Action: restart_service

Restart the auth service when it is degraded by the attack (errors, slow answers,
saturated connections) or after the block, to come back to a clean state.

## Check

After remediation, a new test payment must succeed: it proves the platform has
recovered with no human action.

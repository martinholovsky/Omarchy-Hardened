# Security policy

This project changes authentication, firewall and kernel settings on the
machine it runs on. A bug here can lock a user out or quietly leave them less
protected than the output claims.

## Reporting

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/martinholovsky/Omarchy-Hardened/security/advisories/new),
not in a public issue.

Especially wanted: any case where the playbook reports success but a setting
is not actually in force, for example an Omarchy change that makes a role's
edit a silent no-op.

## Supported versions

Only `main` is supported while the project is pre-1.0.

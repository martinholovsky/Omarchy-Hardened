# Security policy

This project changes authentication, firewall and kernel settings on the
machine it runs on. A bug here can lock a user out or quietly leave them less
protected than the output claims.

## Reporting

While the repository is private, report vulnerabilities to the owner
directly, not in an issue. GitHub's private vulnerability reporting is not
available on private repositories (the API returns 404). Turn it on when the
repo goes public, and link it here.

Especially wanted: any case where the playbook reports success but a setting
is not actually in force, for example an Omarchy change that makes a role's
edit a silent no-op.

## Supported versions

Only `main` is supported while the project is pre-1.0.

#!/bin/bash
# Vendored from basecamp/omarchy @ dde0d123bb7e130cb7c8a679ed9d3b8b2a11887e:
# install/config/firewall.sh lines 1-11 (rule set only; the ufw-docker part
# is dropped), plus the rule bin/omarchy-setup-security-sshd adds when the
# user opts into SSH. Upstream licence: MIT — see LICENSE.omarchy.
set -euo pipefail
# Allow nothing in, everything out.
ufw default deny incoming
ufw default allow outgoing

# Allow ports for LocalSend.
ufw allow 53317/udp
ufw allow 53317/tcp

# Allow Docker containers to use DNS on host.
ufw allow in proto udp from 172.16.0.0/12 to 172.17.0.1 port 53 comment 'allow-docker-dns'
ufw allow in proto udp from 192.168.0.0/16 to 172.17.0.1 port 53 comment 'allow-docker-dns'

# bin/omarchy-setup-security-sshd:73
ufw limit 22/tcp comment "omarchy-sshd" >/dev/null

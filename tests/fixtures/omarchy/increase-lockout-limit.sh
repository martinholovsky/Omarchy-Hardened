#!/bin/bash
# Vendored from basecamp/omarchy @ dde0d123bb7e130cb7c8a679ed9d3b8b2a11887e
# install/config/increase-lockout-limit.sh (system-auth part only; the
# sddm-autologin lines are dropped because the test image has no sddm).
# Upstream licence: MIT, Copyright (c) David Heinemeier Hansson — see
# tests/fixtures/omarchy/LICENSE.omarchy. Used only to reproduce the PAM
# state Omarchy leaves behind.
set -euo pipefail
sed -i 's|^\(auth\s\+required\s\+pam_faillock.so\)\s\+preauth.*$|\1 preauth silent deny=10 unlock_time=120|' \
           /etc/pam.d/system-auth
sed -i 's|^\(auth\s\+\[default=die\]\s\+pam_faillock.so\)\s\+authfail.*$|\1 authfail deny=10 unlock_time=120|' \
           /etc/pam.d/system-auth

#!/usr/bin/env bash
# D-25 end to end: opensnitchd -> aegis-egress-collector -> audit.
#
# Usage: tests/vm/egress.sh   (after tests/vm/run.sh, VM still running)
#
# A copy of curl that no package owns connects out with a marker on its
# command line; the audit must name it, must not name the packaged curl, and
# the marker must reach neither the collector's state nor its journal.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"

die() {
  printf 'egress.sh: %s\n' "$*" >&2
  exit 1
}

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}
readonly MARKER=AEGIS-EGRESS-MARKER-7f3c
readonly PROBE=".local/bin/aegis-probe-curl"
readonly STATE_FILE=/var/lib/private/aegis-egress/egress.json

export ANSIBLE_CONFIG="$repo/ansible.cfg"
export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
play=(uv run --project "$repo" ansible-playbook -i "$here/inventory.yml" -u "$user"
  --private-key "$state/id_ed25519" --become-password-file "$state/become-password"
  -e "@$here/vm-vars.yml" "$repo/omarchy-harden.yml" --tags opensnitch)

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"
[[ $(vm_state) == running ]] || die "start with the VM running, after tests/vm/run.sh"

finding() {
  guest_root cat /var/lib/aegis/audit.jsonl | python3 -I -c 'import json,sys
for line in sys.stdin:
    f = json.loads(line)
    if f["id"] == sys.argv[1]:
        print(f["status"], f["detail"]); break
else:
    print("MISSING")' "$1"
}

echo "--- the collector runs, sandboxed"
[[ $(guest_root systemctl is-active aegis-egress-collector.service) == active ]] || die "collector not active"
exposure=$(guest_root systemd-analyze security --no-pager aegis-egress-collector.service | tail -1)
echo "  $exposure"
score=$(sed -nE 's/.*exposure level[^0-9]*([0-9]+\.[0-9]+).*/\1/p' <<<"$exposure")
if [[ -z $score ]] || ! awk -v s="$score" 'BEGIN{exit !(s <= 3.0)}'; then
  die "exposure score '$score' is not at most 3.0"
fi
echo "PASS: aegis-egress-collector active, systemd exposure $score"

echo "--- a packaged and an unowned program connect out"
guest_ssh "install -D -m 755 /usr/bin/curl \$HOME/$PROBE"
guest_ssh "curl -s -m 60 -o /dev/null https://archlinux.org/" || die "packaged curl could not connect"
guest_ssh "\$HOME/$PROBE -s -m 60 -o /dev/null -H 'X-Marker: $MARKER' https://archlinux.org/" || die "probe could not connect"
# Wait for the collector's own save (every 30 s) rather than restarting it:
# opensnitchd can send an event after the connection is done, and one that
# arrives while the collector restarts is lost (measured 2026-10-25: of three
# fast probes restarted at once, one arrived later and one never did).
for _ in $(seq 10); do
  sleep 9
  paths=$(guest_root python3 -I -c 'import json,sys; print("\n".join(e["path"] for e in json.load(open(sys.argv[1]))["entries"]))' "$STATE_FILE")
  grep -qx "/home/$user/$PROBE" <<<"$paths" && break
done
grep -qx "/home/$user/$PROBE" <<<"$paths" || die "collector did not record the probe within 90 s; recorded: $(sort -u <<<"$paths" | tr '\n' ' ')"
echo "PASS: opensnitchd -> collector recorded the probe ($(wc -l <<<"$paths" | tr -d ' ') programs in the table)"

! guest_root grep -q "$MARKER" "$STATE_FILE" || die "a command line reached the collector's state file"
! guest_root journalctl -u aegis-egress-collector.service --no-pager | grep -q "$MARKER" \
  || die "a command line reached the collector's journal"
echo "PASS: the marker on the probe's command line is in neither the state file nor the collector's journal"

echo "--- the audit names the unowned program only"
"${play[@]}" >"$state/egress-audit.log" 2>&1 || die "opensnitch run failed, see $state/egress-audit.log"
got=$(finding egress.unknown_programs)
[[ $got == "WARN "*"/home/$user/$PROBE ->"* ]] || die "egress.unknown_programs: $got"
[[ $got != *"/usr/bin/curl ->"* ]] || die "a package-owned program was reported: $got"
echo "PASS: ${got:0:120}..."

echo "--- clean up"
guest_ssh "rm -f \$HOME/$PROBE"
echo "Done."

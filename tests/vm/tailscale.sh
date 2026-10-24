#!/usr/bin/env bash
# D-10/D-24 against a real tailnet: Headscale and a second Tailscale node run
# as rootless containers inside the test VM, so no account, relay or TLS is
# needed and nothing listens outside the VM (tests/vm/README.md §7).
#
# Usage: tests/vm/tailscale.sh   (after tests/vm/run.sh, VM still running)
#
# Checks that with Tailscale's default netfilter mode a tailnet peer reaches a
# port ufw does not allow, and that the audit says so (WARN); then, as the
# control, that in nodivert mode ufw governs tailscale0, the port is closed
# and the finding no longer warns.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"

die() {
  printf 'tailscale.sh: %s\n' "$*" >&2
  exit 1
}

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}

# Digests resolved from Docker Hub on 2026-10-24.
readonly HS_IMG=docker.io/headscale/headscale@sha256:780ed2f9e85719a2211277433f2c8afb45105d0d25031949a6848a485f9e216d # v0.29.5
readonly TS_IMG=docker.io/tailscale/tailscale@sha256:b11583ad2e93e4671128538c88cf11f460444a5d7e449311dd1933a400ab849d # v1.104.2
# Not 22: the VM keeps Omarchy's SSH rule open for the harness (vm-vars.yml).
readonly PORT=2200
readonly LOGIN=http://127.0.0.1:8080

export ANSIBLE_CONFIG="$repo/ansible.cfg"
export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
play=(uv run --project "$repo" ansible-playbook -i "$here/inventory.yml" -u "$user"
  --private-key "$state/id_ed25519" --become-password-file "$state/become-password"
  -e "@$here/vm-vars.yml" -e "aegis_overlay_ssh_port=$PORT" "$repo/omarchy-harden.yml" --tags overlay)

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"
[[ $(vm_state) == running ]] || die "start with the VM running, after tests/vm/run.sh"

# Status and detail of one finding in the guest's latest audit file.
finding() {
  guest_root cat /var/lib/aegis/audit.jsonl | python3 -I -c 'import json,sys
for line in sys.stdin:
    f = json.loads(line)
    if f["id"] == sys.argv[1]:
        print(f["status"], f["detail"]); break
else:
    print("MISSING")' "$1"
}
# "<http code> <curl exit>" for a port as the probe node sees it. The first
# dial through the probe's SOCKS proxy can fail (curl exit 97) even when the
# path is open, so callers retry before believing a failure.
probe() {
  guest_ssh "curl -s -m 8 -o /dev/null -w '%{http_code} ' --socks5-hostname 127.0.0.1:1055 http://$vm_ip:$1/; echo \$?" || true
}
# Connected = curl reached the port, whatever spoke there (sshd is not HTTP).
connected() { [[ $1 != *" 97" && $1 != *" 28" && $1 != *" 7" ]]; }

echo "--- install Tailscale as Omarchy does (pacman, enable tailscaled)"
guest_root pacman -S --needed --noconfirm tailscale podman >/dev/null
guest_root systemctl enable --now tailscaled.service

echo "--- Headscale and a probe node (rootless podman, loopback only)"
guest_ssh 'mkdir -p ~/aegis-hs/config ~/aegis-hs/lib ~/aegis-hs/run'
guest_ssh 'cat > ~/aegis-hs/config/config.yaml' <"$here/tailscale/headscale.yaml"
guest_ssh 'cat > ~/aegis-hs/config/derp.yaml' <"$here/tailscale/derp.yaml"
guest_ssh "podman rm -f aegis-hs aegis-probe >/dev/null 2>&1 || true
  podman run -d --name aegis-hs --network host -v \$HOME/aegis-hs/config:/etc/headscale:ro \
    -v \$HOME/aegis-hs/lib:/var/lib/headscale -v \$HOME/aegis-hs/run:/var/run/headscale $HS_IMG serve >/dev/null"
for _ in $(seq 20); do guest_ssh "curl -sf -m 2 $LOGIN/health >/dev/null" && break; sleep 2; done
guest_ssh "curl -sf -m 2 $LOGIN/health >/dev/null" || die "Headscale did not come up"
guest_ssh 'podman exec aegis-hs headscale users create aegis-test >/dev/null 2>&1 || true'
uid=$(guest_ssh 'podman exec aegis-hs headscale users list -o json' |
  python3 -I -c 'import json,sys; print([u["id"] for u in json.load(sys.stdin) if u["name"]=="aegis-test"][0])')
key=$(guest_ssh "podman exec aegis-hs headscale preauthkeys create --user $uid --reusable --expiration 1h -o json" |
  python3 -I -c 'import json,sys; print(json.load(sys.stdin)["key"])')
# Omarchy's installer runs `tailscale up --accept-routes`; only the server differs.
guest_root tailscale up --login-server="$LOGIN" --authkey="$key" --accept-routes --hostname=aegis-vm --reset
vm_ip=$(guest_ssh 'tailscale ip -4')
guest_ssh "podman run -d --name aegis-probe --network host -e TS_USERSPACE=true -e TS_AUTHKEY=$key \
  -e TS_HOSTNAME=aegis-probe -e TS_SOCKET=/tmp/aegis-probe.sock -e TS_SOCKS5_SERVER=127.0.0.1:1055 \
  -e TS_EXTRA_ARGS=--login-server=$LOGIN $TS_IMG >/dev/null"
# The first connection fails until the two nodes have a direct path.
joined=false
for _ in $(seq 20); do
  if guest_ssh "podman exec aegis-probe tailscale --socket=/tmp/aegis-probe.sock ping -c 1 $vm_ip >/dev/null 2>&1"; then
    joined=true && break
  fi
  sleep 3
done
[[ $joined == true ]] || die "the probe node never reached $vm_ip over the tailnet"
echo "PASS: VM ($vm_ip) and probe node joined the test tailnet"

echo "--- a listener on $PORT that ufw does not allow"
guest_root systemd-run --unit=aegis-overlay-listener --property=DynamicUser=yes --collect \
  python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1 || guest_root systemctl restart aegis-overlay-listener
guest_ssh "for _ in \$(seq 10); do ss -ltn | grep -q ':$PORT ' && exit 0; sleep 1; done; exit 1" || die "listener did not start"
! guest_root ufw status | grep -Eq "^$PORT/tcp" || die "ufw allows $PORT; the test needs it closed"

echo "--- netfilter mode on (Omarchy's default): Tailscale bypasses ufw"
for _ in $(seq 10); do got=$(probe "$PORT"); [[ $got == "200 0" ]] && break; sleep 3; done
[[ $got == "200 0" ]] || die "the probe did not reach $PORT ($got); has Tailscale stopped bypassing ufw? D-24's WARN would then be stale"
"${play[@]}" >"$state/tailscale-on.log" 2>&1 || die "overlay run failed, see $state/tailscale-on.log"
got=$(finding network.overlay)
[[ $got == "WARN "*"accepts every inbound connection"* ]] || die "network.overlay: $got"
echo "PASS: a tailnet peer reaches a port ufw denies, and the audit WARNs: ${got:0:90}..."

echo "--- control: netfilter mode nodivert, ufw governs tailscale0"
guest_root tailscale set --netfilter-mode=nodivert
# Control: port 22 stays open (Omarchy's SSH rule, kept by vm-vars.yml), so
# the probe path works and a failure on $PORT is the firewall, not the probe.
for _ in $(seq 5); do got=$(probe 22); connected "$got" && break; sleep 3; done
connected "$got" || die "in nodivert mode the probe cannot reach port 22 either ($got)"
for _ in 1 2 3; do
  got=$(probe "$PORT")
  ! connected "$got" || die "in nodivert mode the probe still reached $PORT ($got)"
done
"${play[@]}" >"$state/tailscale-nodivert.log" 2>&1 || die "overlay run failed, see $state/tailscale-nodivert.log"
got=$(finding network.overlay)
[[ $got == "PASS "*"ufw governs"* ]] || die "network.overlay in nodivert mode: $got"
echo "PASS: in nodivert mode the port is closed and the finding passes"
guest_root tailscale set --netfilter-mode=on

echo "--- SSH findings on the harness's key-only sshd"
got=$(finding ssh.password_auth)
[[ $got == "PASS "* ]] || die "ssh.password_auth: $got"
got=$(finding ssh.authorized_keys)
[[ $got == "INFO "*"ssh-ed25519"* ]] || die "ssh.authorized_keys: $got"
echo "PASS: key-only sshd passes; the harness's ssh-ed25519 key is reported as not hardware-backed"

echo "--- clean up"
guest_root systemctl stop aegis-overlay-listener || true
guest_root tailscale logout || true
guest_ssh 'podman rm -f aegis-probe aegis-hs >/dev/null' || true
echo "Done."

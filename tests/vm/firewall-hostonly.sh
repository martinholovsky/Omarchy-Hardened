#!/usr/bin/env bash
# Firewall with real traffic from another machine (open-items §1). Gives the
# VM a second NIC on a VirtualBox host-only network for the length of the
# test, then probes it from this host before and after hardening:
#   - SSH (22) is reachable before and dropped after on that interface
#     (aegis_firewall_remove_ssh: true, the default). The harness keeps SSH
#     through a rule limited to the NAT interface it uses.
#   - LocalSend (53317/tcp) is allowed before (refused: nothing listens) and
#     dropped after. ufw drops, so a blocked port times out; a refused port
#     was let through.
#   - Docker DNS (172.17.0.1:53/udp) still answers a container after
#     hardening; control: without the rule it does not.
# Host-only, not bridged: on 2026-10-25 a NIC bridged to this Mac's Wi-Fi got
# no DHCPv4 lease, and host-only keeps the guest off the LAN. ufw does not
# care which kind of interface the traffic arrives on. Starts from the
# pre-aegis-hw snapshot; removes the NIC and the host-only network at the end.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"
die() { printf 'firewall-hostonly.sh: %s\n' "$*" >&2; exit 1; }

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}
snapshot=${AEGIS_VM_SNAPSHOT:-pre-aegis-hw}
readonly alpine=docker.io/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
# A subnet clear of the LAN (192.168.2.0/24 here), VirtualBox NAT
# (10.0.2.0/24) and Docker (172.16.0.0/12).
readonly net=aegis-fwtest net_prefix=192.168.56.

export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
play=(uv run --project "$repo" ansible-playbook -i "$here/inventory.yml" -u "$user"
  --private-key "$state/id_ed25519" --become-password-file "$state/become-password"
  -e "@$here/vm-vars.yml" -e aegis_firewall_remove_ssh=true "$repo/omarchy-harden.yml")

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"

remove_nic() {
  VBoxManage controlvm "$vm" poweroff >/dev/null 2>&1 || true
  for _ in $(seq 15); do [[ $(vm_state) == poweroff ]] && break; sleep 2; done
  # Right after a power-off VirtualBox can still hold the session lock, and
  # modifyvm fails (it took 2 attempts on 2026-10-25). Retry, then say so if
  # the NIC is still there.
  for _ in $(seq 15); do
    VBoxManage modifyvm "$vm" --nic2 none >/dev/null 2>&1 && break
    sleep 2
  done
  if VBoxManage showvminfo "$vm" --machinereadable | grep -q '^nic2="none"$'; then
    echo "  second NIC removed"
  else
    printf 'firewall-hostonly.sh: could not remove nic2; run: VBoxManage modifyvm %s --nic2 none\n' "$vm" >&2
  fi
  VBoxManage hostonlynet remove --name="$net" >/dev/null 2>&1 || true
}
trap remove_nic EXIT

echo "--- restore $snapshot, add a NIC on host-only network $net (${net_prefix}0/24)"
remove_nic
VBoxManage snapshot "$vm" restore "$snapshot" >/dev/null
VBoxManage hostonlynet add --name="$net" --netmask=255.255.255.0 \
  --lower-ip="${net_prefix}100" --upper-ip="${net_prefix}199" --enable >/dev/null
VBoxManage modifyvm "$vm" --nic2 hostonlynet --host-only-net2="$net" >/dev/null
ensure_running

# NAT is the interface with VirtualBox's 10.0.2.x address; the probe target
# is the guest's address on the host-only subnet.
nat_if=$(guest_ssh "ip -4 -o addr show" | awk '$4 ~ /^10\.0\.2\./ {print $2; exit}')
[[ -n $nat_if ]] || die "no NAT interface in the guest"
target=''
for _ in $(seq 12); do
  target=$(guest_ssh "ip -4 -o addr show" | awk -v p="$net_prefix" 'index($4, p) == 1 {sub(/\/.*/, "", $4); print $4; exit}')
  [[ -n $target ]] && break
  sleep 5
done
[[ -n $target ]] || { guest_ssh 'ip -br addr' >&2; die "the host-only NIC got no address"; }
echo "  NAT: $nat_if, host-only address: $target"
# Probe on-link only. On 2026-10-25 a connect to an unused address behind the
# router (10.255.255.1:22) came back "open" from this host; on-link addresses
# answered honestly (refused, or timeout).
if route -n get "$target" | grep -q 'gateway:'; then
  die "$target is reached through a gateway; probes would not be direct"
fi

# open | refused | timeout, from this host to the guest's host-only address.
# (Python, not nc: which nc is on PATH varies, and their flags differ.)
probe() {
  python3 -I -c 'import socket, sys
s = socket.socket()
s.settimeout(5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    print("open")
except ConnectionRefusedError:
    print("refused")
except (TimeoutError, socket.timeout):
    print("timeout")
except OSError as e:
    print("error: %s" % e)' "$target" "$1"
}

docker_dns() { # exit 0 if a container resolves a name through 172.17.0.1
  guest_root docker run --rm --dns 172.17.0.1 "$alpine" nslookup -timeout=5 archlinux.org >/dev/null 2>&1
}

echo "--- Omarchy as installed (control)"
before22=$(probe 22) before53317=$(probe 53317)
echo "  22: $before22, 53317/tcp: $before53317"
[[ $before22 == open ]] || die "SSH is not reachable before hardening ($before22); the probe cannot see the change"
[[ $before53317 == refused ]] || die "53317 is not refused before hardening ($before53317); expected Omarchy's allow rule with no listener"
guest_root systemctl start docker
docker_dns || die "Docker DNS does not work before hardening; nothing to keep"
echo "PASS: control: SSH open, LocalSend allowed, Docker DNS answers"

echo "--- harden (SSH removed, except on the NAT interface the harness uses)"
guest_root ufw allow in on "$nat_if" to any port 22 proto tcp >/dev/null
guest_root pacman -S --needed --noconfirm ansible-core >/dev/null
"${play[@]}" >"$state/firewall-hostonly.log" 2>&1 || { tail -30 "$state/firewall-hostonly.log"; die "playbook failed"; }
guest_root ufw status | sed 's/^/  /'

after22=$(probe 22) after53317=$(probe 53317)
echo "  22: $after22, 53317/tcp: $after53317"
[[ $after22 == timeout ]] || die "SSH is $after22 after hardening, expected dropped (timeout)"
[[ $after53317 == timeout ]] || die "53317 is $after53317 after hardening, expected dropped (timeout)"
ssh_up || die "the harness lost SSH on the NAT interface"
echo "PASS: SSH and LocalSend are dropped from another machine; SSH still works where allowed"

guest_root systemctl restart docker
docker_dns || die "Docker DNS broke after hardening"
guest_root ufw delete allow proto udp from 172.16.0.0/12 to 172.17.0.1 port 53 >/dev/null
if docker_dns; then
  die "Docker DNS answered without its rule; the check cannot see the firewall"
fi
guest_root ufw allow proto udp from 172.16.0.0/12 to 172.17.0.1 port 53 >/dev/null
docker_dns || die "Docker DNS did not come back with its rule"
echo "PASS: Docker DNS answers after hardening, and not without its rule"
echo "  not tested: 53317/udp (a dropped and an unanswered UDP probe look the same from here)"
echo "Done. The second NIC and the host-only network are removed on exit."

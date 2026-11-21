#!/usr/bin/env bash
# D-37 end to end: every Tetragon policy fires on the technique it watches and
# stays quiet on the look-alike a desktop does every day.
#
# Usage: tests/vm/tetragon.sh   (after tests/vm/run.sh, VM still running;
#                                vm-vars.yml turns aegis_tetragon_enabled on)
#
# Each "attack" is harmless: it reads a dummy key it planted, appends a comment
# it removes again, loads and unloads the in-tree `dummy` module from a copy in
# /tmp, loads a two-instruction socket filter, and attaches ptrace to its own
# child. Saves tetra probe, the unit's security score, noise before the
# attacks and an overhead measurement to tests/vm/.state/tetragon-*.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"

die() {
  printf 'tetragon.sh: %s\n' "$*" >&2
  exit 1
}

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}

export ANSIBLE_CONFIG="$repo/ansible.cfg"
export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
play=(uv run --project "$repo" ansible-playbook -i "$here/inventory.yml" -u "$user"
  --private-key "$state/id_ed25519" --become-password-file "$state/become-password"
  -e "@$here/vm-vars.yml" "$repo/omarchy-harden.yml" --tags tetragon)

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"
[[ $(vm_state) == running ]] || die "start with the VM running, after tests/vm/run.sh"

finding() { # id -> "STATUS detail"
  guest_root cat /var/lib/aegis/audit.jsonl | python3 -I -c 'import json,sys
for line in sys.stdin:
    f = json.loads(line)
    if f["id"] == sys.argv[1]:
        print(f["status"], f["detail"]); break
else:
    print("MISSING")' "$1"
}
expect() { # id status [substring...]
  local id=$1 want=$2 got
  shift 2
  got=$(finding "$id")
  [[ $got == "$want "* ]] || die "$id: want $want, got: $got"
  for s in "$@"; do [[ $got == *"$s"* ]] || die "$id: '$s' not in: $got"; done
  echo "PASS: $id $want"
}
refute() { # id substring: a benign look-alike must not be listed
  local got
  got=$(finding "$1")
  [[ $got != *"$2"* ]] || die "$1: benign '$2' was reported: $got"
  echo "PASS: $1 does not list $2"
}

echo "--- Tetragon is running with every policy loaded"
"${play[@]}" >"$state/tetragon-run1.log" 2>&1 || { tail -40 "$state/tetragon-run1.log"; die "playbook failed"; }
expect tetragon.service PASS
expect tetragon.policies PASS "6 policies"
guest_root /usr/local/bin/tetra probe >"$state/tetragon-probe.txt" 2>&1 || true
guest_root systemd-analyze security tetragon.service >"$state/tetragon-security.txt" 2>&1 || true
if guest_root ss -Htlnup | grep -q tetragon; then die "tetragon listens on a network socket"; fi
echo "PASS: no network listener"

echo "--- noise on a freshly booted desktop, before any attack"
for p in cred_access persistence kernel_modules bpf_load process_injection exec_writable; do
  printf '%s: %s\n' "$p" "$(finding "tetragon.$p")"
done | tee "$state/tetragon-noise.txt"

echo "--- benign look-alikes"
guest_ssh 'set -e; mkdir -p ~/.ssh; [ -e ~/.ssh/id_ecdsa ] || { ssh-keygen -q -t ecdsa -N "" -f ~/.ssh/id_ecdsa; touch ~/.ssh/.aegis-planted; }
  ssh-keygen -y -f ~/.ssh/id_ecdsa >/dev/null
  cat ~/.bashrc >/dev/null'
guest_root sudo -n true
guest_root modprobe dummy && guest_root modprobe -r dummy

echo "--- attacks"
# Credential access: python3 reads the planted key and /etc/shadow.
guest_ssh 'python3 -I -c "import os; open(os.path.expanduser(\"~/.ssh/id_ecdsa\")).read()"'
guest_root python3 -I -c 'open("/etc/shadow").read()'
# Persistence: append to ~/.bashrc and create a sudoers drop-in, then undo both.
guest_ssh 'cp ~/.bashrc ~/.bashrc.aegis-bak && echo "# aegis-test" >> ~/.bashrc && mv ~/.bashrc.aegis-bak ~/.bashrc'
guest_root sh -c 'echo "# aegis-test" > /etc/sudoers.d/zz-aegis-test && rm /etc/sudoers.d/zz-aegis-test'
# Run from /tmp and from memory.
guest_ssh 'cp /usr/bin/true /tmp/aegis-true && /tmp/aegis-true && rm /tmp/aegis-true'
guest_ssh 'python3 -I -c "
import os
fd = os.memfd_create(\"aegis\")
os.write(fd, open(\"/usr/bin/true\", \"rb\").read())
pid = os.fork()
if pid == 0:
    os.execve(fd, [\"aegis\"], {})
os.waitpid(pid, 0)
"'
# Out-of-tree module: an in-tree module, but loaded from /tmp.
# shellcheck disable=SC2016 # expanded by the guest's shell
guest_root sh -c 'zstd -qdf "/usr/lib/modules/$(uname -r)/kernel/drivers/net/dummy.ko.zst" -o /tmp/aegis-dummy.ko \
  && insmod /tmp/aegis-dummy.ko && rmmod dummy && rm /tmp/aegis-dummy.ko'
# BPF: a two-instruction socket filter (r0 = 0; exit) loaded with bpf(2).
guest_root python3 -I -c '
import ctypes, ctypes.util, platform
nr = {"x86_64": 321, "aarch64": 280}[platform.machine()]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
insns = (ctypes.c_uint64 * 2)(0x00000000000000b7, 0x0000000000000095)
lic = ctypes.create_string_buffer(b"GPL")
attr = (ctypes.c_uint8 * 128)()
ctypes.memmove(ctypes.addressof(attr), ctypes.byref(ctypes.c_uint32(1)), 4)    # SOCKET_FILTER
ctypes.memmove(ctypes.addressof(attr) + 4, ctypes.byref(ctypes.c_uint32(2)), 4)
ctypes.memmove(ctypes.addressof(attr) + 8, ctypes.byref(ctypes.c_uint64(ctypes.addressof(insns))), 8)
ctypes.memmove(ctypes.addressof(attr) + 16, ctypes.byref(ctypes.c_uint64(ctypes.addressof(lic))), 8)
fd = libc.syscall(nr, 5, ctypes.byref(attr), 128)                              # BPF_PROG_LOAD
assert fd >= 0, ctypes.get_errno()
'
# ptrace: root attaches to its own sleeping child.
guest_root python3 -I -c '
import ctypes, os, signal, time
pid = os.fork()
if pid == 0:
    time.sleep(5); os._exit(0)
libc = ctypes.CDLL(None)
libc.ptrace(16, pid, 0, 0)
time.sleep(0.2)
os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
'
guest_ssh '[ -e ~/.ssh/.aegis-planted ] && rm -f ~/.ssh/id_ecdsa ~/.ssh/id_ecdsa.pub ~/.ssh/.aegis-planted || true'
sleep 3

echo "--- the audit names each attack and none of the look-alikes"
"${play[@]}" >"$state/tetragon-run2.log" 2>&1 || { tail -40 "$state/tetragon-run2.log"; die "playbook failed"; }
expect tetragon.cred_access WARN "/usr/bin/python3" "/.ssh/id_ecdsa" "/etc/shadow"
refute tetragon.cred_access "/usr/bin/ssh-keygen"
refute tetragon.cred_access "/usr/bin/sudo"
expect tetragon.persistence WARN "/.bashrc" "/etc/sudoers.d/zz-aegis-test"
expect tetragon.exec_writable WARN "/tmp/aegis-true" "_sys_execveat("
expect tetragon.kernel_modules WARN "/tmp/aegis-dummy.ko"
refute tetragon.kernel_modules "dummy.ko.zst"
expect tetragon.bpf_load WARN "/usr/bin/python3"
expect tetragon.process_injection WARN "/usr/bin/python3"

echo "--- overhead: 20000 opens and 500 execs, with Tetragon running and stopped"
bench='python3 -I -c "
import os, subprocess, time
t = time.perf_counter()
for _ in range(20000):
    os.close(os.open(\"/etc/hostname\", os.O_RDONLY))
o = time.perf_counter() - t
t = time.perf_counter()
for _ in range(500):
    subprocess.run([\"/usr/bin/true\"])
print(\"open %.3fs exec %.3fs\" % (o, time.perf_counter() - t))
"'
{
  echo "running: $(guest_ssh "$bench") rss=$(guest_root systemctl show -P MemoryCurrent tetragon.service)"
  guest_root systemctl stop tetragon.service
  echo "stopped: $(guest_ssh "$bench")"
  guest_root systemctl start tetragon.service
} | tee "$state/tetragon-overhead.txt"
echo "tetragon.sh: all checks passed"

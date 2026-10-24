#!/usr/bin/env bash
# D-26 end to end: aegis-agent through the Smokescreen proxy, both modes.
#
# Usage: tests/vm/agent-egress.sh   (after tests/vm/run.sh, VM still running)
#
# report:  listed and unlisted hosts both reachable; direct traffic too.
# enforce: listed host reachable, unlisted host refused, no direct route.
# Then the audit must name the unlisted host and the refusal.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"

die() {
  printf 'agent-egress.sh: %s\n' "$*" >&2
  exit 1
}

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}
# curl 8.22.0, the curl project's own image, by index digest (2026-10-24).
readonly IMG=docker.io/curlimages/curl@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777

export ANSIBLE_CONFIG="$repo/ansible.cfg"
export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
play=(uv run --project "$repo" ansible-playbook -i "$here/inventory.yml" -u "$user"
  --private-key "$state/id_ed25519" --become-password-file "$state/become-password"
  -e "@$here/vm-vars.yml" "$repo/omarchy-harden.yml" --tags agents)

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
# "<CONNECT code> <curl exit>" for an HTTPS URL from inside an agent container.
agent_curl() { # mode url [extra curl args]
  local mode=$1 url=$2
  shift 2
  guest_ssh "mkdir -p ~/aegis-proj && cd ~/aegis-proj && aegis-agent --egress $mode --image $IMG -- \
    curl -s -o /dev/null -m 20 -w '%{http_connect} ' $* $url; echo \$?" 2>/dev/null | tail -1
}

echo "--- report: everything reachable, unlisted hosts logged"
got=$(agent_curl report https://github.com/)
[[ $got == "200 0" ]] || die "report, github.com: $got"
got=$(agent_curl report https://example.org/)
[[ $got == "200 0" ]] || die "report, example.org (unlisted) should pass: $got"
got=$(agent_curl report https://example.org/ --noproxy "'*'")
[[ ${got##* } == 0 ]] || die "report, direct to example.org should pass: $got"
echo "PASS: report mode lets listed, unlisted and direct traffic out"

echo "--- enforce: only the allowlist, no direct route"
got=$(agent_curl enforce https://github.com/)
[[ $got == "200 0" ]] || die "enforce, github.com: $got"
got=$(agent_curl enforce https://example.org/)
[[ $got != "200 0" && ${got%% *} != 000 ]] || die "enforce, example.org should be refused by the proxy: $got"
got=$(agent_curl enforce https://example.org/ --noproxy "'*'")
[[ ${got##* } != 0 ]] || die "enforce, direct to example.org should have no route: $got"
echo "PASS: enforce mode allows github.com, refuses example.org, and has no direct route"

echo "--- the proxy containers are hardened"
for mode in report enforce; do
  spec=$(guest_ssh "podman container inspect --format \
    '{{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' \
    aegis-agent-proxy-$mode")
  [[ $spec == "true 65534:65534 "*"no-new-privileges"* && $spec == *seccomp* ]] \
    || die "aegis-agent-proxy-$mode: $spec"
done
echo "PASS: both proxies run read-only, as 65534, with no-new-privileges and the seccomp profile"

echo "--- the audit names the unlisted host and the refusal"
"${play[@]}" >"$state/agent-egress-audit.log" 2>&1 || die "agents run failed, see $state/agent-egress-audit.log"
got=$(finding agent.egress)
[[ $got == "INFO "*"outside the allowlist: example.org"* ]] || die "agent.egress: $got"
[[ $got == *"refused in enforce mode: example.org"* ]] || die "agent.egress, refusal missing: $got"
echo "PASS: ${got:0:150}..."
echo "Done."

# eBPF, sandboxing and network-isolation proposals: evaluation

- **Date:** 2026-11-20
- **What was evaluated:** eight proposals from a generic "harden Arch/Omarchy
  with eBPF, sandboxing and network isolation" write-up that no earlier review
  or decision covered: Tetragon, custom BPF-LSM programs, bpftrace, development
  toolchains in rootless Podman, per-application network namespaces, an
  nftables ruleset in place of ufw, XDP, and systemd socket activation for
  local services. The write-up's other items were already implemented or
  decided: `linux-hardened` (D-02), AppArmor (D-05), Flatpak (D-06), agent
  containment (D-07, D-26), `pam_u2f` (D-04), Secure Boot/UKI (roadmap #21),
  auditd (#24).
- **Short version:** one proposal is worth a decision, and that is
  **Tetragon as an opt-in, detection-first role** (roadmap #27). Two cheap
  audit checks fall out of the review: `bpf` stays in the active LSM list
  (#28), and listening sockets are inventoried (#29). Development toolchains can
  already run in `aegis-agent`, so #30 only documents that. Do not adopt the
  rest: custom BPF-LSM code, a hand-written nftables ruleset, XDP, `ip netns`
  wrappers, and socket activation either duplicate what is already in force or
  defend against threats a laptop does not face. **Never install the AUR
  `tetragon-bin` package**: it is not Tetragon 1.8.0 (§1.4).
- **Compared against:** Omarchy `v4.5.0` (`ac2690c`, the newest release on
  2026-11-20), read from the release tarball (5218 files) and never executed.
  `linux-omarchy` 7.2.15-2 config from `omacom/omarchy-pkgs` at `0c38831`.
  Arch `linux` and `linux-hardened` 7.2.15 configs from
  `gitlab.archlinux.org/archlinux/packaging/packages/<pkg>/-/raw/main/config.x86_64`.
  Tetragon `v1.8.0` (`a5a6678`). systemd `v262.2` (also Arch's version).
  Nothing was run on the VM; every "works on this kernel" below is inferred
  from the kernel config and the source, and is marked as such.

## Kernel facts all eight depend on

Read from the three configs (2026-11-20):

| Option | `linux-omarchy` | Arch `linux` | `linux-hardened` |
|---|---|---|---|
| `CONFIG_BPF_LSM` | y | y | y |
| `CONFIG_LSM` | `landlock,lockdown,yama,integrity,bpf` | same | same |
| `CONFIG_DEBUG_INFO_BTF` | y | y | y |
| `CONFIG_BPF_UNPRIV_DEFAULT_OFF` | y | y | y |
| `CONFIG_FUNCTION_ERROR_INJECTION` | **not set** | y | y |
| `CONFIG_BPF_KPROBE_OVERRIDE` | absent (needs the above) | y | **not set** |
| `CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE` | y | y | y |

- The `apparmor` role's `lsm=` drop-in keeps `bpf`:
  `aegis_apparmor_lsm: landlock,lockdown,yama,integrity,apparmor,bpf`
  (`roles/apparmor/defaults/main.yml:9`). An `lsm=` that left it out would
  silently switch BPF LSM off, which is what #28 guards.
- The `sysctl` role sets `kernel.unprivileged_bpf_disabled=1` and
  `net.core.bpf_jit_harden=2` (`roles/sysctl/defaults/main.yml:26-27`). Both
  restrict unprivileged users only; Tetragon and bpftrace run as root.
- Kernel lockdown (`include/linux/security.h`, `enum lockdown_reason`, read at
  torvalds `v6.18`): `integrity` blocks `LOCKDOWN_BPF_WRITE_USER` and
  `LOCKDOWN_DEBUGFS`. `confidentiality` additionally blocks
  `LOCKDOWN_KPROBES`, `LOCKDOWN_BPF_READ_KERNEL`, `LOCKDOWN_PERF` and
  `LOCKDOWN_TRACEFS`, which **breaks Tetragon and bpftrace**. Roadmap #19
  already proposes `integrity`, not `confidentiality`; it should stay that way
  if #27 is adopted.

## 1. Tetragon (standalone, systemd): candidate, needs a decision (#27)

### 1.1 What it would give us

Process-exec events with binary, working directory and full argv, and
kprobe/LSM-hook policies on file access, for example: alert when anything
other than `ssh`, `ssh-agent` or `git` opens `~/.ssh/*`, or when an agent
started from `omarchy-agent` or `mise` executes a binary outside an allowlist.
That fills a real gap. Today the playbook can say which program connected
where (D-25) and what the agent proxy saw (D-26). Nothing records **what
ran or what read the keys** on the host. Upstream's quickstart policy
`examples/quickstart/file_monitoring.yaml` hooks `security_file_permission`
with `matchArgs` on a path prefix and the access mask; its enforcing variant
adds `matchActions: [{action: Sigkill}]`.

### 1.2 Enforcement on our kernels (inferred from source, not run)

From `pkg/sensors/tracing/generickprobe.go:335-358` (`validateOverride`) and
the kernel's fmod_ret allow-list (`kernel/bpf/verifier.c`):

| Action | `linux-omarchy` | `linux-hardened` | Mechanism |
|---|---|---|---|
| Sigkill / Signal | works | works | `bpf_send_signal` |
| Override on a `security_*` kprobe | works | works | fmod_ret |
| `lsmHooks` with Override | works while `bpf` is in `/sys/kernel/security/lsm` | same | BPF LSM |
| Override on a syscall kprobe | **fails to load** | **fails to load** | needs `CONFIG_BPF_KPROBE_OVERRIDE` |

Upstream's enforcement page warns that Sigkill does not guarantee a `write()`
is prevented and recommends pairing it with Override. Policies must therefore
use `security_*`/LSM hooks, not syscalls. `sudo tetra probe` reports the
features (`override_return`, `fmodret`, `lsm`, …) and would confirm this in
the VM. The daemon also logs `BPF detected features:` at start
(`cmd/tetragon/main.go:491`).

### 1.3 Costs and risks

- **Supply chain.** Not in the Arch repos. Upstream's release tarball comes
  with only a `.sha256sum` from the same release page: no signature, and no
  SLSA provenance step in its workflows. That is weaker than Smokescreen,
  whose provenance was checked with `gh attestation verify` (D-26). Upstream's
  **container images** are cosign-signed (keyless, GitHub Actions issuer;
  tetragon.io/docs/installation/verify/). A role could verify the image
  signature and extract the binaries from it, or pin the tarball's SHA-256
  and accept same-origin integrity only. That choice is part of the decision.
- **Install footprint.** Upstream's `install.sh` copies into `/usr/local`
  and installs a root unit (`User=root`, no sandboxing directives) and
  `/etc/tetragon/tetragon.tp.d/` for policies. Nothing under `/usr/local` is
  owned by a package, so `pacman_integrity` and the D-25 egress audit must be
  told about it.
- **Privacy.** Events carry full argv and file paths; argv routinely holds
  tokens (`curl -H "Authorization: …"`, `mysql -p…`). The default export is
  `/var/log/tetragon/tetragon.log`, mode 0600, rotated at 10 MB with 5
  backups (`pkg/option/flags.go:549-554`). A role would need
  `--redaction-filters` and an explicit retention. Environment capture is off
  by default and must stay off.
- **Overhead.** Upstream publishes no figures, only "low overhead"
  (tetragon.io/docs/troubleshooting/bpf-progs-stats/ shows how to measure).
  Measure it in the VM before calling it cheap.
- **Lockdown.** Incompatible with `lockdown=confidentiality` (see above).
- **Support window.** Minor releases roughly every six months; patch releases
  "on demand" for "maintained stable branches", with no published list of
  which ones (release-cadence page). Latest: v1.8.0, 2026-10-30. There is no
  EOL date to record; the drift check would have to watch the release page.

### 1.4 The AUR package is not Tetragon

`tetragon-bin` 1.8.0-1 (AUR, PKGBUILD read 2026-11-20 and re-fetched
identical): `pkgver=1.8.0`, but `source=` points at the fixed release tag
`tetragon-cli`, whose `tetragon-linux-amd64.tar.gz` was uploaded
**2022-07-21**. It contains an old event-observe client, not the daemon; there
are no BPF objects and no unit. Its `package()` **runs the downloaded binary**
to generate shell completions. Do not install it.

### 1.5 Recommendation (decided 2026-11-20 as D-37 (a); implemented, VM-tested 2026-11-21)

Open a decision (D-37) for an opt-in `tetragon` role with these properties:
detection only at first (no Sigkill/Override policies); a few policies (exec
of anything under the agent and mise paths, reads of `~/.ssh`, `~/.gnupg`,
`~/.config/sops`, and `/etc/shadow` by binaries outside an allowlist);
redaction on; events summarised into `aegis_findings` like D-25 and D-26;
supply-chain path chosen by the owner; VM-tested on both kernels. Enforcement
policies come later, one at a time, like AppArmor enforce (D-05).

## 2. Custom BPF-LSM programs: do not adopt

BPF LSM is already compiled in and active on all three kernels and kept
active by our `lsm=`. Writing and loading our own BPF C programs would mean
carrying kernel-version-coupled code, a loader daemon and a CO-RE build in an
Ansible repo, for a control nobody here can review the way a kernel or
Tetragon policy is reviewed. The capability is reachable without that:

- Tetragon `lsmHooks` policies (YAML, §1);
- systemd's `RestrictFileSystems=`, which is implemented with the BPF LSM
  hook (`man/systemd.exec.xml` at `v262.2`: "might not be supported … if the
  LSM eBPF hook is not enabled").

What is worth doing is cheap: **#28**, assert that `bpf` is in
`/sys/kernel/security/lsm` (the `apparmor` role already reads that file,
`roles/apparmor/tasks/main.yml:125`), so a future `lsm=` edit cannot silently
disable it.

## 3. bpftrace: no role

`extra/bpftrace` 0.27.1 (2026-11-09). It needs root (`unprivileged_bpf_disabled=1`
stays), so installing it changes nothing about what an unprivileged attacker
can do, and a root attacker can load BPF without it. It is a diagnostic, not
a control; installing it by default would just be another package to keep
patched. Mention it in operating notes as the tool for live debugging; it
stops working under `lockdown=confidentiality`.

## 4. Development toolchains in rootless Podman: document, do not force (#30)

Omarchy installs runtimes on the host through mise
(`bin/omarchy-install-dev-env`: node 21-30, go 54-56, python 75-77; `mise-bin`
is a base package), declares coding agents as lazy mise tools, and ships
Docker with only `docker.socket` enabled and the user outside the `docker`
group (`install/config/docker.sh`). Podman, distrobox and toolbox appear
nowhere in its code.

Moving every toolchain off the host would break `omarchy-install-dev-env`,
editor language servers and the agents Omarchy launches, which is the same
reason D-06 moved no apps. The mechanism already exists: `aegis-agent` runs
**any** command, not just an agent (`roles/agent_containment/templates/aegis-agent.sh.j2:11-12`,
`aegis-agent [--image …@sha256:…] [--egress report|enforce|off] [--network pasta|none] -- COMMAND`),
with only the project mounted, no capabilities, no new user namespaces, and
egress through the proxy. #30 is documentation: show `aegis-agent --egress
enforce -- npm ci` for an untrusted repository. Limit: it does not run on
`linux-hardened` (D-30).

The write-up also asks for working directories on an encrypted volume.
Omarchy's installer encrypts the disk with LUKS by default (see
operating-notes, VM row), and `pacman_integrity` already WARNs on autologin
without LUKS (#18n).

## 5. Per-application network namespaces (`ip netns`): do not adopt

- `ip netns exec` needs root, so every launch would be a sudo plus a
  privilege drop, which is a new root-reachable wrapper to get wrong.
- A network namespace alone does not isolate much on a desktop. systemd's own
  `PrivateNetwork=` page (`v262.2`): AF_UNIX sockets "located in the file
  system will continue to be accessible". On Omarchy that includes the session
  D-Bus, the Wayland socket, the gcr SSH agent socket when enabled
  (`bin/omarchy-setup-security-ssh-agent:9`), and `herdr`. A real boundary
  also needs a mount namespace, and that is what `aegis-agent` is: rootless
  Podman with a private netns (`--network none`, or the internal network in
  `enforce`), no `$HOME`, and Smokescreen refusing private and internal
  addresses (D-26). That is the "blind to the LAN" property the write-up
  wants.
- Routing one app through a dedicated WireGuard interface conflicts with the
  overlay decision (D-10, Tailscale) and needs per-app root plumbing.
- Caveat that stays open: in `report` mode, traffic that ignores the proxy
  still leaves through `aegis-agent-ext` (D-26), and that includes the LAN.
  Use `enforce` for untrusted code. This is already decided and documented.

## 6. nftables instead of ufw: do not adopt (already nftables)

- Arch's `core/iptables` 1.8.13 is "using nft interface" and provides
  `iptables-nft`; `iptables-legacy` is a separate package. ufw's rules are
  therefore already nftables rules.
- ufw's shipped defaults (`conf/ufw.defaults` at 0.36.2): input `DROP`,
  output `ACCEPT`, **forward `DROP`**. Omarchy's `install/config/firewall.sh`
  sets deny-incoming and installs `ufw-docker` after-rules; the `firewall`
  role keeps deny-incoming and removes LocalSend and opt-in SSH. Default-deny
  ingress and forward is in force. `ufw limit` provides rate limiting.
- A hand-written ruleset would fight `ufw-docker`, Docker's own chains,
  Omarchy's update scripts and our drift check, which reads ufw's files
  (D-11), with no gain in policy. Outbound control is OpenSnitch (D-09), not
  the packet filter.

## 7. XDP early drop: do not adopt

XDP addresses volumetric traffic against an exposed server. This machine has
no inbound service open after the `firewall` role (LocalSend and SSH rules
removed). A flood at a laptop on Wi-Fi saturates the link before the kernel
sees it, so dropping in XDP instead of netfilter gains nothing measurable.
That is reasoning, not a measurement. Many Wi-Fi drivers would also only
offer generic (skb) XDP, which runs after the skb is built; that is
UNVERIFIED per driver. It also adds a program to load, pin and drift-check on
every interface change.

## 8. Socket activation for local services: no role; add a listener audit (#29)

- What actually listens on a default Omarchy 4.5.0 install
  (`install/config/enable-services.sh:3-18` and the agent survey):
  - `cups` and `avahi-daemon` (enabled);
  - `docker.socket` (already socket-activated);
  - resolved on `172.17.0.1:53` for Docker DNS
    (`etc/systemd/resolved.conf.d/20-docker-dns.conf`);
  - LocalSend on demand (its rule is removed by the `firewall` role);
  - opt-in sshd;
  - the opt-in OpenClaw gateway on `127.0.0.1:18789`
    (`bin/omarchy-install-ai-openclaw:19`, user service via
    `openclaw onboard --install-daemon`, `bin/omarchy-openclaw-onboard:22`);
  - opt-in Ollama.
- Omarchy runs **no local LLM server by default**. The Ollama menu entry only
  installs the package. Arch's `ollama.service` runs as `User=ollama` with
  `PrivateTmp=yes`, `ProtectSystem=full`, `ProtectHome=yes`, and is not
  enabled by Omarchy (`bin/omarchy-remove-ai-ollama:9` only stops it).
  Whether `ollama serve` accepts a systemd-passed socket is UNVERIFIED; if it
  does not, activation needs a `systemd-socket-proxyd` shim.
- Socket activation does not shrink the reachable surface: systemd holds the
  same listening socket, and the first connection starts the service. It saves
  memory, not attack surface.
- The useful control is visibility. **#29** is an audit-only check, a
  listening-socket inventory (`ss -Htulpn`): WARN on any non-loopback
  listener not in an allowlist, INFO on loopback listeners (OpenClaw,
  Ollama). Like every audit check, it needs a planted-problem test.
- Unit sandboxing for the opt-in AI daemons (Ollama, OpenClaw's user
  service) belongs with roadmap's systemd-sandbox item, not here. Ollama's
  Arch unit already has a partial sandbox; OpenClaw's unit content was not
  read (UNVERIFIED).

## 9. Ready-made Tetragon rules: where they are, whether they are maintained, licences

Checked 2026-11-20 at `cilium/tetragon` v1.8.0 (`a5a6678`), for the D-37
requirement that monitor mode flag malicious behaviour from day one.

| Source | Licence | Last change to the policies | Tested upstream? | Usable on a desktop? |
|---|---|---|---|---|
| `examples/policylibrary/` (7 files: bpf, egress, library, modules, sshd, privileges ×2) | Apache-2.0 (root `LICENSE`; no per-file headers, no NOTICE) | 2026-04-29 (`46c51eb`) | No: no workflow or test loads them | Yes, all cluster-wide, no pod selectors; `egress.yaml` needs CIDRs filled in |
| `examples/tracingpolicy/` (77 files) | Apache-2.0 | 2026-10-27 (`ad973c1`) | Parsed by `TestExamplesSmoke` (`pkg/crdutils/crdutils_test.go:398`); only `bpf.yaml` and `tcp-connect.yaml` are loaded on a kernel (`tarball-tests.yaml`) | Mostly; two are Kubernetes-only. `examples/README.md`: "samples only… do not provide any security observability guarantees" |
| `examples/quickstart/` | Apache-2.0 | 2026-04-29 | No | `file_monitoring.yaml` yes; the `_enforce` variants are namespaced (Kubernetes) |
| Docs "Policy Library" (14 use cases) | Apache-2.0 (no separate docs licence) | 2026-04-02 | n/a | Half need no policy (default exec events plus `jq`) |
| v1.8.0 release tarball | — | — | — | Ships **no** policies (`install.sh` creates an empty `tetragon.tp.d`) |
| gccloudone-aurora/tetragon-policies | MIT (Crown copyright, Statistics Canada) | 2026-09-10 | Schema check only | 7 of 10 are copies of upstream examples; its own 3 are container-scoped with Debian paths |
| Other GitHub repositories | mostly none | — | — | Demos and generators, ≤10 stars |
| Isovalent Enterprise policy library | proprietary | — | — | Not usable; its existence and content were not verified |
| falcosecurity/rules | Apache-2.0 | 2026-11-09 | — | Cannot be translated mechanically: Falco conditions are boolean expressions over userspace event fields, while Tetragon needs a kernel hook and bounded in-kernel selectors. Used as a checklist only |

**Conclusion.** Nobody ships "reliable" Tetragon rules for a host; the
examples are building blocks. D-37 therefore adapts six of them
(`roles/tetragon/templates/policies/README.md`):

- **Licence.** Apache-2.0 allows the copy. §4 asks for the licence text (the
  repository's own `LICENSE`), a notice in every modified file (each policy
  has one), and kept attributions (upstream's files carry none to keep).
- **Testing.** Each policy is tested in the VM against its technique and a
  benign look-alike (`tests/vm/tetragon.sh`), since upstream's CI does not
  load them.
- **Not used:** every example with Sigkill or Override; `privileges-raise`
  (setuid to root fires for sudo, polkit and systemd on every login);
  `tcp-connect` (every connection; OpenSnitch covers egress); the
  CVE-2024-3094 xz check (targets `/usr/sbin/sshd`; Arch's is
  `/usr/bin/sshd`, and the affected versions are long gone).

## Not verified in this review

- No VM run: kernel feature support (`tetra probe`), Tetragon overhead and
  AppArmor coexistence are inferred, not measured.
- The 7.2.15 stable trees were not diffed against mainline v7.2 for the
  fmod_ret allow-list.
- `herdr server`'s transport, the OpenClaw unit, and whether Omarchy's shell
  agents panel makes network calls.

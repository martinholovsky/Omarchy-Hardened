# Threat model: what the hardening protects against

What each implemented control defends, against whom, how we know it works,
and what it does **not** stop. Written for release 0.1.0 (2026-10-26) from
the code at that commit; every "Evidence" entry names a check that exists in
`tests/container/inside.sh` (container, CI) or `tests/vm/*.sh` (VirtualBox VM,
Omarchy 4.0.6). Nothing here has run on real hardware yet
([open-items.md](open-items.md) §1).

Decisions are in [open-decisions.md](open-decisions.md) (D-NN), what a run
changes for the user in [operating-notes.md](operating-notes.md), Omarchy's own
behaviour in [upstream-baseline.md](upstream-baseline.md).

Status words used below:

- **enforces**: the setting is in force after a run, and a test shows it
  blocking or limiting something.
- **reports**: the audit (`/var/lib/aegis/audit.jsonl`) names the problem;
  FAIL stops the run, WARN and INFO do not. Nothing is changed.
- **opt-in**: off until the user asks for it.

ATT&CK technique IDs and CWE numbers are given where one clearly fits; a
missing ID means none fits well, not that none was looked for.

## 1. What we are protecting, and from whom

Assets:

- **Root on the workstation**, and through it everything else below.
- **The user's session and data**: `$HOME`, SSH and signing keys, browser
  profiles, tokens in config files.
- **The integrity of installed software**: packages, PAM, sudoers, the
  hardening itself.
- **Code the user publishes**: commits and tags pushed under their name.

Attackers this release is meant to slow down or expose:

| ID | Attacker | Starting point |
|---|---|---|
| A1 | Someone on the same network (café, office LAN, a compromised IoT device) | Can reach the machine's open ports |
| A2 | Malicious or compromised code running **as the user**: a browser or Electron exploit, a bad editor plugin, an npm/pip post-install script, a prompt-injected AI agent | User privileges, no root |
| A3 | Someone who learns the user's password (shoulder surfing, phishing, reuse) | Password, maybe a local session |
| A4 | A malicious or tampered package source: mirror, repository, MitM on the download | Controls bytes pacman or Flatpak installs |
| A5 | A tailnet peer (D-10, D-24) | Reaches the machine over `tailscale0` |
| A6 | Someone with the powered-off laptop | Physical access, no password |

Out of scope: an attacker who already has root, firmware/hardware implants,
and A6 against a running, unlocked session.

## 2. Where the boundaries are

```mermaid
flowchart LR
  subgraph NET["Network (A1, A5)"]
    LAN[LAN / Internet peers]
    TS[Tailnet peers]
  end
  subgraph SRC["Package sources (A4)"]
    MIR[Arch mirrors / repos]
    FH[Flathub]
  end
  subgraph HOST["Workstation"]
    FW{{ufw: inbound}}
    OS{{OpenSnitch: outbound}}
    subgraph USER["User session (A2, A3)"]
      APPS[Browser, editors, plugins]
      AG[aegis-agent container]
    end
    PX[Smokescreen proxy]
    AUTH{{PAM: sudo, su, lock screen}}
    KERN[(Kernel: sysctl, LSM)]
    PKG[pacman + D-11 drift check]
    ROOT[(root-owned state: /etc, packages)]
  end
  DISK[(LUKS disk, A6)]

  LAN -->|inbound| FW --> HOST
  TS -->|tailscale0, bypasses ufw| HOST
  APPS -->|outbound| OS --> LAN
  AG -->|HTTP(S) only| PX --> LAN
  APPS -->|privilege request| AUTH --> ROOT
  APPS -->|syscalls| KERN
  MIR -->|signed packages| PKG --> ROOT
  FH -->|verified apps| APPS
  ROOT --- DISK
```

The boundaries the controls sit on: **network → host** (ufw, Tailscale),
**user → root** (PAM, sudoers, polkit, groups), **user code → kernel**
(sysctl, user namespaces, LSM), **package source → system** (pacman trust,
drift), **agent container → host and network** (Podman, proxy), and
**host → internet** (OpenSnitch, egress report).

## 3. Controls, threats and evidence

### 3.1 Network → host (A1, A5)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `firewall`: ufw default-deny inbound; removes LocalSend 53317/tcp+udp and the opt-in SSH rule; keeps Docker DNS | A1 reaches a listening service the user never meant to expose (LocalSend file transfer, sshd) and exploits it or guesses its password. T1021.004 (SSH) | enforces | Services Omarchy or the user re-allow later; traffic over `tailscale0` (row below); 53317/udp is not tested from outside | VM, from another machine: SSH 22 open → timeout, LocalSend 53317/tcp refused → timeout, Docker DNS still answers and fails without its rule (`firewall-hostonly.sh`). Container: "LocalSend and SSH rules removed, Docker DNS kept" |
| `overlay_network` (D-10, D-24): reports Tailscale; opt-in SSH on `tailscale0` only | A5 reaches every listening port, because Tailscale's default netfilter mode accepts `tailscale0` before ufw | reports (WARN `network.overlay`) | The bypass itself: the role reports it, it does not switch Tailscale to `nodivert` (D-24 a′) | VM with Headscale: a tailnet peer reaches a port ufw denies and the audit WARNs; in `nodivert` the port is closed and the finding passes (`tailscale.sh`) |
| `overlay_network`: sshd audit | A1/A5 brute-forces sshd password logins, or uses a stolen software key file. T1110.001, T1021.004 | reports (`ssh.password_auth`, `ssh.authorized_keys`) | A key the attacker already holds; sshd on a non-default config path | Container: Arch's stock sshd_config warns, Omarchy's key-only drop-in passes, an `ssh-ed25519` key is reported as not hardware-backed, an `sk-` key passes |
| `sysctl` network keys: redirects and source routing off (IPv4/IPv6), loose `rp_filter`, `tcp_syncookies`, `tcp_rfc1337`, IPv6 temporary addresses | A1 on the same segment redirects traffic through itself with ICMP redirects or source-routed packets (T1557); SYN floods; tracking the machine by a stable IPv6 address | enforces (values read back after apply) | ARP/DHCP spoofing, rogue Wi-Fi, anything at layer 2 | Container: all values written and read back; VM: live values after reboot. The effect of each key is the kernel's documented behaviour, not measured here |

### 3.2 User → root (A2, A3)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `pam_faillock` (D-13, D-14, D-19): `deny=10`, `unlock_time=900` (Omarchy: 120), persistent tally, in `faillock.conf` and the inline arguments of `system-auth` and the lock-screen stack; `su` through `system-auth`, wheel-only; root locks too | A2/A3 guesses the password at sudo, su or the lock screen. T1110.001, CWE-307 | enforces | Offline guessing of a stolen hash (see `accounts.password_hash`); a reboot clears the tally while autologin is on (D-23, accepted); polkit prompts bypass it after Omarchy's FIDO2 setup (measured; the audit WARNs, `auth.polkit_faillock`, D-28, and does not repair it) | VM: lock screen locks out after 10 failures, sudo and su fill one tally and refuse the right password at 10, su refuses a non-wheel user with root's password (`run.sh`); 10 wrong `pkexec` passwords fill the tally and lock the user, through polkit's sandboxed helper with the D-27 drop-in (VM over SSH, 2026-10-27); in a desktop terminal `pkexec` runs with the drop-in and refuses the right password without it (VM, 2026-10-27). Container: real `su` logins, tally persistence, `even_deny_root` |
| `fido2` (D-04): with ≥2 keys per wheel user, sudo needs key **and** password (`pam_u2f required`) | A2/A3 who has the password escalates with sudo. T1548.003 | enforces with ≥2 keys; with 1 key Omarchy's `sufficient` stays and the audit WARNs | With one key: the password alone still works. Login, polkit and LUKS are not changed | VM with a YubiKey: one key stays `sufficient`, WARN (2026-10-26). Container: 0, 1 and 2 keys; 2 keys make sudo key AND password. Two keys on real hardware: untested |
| `pacman_integrity`: NOPASSWD sudoers rules, docker/libvirt/disk (FAIL) and input (WARN) membership, polkit rules that grant everything | A2 becomes root without any password through a NOPASSWD rule, the docker socket or a blanket polkit rule. T1548.003, T1611 | reports; group membership FAILs (D-20) | Grants it does not know about (other setuid helpers, D-Bus services) | Container: unknown NOPASSWD rule warns, Omarchy's asdcontrol drop-in is known; docker membership fails and `aegis_audit_skip` accepts it; unconditional polkit YES warns |
| `pacman_integrity`: setuid files no package owns, world-writable and unowned files | A2 left a setuid binary or a writable file root later runs. T1548.001 | reports (unowned setuid FAILs) | setuid files a package does own | Container: an unowned setuid binary fails the audit |
| `pacman_integrity`: password hash algorithm | A3 who obtains `/etc/shadow` cracks SHA-512 hashes faster than yescrypt. T1110.002 | reports (`accounts.password_hash` WARN, without printing the hash) | Weak passwords | Container: SHA-512 warns without leaking it, yescrypt passes |

### 3.3 User code → kernel (A2)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `sysctl`: `dmesg_restrict=1`, `kptr_restrict=2` | A2 reads kernel addresses and logs to defeat KASLR before a kernel exploit. CWE-200 | enforces | Address leaks through other channels (side channels, `/proc` bugs) | Container and VM: values read back. Effect per kernel documentation |
| `sysctl`: `yama.ptrace_scope=1`, `suid_dumpable=0` | A2 attaches to another of the user's processes (a browser, an ssh-agent) and reads its memory or injects code. T1055.008, T1003.007 | enforces | Code injection through other means (`LD_PRELOAD` in the user's own shell config, editor plugins) | Values read back; effect per kernel documentation |
| `sysctl`: unprivileged BPF off, BPF JIT hardening, `perf_event_paranoid=3`, `unprivileged_userfaultfd=0`, `ldisc_autoload=0` | A2 uses kernel interfaces that are common local privilege-escalation surfaces. T1068 | enforces | Bugs in interfaces that stay open, including unprivileged user namespaces (kept on for browsers and Flatpak, D-01) | Values read back; effect per kernel documentation. On `linux-hardened`, `unprivileged_userfaultfd` does not exist (userfaultfd is compiled out) and is reported, not read (D-29) |
| `sysctl`: `kexec_load_disabled=1`, `sysrq=16` (D-15), `protected_fifos/regular=2` | Root-level persistence by booting a new kernel without a reboot; a local user using SysRq beyond sync; spoofed files in sticky world-writable directories such as `/tmp` (CWE-377) | enforces | Anything an attacker does after gaining root | Values read back. On `linux-hardened`, kexec is compiled out and the key is reported, not read (D-29) |
| `sysctl`: ASLR `mmap_rnd_bits=32`, `compat=16` (D-16); `oops_limit=100` (D-17) | Exploits that brute-force address layout; exploits that retry after a kernel oops | enforces | A single-shot exploit with an information leak | Values read back; VM live values after reboot |
| `kernel` (D-02): `linux-hardened` installed **alongside** `linux-omarchy` with its own boot entry | A2 exploits a kernel bug that the hardened patch set would have made harder. T1068 | opt-in: protects only after the user makes it the default (`linux-omarchy` stays the default) | Everything, until it is the default; it is not tested booted | VM: Limine lists `linux-omarchy` first, then `linux-hardened`. Container: a menu without the hardened entry fails the run |
| `apparmor` (D-05): installed, in `lsm=`, every profile in complain mode | Confining applications so a compromised one cannot read the rest of `$HOME` | reports only: complain mode **logs and does not block** | Any access, in this release | VM: AppArmor active, 83 profiles, all in complain mode |

### 3.4 Package source → system (A4)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `pacman_integrity`: `SigLevel` (including `Include=` files), mirror transport | A4 serves an unsigned or altered package, or tampers with plain-HTTP traffic. T1195.002, CWE-494, CWE-319 | reports (weak SigLevel and HTTP mirrors FAIL) | A malicious package correctly signed by an Arch packager; the AUR (not managed) | Container: `SigLevel = Never` fails, the exception list lets a named repo through, an `Include=` file is audited, a plain-HTTP mirror fails |
| `pacman_integrity`: last full upgrade age | Running known-vulnerable packages because updates stopped | reports (WARN after 7 days) | Zero-days | Container: a 2-day-old install passes, a 30-day-old never-upgraded one warns |
| `pacman_integrity` (D-21, D-22): `pacman -Qkk` drift | Someone (A2 after escalation, or a bad update) modifies a packaged binary or config. T1554 | reports (content drift FAILs; known-benign and tightened permissions are INFO) | Files no package owns; changes made and reverted between runs | Container: a modified binary is reported, a file with several reasons is listed once, tightened permissions accepted, loosened ones are drift |
| `drift_check` (D-11): after every pacman transaction, a root-owned copy of the playbook runs in check mode | An update (`omarchy-update`, a package) silently reverts the hardening (PAM, sysctl, ufw) | reports (journal and desktop notice); never re-applies | Changes made outside pacman transactions until the next manual run; commit signing and agent egress, which need the desktop user (INFO, D-33); ufw is checked from its files, not the live netfilter rules (D-33) | VM: a real `pacman -S` triggered the check, which reported a reverted PAM file without repairing it. Container: clean after apply, warns after a revert, clean in a service's environment; a check that breaks part-way exits 2 "broken", not drift; with ufw unable to run, each planted ufw revert is named (D-33). VM (2026-10-30): the check after a real `pacman -S` ran every role to the end (`failed=0`). Live sysctl values: reported since D-32 (VM, 2026-10-28) |
| `flatpak` (D-06): Flathub limited to verified apps; apps with host, home, device or bus access reported | A4 publishes a look-alike unverified app; an app with broad permissions escapes Flatpak's sandbox in practice | enforces (remote filter) and reports | Verified apps that are malicious; apps not installed through Flatpak | Container: without Flatpak the role only reports. Flatpak installed: not tested yet |

### 3.5 Agent container → host and network (A2: a prompt-injected or malicious AI agent)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `agent_containment` (D-07, D-01): `aegis-agent` runs the agent in rootless Podman with only the project directory mounted, no `$HOME`, all capabilities dropped, no new privileges, a seccomp profile that refuses user namespaces | An agent reads SSH keys, tokens or other projects, or escalates through the kernel from inside the container. T1611, T1552.001 | opt-in, per invocation; enforces when used | Damage inside the project directory it was given; agents started without the wrapper; a container escape through a kernel bug. It does not run on `linux-hardened` (no unprivileged overlayfs); the audit WARNs (D-30) | VM: no capabilities, no user namespaces, project directory writable (`run.sh`) |
| `agent_containment` (D-26): the agent's HTTP(S) goes through Smokescreen; `report` (default) logs hosts outside the allowlist, `enforce` allows only the allowlist with no direct route; LAN and cloud metadata addresses refused | An agent exfiltrates code or secrets, or reaches internal services and metadata endpoints. T1041, T1552.005 | reports by default; enforces in `enforce` mode | Exfiltration to an allowlisted host; in `report` mode, any host (it is logged, not blocked); non-HTTP traffic in `report` mode | VM: report lets listed, unlisted and direct traffic out; enforce allows github.com, refuses example.org, has no direct route; proxies run read-only as 65534 with the seccomp profile (`agent-egress.sh`). Container: checksum-pinned install, a wrong checksum stops it; `169.254.169.254` refused (407) in enforce, and `169.254.169.254` and `10.0.0.1` refused (407) in report mode, where only the address rules can refuse (a config that allows those ranges gets 502 instead, checked 2026-10-26) |

### 3.6 Host → internet (A2)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `opensnitch` (D-09): OpenSnitch with default action `allow`, seeded rules, prompt UI; an unanswered prompt allows | A2 calls home or exfiltrates over the network (T1071.001, T1041); the user sees and can deny new programs | reports (prompts); allows by default | Anything the user allows, or that reaches the network while the prompt times out; programs that reuse an allowed one (curl, the browser) | VM: opensnitchd active; with the UI running, an unanswered prompt lets a new program out; the UI's own deny default was found cutting egress and fixed |
| `opensnitch` (D-25): `aegis-egress-collector` records which program connected where (never command lines); audit WARNs on programs no package owns | A2 drops its own binary in `~/.local/bin` or similar and connects out | reports (`egress.unknown_programs`); best effort (UDP, events can be lost) | Malware inside a packaged program or an interpreter (python, node); events lost while the collector restarts | VM: the probe was recorded, the marker on its command line is in neither the state file nor the journal, the audit names only the unowned program (`egress.sh`). Container: a non-root sender is rejected |

### 3.7 Code the user publishes

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `commit_signing` (D-08): SSH signing of commits and tags with a hardware `sk-` key you name | A2 or anyone with the user's repository credentials pushes commits that look like the user's | opt-in (reports until a key is set); refuses software keys by default | Hosts that do not require verified signatures; a malicious commit the user signs themselves | Container: an `sk-` key configures signing idempotently, `ssh-ed25519` is refused. Real key: untested |

### 3.8 Physical access (A6)

| Control | Threat it addresses | Status | Does not stop | Evidence |
|---|---|---|---|---|
| `pacman_integrity`: autologin on an unencrypted root, `/tmp` mount options, fwupd | A6 boots the stolen laptop straight into the session; firmware left unpatched | reports | Everything else about physical access: LUKS is Omarchy's, unchanged; no Secure Boot or TPM work in this release | Container: autologin without disk encryption warns; tmpfs with nosuid,nodev passes, a disk directory warns |

## 4. What this release does not protect against

Stated plainly, so nobody reads more into the green audit than is there:

- **Malware running as the user can read the user's files.** Nothing
  confines ordinary applications: AppArmor is in complain mode (D-05), and
  only agents started through `aegis-agent` are contained.
- **Outbound traffic is allowed by default** (D-09, D-26 `report`).
  OpenSnitch and the proxy make it visible, not blocked.
- **The hardened kernel is not the default** (D-02); its protection starts
  when the user switches.
- **Unprivileged user namespaces stay on** (D-01), a frequent part of local
  kernel exploits, because browsers and Flatpak need them.
- **Tailscale traffic bypasses ufw** in Tailscale's default mode (D-24); the
  audit says so.
- **hardened_malloc is not used** (D-03, deferred).
- **Root is the end of the line.** Every control above assumes the attacker
  is not root yet; the audit and drift checks run as root and can be lied to
  by root.
- **Real hardware is untested.** VM and container results do not cover
  firmware, Secure Boot, suspend, real Wi-Fi or GPU drivers.

## 5. Risks accepted, and by whom

| Risk | Decision | Accepted |
|---|---|---|
| User namespaces stay enabled | D-01 (a) | owner, 2026-10-21 |
| `linux-omarchy` stays the default kernel | D-02 | owner, 2026-10-21 |
| AppArmor complain mode only | D-05 | owner, 2026-10-21 |
| Outbound allowed by default | D-09, D-26 | owner, 2026-10-21 and 2026-10-24 |
| A reboot clears the faillock tally while autologin is on | D-23 (a) | owner, 2026-10-22 |
| Tailscale bypasses ufw; reported, not changed | D-24 (a′) | owner, 2026-10-24 |
| Egress report is best effort | D-25 | owner, 2026-10-24 |

Open, not yet decided or tested: after Omarchy's FIDO2 setup, polkit password
guesses bypass faillock (measured; reported by D-28, not repaired);
FIDO2 with two keys on hardware; a full run on hardware
([open-items.md](open-items.md)).

## 6. When to revisit this document

Update it in the same change as any of these:

- a role is added, removed, or changes what it enforces or reports;
- a decision in `open-decisions.md` is made or reversed;
- a new trust boundary or entry point: a new listening service, a new
  package source, a new way to gain root, a new container or agent path;
- Omarchy changes something a control depends on (see
  `upstream-baseline.md`);
- the first run on real hardware, or a control moves from report to enforce
  (AppArmor enforce, `enforce` egress, `linux-hardened` as default).

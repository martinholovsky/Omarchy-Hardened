# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning:
SemVer once 1.0 ships.

## [Unreleased]

### Added

- `agent_containment` (D-26): `aegis-agent --egress report|enforce|off`.
  Agents' HTTP(S) goes through Smokescreen v0.1.0 (checksum-pinned release
  binary, provenance verified), built into a `FROM scratch` image and run
  read-only as UID 65534 with no capabilities. `report` (default) allows
  everything and logs hosts outside `aegis_agent_egress_allowlist`; `enforce`
  puts the agent on an internal network whose only way out is the proxy. The
  audit lists agent destinations (`agent.egress`). Four container checks (60
  in all) run the real binary against both allowlists; `tests/vm/agent-egress.sh`
  covers the wrapper and networks.

- `opensnitch` (D-25): `aegis-egress-collector`, a sandboxed local service
  that receives opensnitchd's connection log over UDP on 127.0.0.1, accepts
  it only from root's socket, and keeps program path and destination for 30
  days; command lines are never read. The audit WARNs on programs that
  connected out and belong to no package (`egress.unknown_programs`) and on
  datagrams from any other sender (`egress.collector_sender`). The collector
  is checked by every ruff rule, strict mypy and 27 unit tests (fuzzing and
  four mutants killed) in pre-commit; four container checks (56 in all) and
  `tests/vm/egress.sh` test it end to end.

- Project scaffold: `omarchy-harden.yml`, one role per PRD item, pinned
  collections (`ansible.posix` 2.2.2, `community.general` 13.5.0) and locked
  dev tooling (ansible-core 2.21.5, ansible-lint 26.10.1, yamllint 1.38.0).
- `preflight`: refuses non-Arch hosts, locates Omarchy, prints the baseline.
- `sysctl`: `dmesg_restrict`, `kptr_restrict`, `kexec_load_disabled`,
  `yama.ptrace_scope`, verified against the live kernel. The unprivileged-userns
  switch is refused until D-01 is decided.
- `pam_faillock`: `deny=10 unlock_time=900` in `faillock.conf` and in Omarchy's
  inline PAM arguments (`system-auth`, `omarchy-lock-password`), with read-back
  verification.
- `firewall`: removes the LocalSend and opt-in SSH ufw rules, keeps
  default-deny incoming, verifies with `ufw status`.
- `pacman_integrity`: audit-only check that no repository accepts unsigned
  packages, with an explicit exception list.
- Stub roles for kernel, hardened_malloc, fido2, apparmor, flatpak,
  agent_containment, commit_signing, opensnitch, overlay_network.
- Container test (15 checks) against Omarchy's PAM and ufw baseline in a
  digest-pinned Arch image. It also checks idempotence and a negative case.
- CI: pre-commit (shellcheck, yamllint, ansible-lint), full-history gitleaks
  with a checksum-verified binary, the container test. Dependabot for Actions
  and uv.
- Docs: verified upstream baseline, open security decisions D-01 to D-12,
  ADR 0001.
- Research: a review of Securix-Linux re-checked against 2026 kernels (192
  settings classified) and a review of secureblue at `5be4f13`, merged into
  `docs/roadmap.md`. D-01 now records the verified facts: no
  `bubblewrap-suid` on Arch, and no mainline AppArmor userns-restrict sysctl.

- Research: a Kicksecure security-misc review at `9535bf8`, merged into the
  roadmap. It found two gaps in `pam_faillock` (roadmap G1/G2), both now fixed:
  - **G1:** the tally moves from tmpfs `/var/run/faillock` to `/var/lib/faillock`
    (with a `tmpfiles.d` entry), so a reboot no longer resets the counter.
  - **G2:** `su`/`su-l` now `include system-auth`, so faillock covers them, and
    `pam_wheel use_uid` limits `su` to wheel.
  The container test drives real `su` logins with `expect`. Mutation runs
  (su coverage off, wheel restriction off) each fail the suite.

- Roadmap Tier 1:
  - `sysctl` renders its drop-in from one variable, now about 30 keys: BPF, perf, userfaultfd, ldisc, fs protections, `suid_dumpable`, IPv4/IPv6 redirects and source routing, loose `rp_filter`, syncookies, rfc1337, IPv6 privacy addresses.
  - `sysctl` re-applies on runtime drift and asserts `mmap_min_addr >= 65536`.
  - `pam_faillock` gains `audit`, `even_deny_root` and `root_unlock_time`.
  - `pacman_integrity` becomes a findings-based audit:
    - SigLevel, now following `Include=`
    - HTTPS mirrors and upgrade age
    - unowned setuid, world-writable and unowned files
    - `pacman -Qkk` drift
    - NOPASSWD sudoers rules
    - dangerous groups
  - New `audit_report` role: summary, `/var/lib/aegis/audit.jsonl`, `aegis_audit_skip`.
  - Settings with a trade-off (D-15 to D-19) default to Omarchy's behaviour; D-20 and D-21 are audit-only.
- Tests:
  - The container suite grows to 25 checks, including planted-problem negatives for every audit and a `--check --diff` run.
  - New CI job `sysctl-apply` applies the role to a live kernel and checks idempotence and drift repair. Locally it refuses unless `AEGIS_ALLOW_HOST_SYSCTL=1`.

- Owner decisions D-15 to D-21 applied with the recommended options:
  - `kernel.sysrq=16` pinned
  - `vm.mmap_rnd_bits=32` / `mmap_rnd_compat_bits=16` on x86_64
  - `kernel.oops_limit=100`, `warn_limit` unset
  - faillock `audit` off
  - `even_deny_root` on, with `root_unlock_time=900`
  - docker/libvirt/disk membership is a FAIL, input a WARN
  - package drift is a WARN

  The container test checks that root locks after 10 `su` failures and unlocks with `faillock --reset` (26 checks).

- `docs/operating-notes.md`: what a run changes for the user, one-way
  settings and rollback, being locked out, verified vs untested areas, and a
  VirtualBox VM test plan.

- Research: a SnowflakeOS review (`docs/research/snowflakeos-review.md`,
  `snowflakeos-modules@0a5e0a3`). It has almost no hardening of its own. Five
  audit-only checks go into the roadmap as 18k–18o: fwupd, tmpfs `/tmp`,
  blanket polkit grants, autologin without encryption, and weak password
  hashes. On a live Omarchy 4.0.6 install, `login.defs` says YESCRYPT but the
  installer left `$6$` (SHA-512) hashes for root and the user, so 18o would
  fire on a default install.

- VM test (`tests/vm/`): creates a VirtualBox VM from the signed Omarchy ISO,
  pinned in `iso.lock` with its SHA-256 and signer. The test installs it,
  applies the playbook over SSH (127.0.0.1 only), checks idempotence, reboots
  through the LUKS prompt, and checks that nothing reverted. First run on
  Omarchy 4.0.6 / `linux-omarchy 7.2.8-9` passed.

- `pacman_integrity` (D-22, owner's choice (b)): known-benign package drift and
  permission changes that only tighten (checked against the package `mtree`)
  are reported as INFO in `integrity.package_drift_accepted`, not as drift.
  Default entries: utempter, `/var/log/journal`, `powerprofilesctl`. All were
  verified on an Omarchy 4.0.6 install.
- D-21: package drift now **fails** the run by default, because a default
  Omarchy 4.0.6 VM install produces none that D-22 does not accept.
- Container test: 32 checks. New ones cover drift reported once per file,
  tightened versus loosened permissions, exact matching of expected entries,
  the upgrade-age install fallback, and the sudoers NOPASSWD check.

- Owner decisions D-01 to D-11 (2026-10-21): all recommended options; D-03
  (hardened_malloc) deferred. Every remaining stub role is now implemented:
  - `drift_check` (D-11): a pacman hook runs a root-owned copy of the
    playbook in `--check` mode after each transaction. It uses the settings
    of the last apply, warns through the journal and the desktop, and never
    re-applies.
  - `kernel` (D-02): `linux-hardened` installed alongside `linux-omarchy`;
    the default entry is unchanged.
  - `fido2` (D-04): sudo becomes key **and** password once every wheel user
    has 2 or more keys.
  - `apparmor` (D-05): `lsm=` drop-in, every profile in complain mode.
  - `flatpak` (D-06): Flathub limited to verified apps; apps with broad
    permissions reported.
  - `agent_containment` (D-07, D-01): rootless Podman and `aegis-agent`.
  - `commit_signing` (D-08): SSH signing for a named `sk-` key.
  - `opensnitch` (D-09): installed, allow by default, seeded rules, UI
    autostart.
  - `overlay_network` (D-10): Tailscale status; opt-in SSH on `tailscale0`
    only.
- `pacman_integrity`: five read-only checks from the SnowflakeOS review
  (roadmap 18k–18o): fwupd, tmpfs `/tmp`, blanket polkit grants, autologin
  without encryption, weak password hashes.
- `tests/vm/update-snapshot.sh` and `tests/vm/lib.sh`: an updated snapshot
  for roles that install packages, and shared boot/unlock helpers. `run.sh`
  now also checks AppArmor after a reboot, the Limine entries, OpenSnitch,
  `aegis-agent`, and that the D-11 hook fires on a real pacman transaction.

### Changed

- `tests/container/inside.sh` prints the seconds since the start on every
  `---` section line and the total at exit, to find where the container
  test's time goes before caching anything.
- `tests/vm/run.sh` enables `ansible.posix.profile_tasks`: every playbook
  log in `tests/vm/.state/` ends with the 30 slowest tasks.
- `kernel.perf_event_paranoid` is now 3. That is the same as 2 on mainline
  (verified on linux-omarchy 7.2.8) and no longer lowers linux-hardened's
  default.
- The firewall check allows the D-10 `22/tcp on tailscale0` rule while still
  rejecting a global SSH rule, IPv4 or IPv6 (`22/tcp (v6)`).
- `groups.empower` joins the D-20 root-equivalent groups (FAIL), and systemd's
  `empower.rules` is listed as a known polkit grant.
- `docs/open-items.md`: one list of what is still open for implemented work
  (untested paths, owner decisions, user steps, harness issues). Corrected
  stale statements: the default-install WARN count is 2, not 0; the D-05
  AppArmor count is 83 complain-mode profiles, not 161; the drift after
  `omarchy-update` is now reported by D-11; roadmap #12 and #18 are
  implemented.
- `docs/open-items.md`: FIDO2 enrolment corrected. `omarchy-setup-security-fido2`
  registers one key, and the second goes in with `pamu2fcfg -n`. The VM's lack of
  FIDO2 passthrough is stated as untried, not as needing the Extension Pack.
- Decisions: D-23 accepts that autologin clears the faillock tally at boot
  (the disk password is the same password); D-20's `empower` FAIL is
  confirmed. Stale statements corrected: the README intro (AppArmor, Flatpak
  and agent containment are implemented), D-13 (`overlay_network` exists) and
  D-14 (`even_deny_root` was decided in D-19).
- Roadmap: the owner approved no Tier 2 or Tier 3 item until the first run on
  real hardware has passed (2026-10-23). `docs/open-items.md`: the container
  test times are re-measured from CI (15m53s and 17m55s, not 21m).
- VM test: a full run from `pre-aegis-updated` passed on a quiet host
  (2026-10-23), step 4 included, so that open item is closed.
- `docs/upstream-baseline.md`: re-checked against Omarchy `cbd44ba`. No row
  changed; the new `omarchy-kernel`, regional mirrors, connectivity check and
  fallback NTP servers are recorded. The Extension Pack is not needed for USB
  passthrough (corrected in `open-items.md` and `operating-notes.md`).

### Fixed (found by the VM and container tests)

- Container test (D-25): senders hold their socket open, so the collector's
  owner check no longer races their exit (CI rejected root's first datagram
  once), and the spoofed datagram is rejected for its uid.
- `agent_containment` (D-26): the Smokescreen extract reported `changed` on
  every run (`--no-same-owner` without `owner`/`group`); the binary is now
  root:root from extraction and a second run changes nothing (VM, 2026-10-25).
- `opensnitch` (D-09): `opensnitch-ui` 1.7.2 aborted at every login in the VM
  (no tray found, then an uninitialised notify2 call; fixed upstream in 1.8.0,
  which Arch does not ship yet). The role sets `hide_systray_warning=true` in
  the UI settings so that path returns early, and reads it back.

- `opensnitch` (D-09): an unanswered prompt denied the connection until
  restart, because `opensnitch-ui` defaults to deny, so "allow by default"
  held only while no UI ran. In the VM it cut all egress after a reboot. The
  role now sets the UI's prompt-timeout action to the daemon's default action
  and reads it back; the VM test checks that a program with no rule gets out
  while the UI runs. The drift check's copy now includes
  `community.general.ini_file`.

- `overlay_network` (D-24): the `network.overlay` finding said "SSH closed"
  while Tailscale accepted every inbound connection on `tailscale0` before
  ufw (measured in the VM against Headscale). It now WARNs while that is so.
  New checks: `ssh.password_auth` (WARN when sshd's effective settings allow
  passwords) and `ssh.authorized_keys` (INFO for keys that are not `sk-`).
  Five container checks (52 in all); `tests/vm/tailscale.sh` tests it against
  a real tailnet.

- VM test: the lock-screen check types wrong passwords until the guest has
  recorded 10 failures (at most 15), instead of assuming 10 typed attempts
  are 10 failures. On 2026-10-24 one attempt never reached the lock screen
  and the check failed although the lockout was right. The tally watcher
  runs 120 s instead of 80 s so the extra attempts fit.
- VM test: snapshot `pre-aegis-hw` adds an xHCI controller, so a FIDO2 key
  can be attached to the guest after boot (`tests/vm/README.md` §5c). A USB
  filter that grabbed the key at power-on hung one boot before the firmware.

- `kernel` (D-02): the role no longer fails once you make `linux-hardened`
  the default boot entry, the switch D-02 leaves to you. It still fails when
  the `linux-hardened` entry is missing, and the `kernel.hardened` finding
  now names the default entry. Three container checks cover it (47 in all).

- AppArmor: profiles declared `flags=(unconfined)` (78 of 145) are no longer
  forced into complain mode. Forcing them broke rootless Podman.
- `aegis-agent`: Podman's default seccomp profile allows `unshare` and `clone`
  with `CLONE_NEWUSER`. The agent now runs with a derived profile that refuses
  them (D-01).
- OpenSnitch: the rules directory is 0755, the mode `opensnitchd` resets it to
  on start. 0700 showed up as drift after every reboot.
- `pam_faillock`: the tally directory is 0755, not 0700. Omarchy's lock
  screen runs PAM as the user, and behind 0700 it recorded no failures at all
  (silently: `pam_faillock` returns success on `EACCES`). This was a
  regression from G1, measured on the VM. The VM test now checks the lockout
  at the real lock screen.
- Docs: a lockout survives a reboot only without autologin. Omarchy's
  `sddm-autologin` runs `pam_faillock authsucc`, which clears it.
- `tests/container/run.sh` requires the final `N/N checks passed` line. It had
  once reported exit 0 after a FAIL.
- VM test: step 4 is scripted. `sudo` and `su` fill one faillock tally, and
  `su` refuses a non-wheel user (`tests/vm/pty-auth.py` drives `su` on a pty).
- VM test: the D-11 wait was 5 minutes, the check took 9m21s, and the test then
  read the unit's default `Result=success` and reported a false failure. It now
  waits up to 20 minutes and fails if the check is still running.
- D-16: ASan and TSan builds (gcc 16, clang 23.1.3) run under
  `vm.mmap_rnd_bits=32`, measured in the VM.
- VM test: no more "junk after the JSON data" warnings. Arch's sudo PAM stack
  runs `pam_systemd`, which prints an OSC 3008 sequence on the pty when the
  session ends; the VM inventory now sets `ansible_ssh_use_tty: false`.
- The `accounts.password_hash` finding says `sudo passwd USER`: plain `passwd`
  refuses to keep the same password, and `sudo passwd` rehashes with yescrypt
  (measured in the VM).

- `pacman_integrity`:
  - A file with several `-Qkk` reasons is listed and counted once. It used to
    appear once per reason.
  - `pacman.upgrade_age` no longer warns on a fresh install. The Omarchy
    installer never runs `-Syu`, so the age counts from the first log entry.
  - `/etc/sudoers.d/50-asdcontrol`, from Omarchy's base `asdcontrol` package
    and restricted by regex, is added to the known NOPASSWD files.

- `SECURITY.md`: GitHub private vulnerability reporting is not available on
  private repos, so the report link is replaced until the repo goes public.

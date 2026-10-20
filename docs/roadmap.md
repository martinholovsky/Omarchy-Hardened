# Roadmap: hardening backlog

This backlog merges the two research reviews:

- [research/securix-linux-review.md](research/securix-linux-review.md): the
  owner's Securix-Linux, a Gentoo hardened-sources/grsecurity server distro,
  re-checked against 2026 kernels. 192 settings classified.
- [research/secureblue-review.md](research/secureblue-review.md): secureblue
  at `5be4f13`.

Both were checked against Omarchy at `dde0d12`. **Nothing here is implemented
yet.** Each item changes security posture, so it needs the owner's go-ahead.
Items that wait on a recorded decision point to `open-decisions.md`.

"Both" means the two reviews recommend the item independently.

## Tier 1: low Omarchy risk, extends existing roles

| # | Item | Role | Source |
|---|---|---|---|
| 1 | Info-leak / attack-surface sysctls: `perf_event_paranoid=2` (3 only on linux-hardened), `kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`, `dev.tty.ldisc_autoload=0`, `vm.unprivileged_userfaultfd=0`, `kernel.sysrq=0` or `16` | `sysctl` | both |
| 2 | Filesystem sysctls: `fs.protected_fifos=2`, `fs.protected_regular=2` (systemd sets 1), `fs.suid_dumpable=0` (systemd-coredump sets 2) | `sysctl` | both |
| 3 | ASLR: `vm.mmap_rnd_bits` / `mmap_rnd_compat_bits` at the kernel maximum; **assert** `vm.mmap_min_addr >= 65536` (Securix's 4096 would weaken it) | `sysctl` | both |
| 4 | Network sysctls that leave Omarchy's ARP fix alone: `send_redirects=0`, `accept_redirects=0` (IPv4 **and** IPv6), `secure_redirects=0`, `accept_source_route=0` (both), `tcp_syncookies=1`, `tcp_rfc1337=1`, `use_tempaddr=2`, `rp_filter=2` (loose, not 1) | `sysctl` | both |
| 5 | `kernel.oops_limit=100`, `kernel.warn_limit=100` | `sysctl` | secureblue |
| 6 | faillock `audit` and `even_deny_root` | `pam_faillock` | secureblue |
| 7 | pacman: HTTPS-only mirrorlist assert; warn when the last `-Syu` is older than N days | `pacman_integrity` | secureblue |
| 8 | Integrity sweeps: setuid/setgid inventory against an allowlist, world-writable and unowned files, `pacman -Qkk` drift, NOPASSWD sudoers drop-in review, dangerous-group membership (docker/libvirt) | `pacman_integrity` | both |
| 9 | Runtime-truth audit pattern: generate asserts from the same variable that writes the file, compare with `/proc`, PASS/INFO/WARN/FAIL, JSON lines, skip list, golden-file CI | all roles | secureblue |

## Tier 2: new roles, low to medium risk

| # | Item | Proposed role | Source |
|---|---|---|---|
| 10 | Module blocklist with `install X /bin/false`: obscure network protocols, debug/test modules, legacy buses (firewire), rare filesystems. **Not** bluetooth, thunderbolt, cifs/nfs clients, hfsplus, udf. Fail if a blocked module is loaded anyway | `module_blocklist` | both |
| 11 | Kernel cmdline via a separate `/etc/limine-entry-tool.d/` drop-in plus UKI rebuild: `init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none random.trust_cpu=off random.trust_bootloader=off`; assert through `/proc/cmdline` | `kernel` | both |
| 12 | `lsm=` adding `apparmor` (verified: Arch `linux` has `CONFIG_SECURITY_APPARMOR=y` but `CONFIG_LSM="landlock,lockdown,yama,integrity,bpf"`) | `kernel` + `apparmor` | Securix |
| 13 | Strict IOMMU DMA protection (`iommu.strict=1`, `intel_iommu=on`, …). This matters because Omarchy keeps Thunderbolt on. Test with docks | `kernel` | secureblue |
| 14 | Core dumps: `coredump.conf.d` size and storage limits, **not** `core_pattern=\|/bin/false` (breaks `omarchy-crash-watch`) | `coredump` | both |
| 15 | NetworkManager privacy: stable MAC randomization, no DHCP hostname, IPv6 privacy | `network_privacy` | secureblue |
| 16 | sshd drop-in for Omarchy's opt-in sshd: `Compression no` (OpenSSH 10.6, 2026-10-06, changed compression over a side channel; verified in the release notes), `PermitRootLogin no`, `MaxAuthTries 3`, no forwarding, `LogLevel VERBOSE`, keep `UsePAM yes` | `sshd` | both |
| 17 | Mount options: ESP `nodev,nosuid,noexec,fmask=0077,dmask=0077`; `/home` and `/tmp` `nodev,nosuid`. **Never** `noexec` on `/var` or `/home` | `mounts` | Securix |
| 18 | Flathub `--subset=verified` remote plus a permission-severity audit (no global lockdown) | `flatpak` | secureblue |

## Tier 3: needs a decision or a VM test first

| # | Item | Waits on |
|---|---|---|
| 19 | `lockdown=integrity`. `confidentiality` breaks hibernation (Omarchy ships `omarchy-hibernation-setup`) | D-02, VM test |
| 20 | `module.sig_enforce=1`. Breaks unsigned DKMS (NVIDIA, broadcom-wl) until a signing hook exists | new decision |
| 21 | Secure Boot with signed UKIs (sbctl); Omarchy already builds UKIs | new decision |
| 22 | NTS time sync with chrony. Omarchy's `omarchy-update-time` restarts timesyncd, so it needs a compatible override | new decision |
| 23 | USBGuard. Omarchy shipped device approval and then **reverted** it (`migrations/1791769486.sh`), so opt-in only | new decision |
| 24 | auditd exec/mount/time rules, opt-in (noisy on a desktop) | new decision |
| 25 | `ptrace_scope=2`, `io_uring_disabled`, `mitigations=auto,nosmt` as opt-ins | owner |
| 26 | Login policy: pam_umask, `HOME_MODE 0700`, lock root, mask ctrl-alt-del, `TMOUT` on TTY/SSH only | owner |

## Do not adopt (breaks Omarchy)

These were confirmed against Omarchy's source:

- `fs.binfmt_misc.status=0`: Omarchy ships `qemu-user-static-binfmt`.
- `core_pattern=|/bin/false` or `core 0`: breaks `omarchy-crash-watch` and `omarchy-agent-crash`.
- `arp_ignore=2` / `arp_filter=1`: undoes Omarchy's dock-plus-Wi-Fi fix.
- `ip_forward=0`: breaks Docker.
- Strict `rp_filter=1`: breaks WireGuard/Tailscale.
- Blocking bluetooth or thunderbolt.
- Removing sudo, global setuid stripping, `chattr +i` dotfiles.
- Xwayland off.
- A global `/etc/ld.so.preload` hardened_malloc. The AUR package was flagged out of date on 2026-02-23, and `no_rlimit_as` is not packaged anywhere.
- Default USBGuard.
- `ia32_emulation=0` with Steam.
- `noexec` on `/var` or `/home`.
- Lowering `fs.file-max`, `pid_max` or `shmmax`.
- `tcp_sack=0`, `tcp_timestamps=0`.
- `TMOUT` in graphical terminals.
- Overriding Omarchy's zram/kyber/BBR tuning.
- Replacing resolved with Unbound/dnsconfd.
- Securix's server-era sshd ciphers (blowfish-cbc was removed in OpenSSH 7.6).

## Where the reviews and the PRD disagree

- **faillock count (decided, D-13).** The PRD asked for `deny=3`. The owner
  chose 10, Omarchy's default, and kept the PRD's 15-minute unlock. The
  Securix review suggested 5; secureblue uses 50 with a 24-hour unlock.
- **Kernel facts are checked against Arch `linux`, not `linux-omarchy`.**
  Neither review found the `linux-omarchy` config. The `kernel` role must read
  `/proc/config.gz` on the target before relying on any of them.

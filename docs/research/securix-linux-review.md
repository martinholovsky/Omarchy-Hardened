# Securix-Linux review for Omarchy-Hardened (2026 Arch/Omarchy desktop)

Reviewed: `martinholovsky/Securix-Linux` at commit `a5846a4` (93 commits; the README says "Project was discontinued"). The kernel config header says `Linux/x86_64 3.7.0-hardened`, and it also contains `IP_NF_TARGET_SYNPROXY`, so it was carried forward to 3.12 or later. Securix is a **headless server** distro (Gentoo hardened-sources with grsecurity/PaX, OpenRC, iptables, no X: `USE="-X ..."`). Most of its choices assume a server, and that matters for every desktop verdict below.

Compatibility baseline: Omarchy clone at `dde0d12`. It was searched with `grep -rn --hidden` over `etc/ install/ bin/ default/ migrations/`.

## Denominator

**Repository:** 49 tracked files (`find . -type f -not -path './.git/*'`).

**Inspected in full (active lines extracted):**
- `system-config/etc/sysctl.d/00_securix_sysctl.conf` (179 lines)
- `system-config/etc/kernels/hardened-amd64.config` (2779 lines, 890 `CONFIG_` lines)
- `system-config/etc/login.defs`
- `system-config/etc/security/limits.d/sx-limits.conf`
- `system-config/etc/ssh/sshd_config`
- `system-config/etc/conf.d/iptables.rules`
- `system-config/var/lib/iptables/rules-save`
- `system-config/etc/securetty`, `system-config/etc/shells`, `system-config/etc/cron.allow`
- `system-config/etc/securix/securix.conf`
- `system-config/etc/logrotate.d/sx-rotate`
- `securix-control/profile.d/sx-profile.sh` and `securix-control/profile.d/sx-aliases.sh`

**Inspected by targeted grep and section reads (not line by line):**
- `securix-install/install.sh`: mount options, fstab, make.conf, LUKS
- `securix-install/chroot.sh`: kernel build, services, GRUB, groups, toolchain
- `securix-control/securix-monitor`: integrity checks
- `securix-control/securix`: config subcommands
- `system-config/etc/fail2ban/jail.local`: enabled jails only
- `system-config/etc/syslog-ng/syslog-ng.conf`: destinations only

**Not inspected for settings:**
- 9 certificate and key files, 3 image files, `LICENSE`, `changelog.txt`, `issue`, `dispatch-conf.conf`
- `rkhunter.conf` (987 lines; only the fact that rkhunter is used is recorded)
- `securix-mailer`, `securix-motd`, `securix-update`, `securix-cron`, `securix-functions`, `checksec.sh`, `cron.daily/rkhunter`, `cron.hourly/sx-once-rkhunter`. These are operational scripts; the motd one was grepped once, for gradm.

**Settings extracted:**

| Source | Raw entries | Table rows | Note |
|---|---|---|---|
| sysctl | 47 active + 10 commented-out | 43 (41 + 2) | all/default pairs merged into one row |
| kernel: grsecurity/PaX | 75 enabled lines + 7 PaX "not set" lines that matter | 27 | grouped by feature |
| kernel: other options | about 40 | 34 | |
| mount options | 9 | 8 | |
| login.defs + limits.d + profile.d/aliases/shells/cron.allow | 33 + 8 + about 25 lines | 21 | trivial defaults merged |
| sshd_config (+ fail2ban jail) | 31 lines | 22 | |
| firewall (iptables) | about 45 rule lines | 9 | |
| services, monitoring, boot, build, package hygiene | about 40 | 28 | |
| **Total** | **about 330 raw entries** | **192** | |

The 192 was counted mechanically (awk over the data rows of this file's 8 setting tables, excluding headers and separators; the source and denominator tables are not counted).

## Primary sources fetched this session

Fetched with `curl` and grepped locally, not quoted from memory. The mainline `master` HEAD was `f47d2236` on 2026-10-20.

| Key | URL |
|---|---|
| [K] | https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/sysctl/kernel.rst |
| [VM] | https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/sysctl/vm.rst |
| [FS] | https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/sysctl/fs.rst |
| [IP] | https://github.com/torvalds/linux/blob/master/Documentation/networking/ip-sysctl.rst |
| [NET] | https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/sysctl/net.rst |
| [KP] | https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt |
| [PROC] | https://github.com/torvalds/linux/blob/master/Documentation/filesystems/proc.rst |
| [YAMA] | https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/LSM/Yama.rst |
| [IOS] | https://github.com/torvalds/linux/blob/master/block/Kconfig.iosched |
| [HARD] | https://github.com/torvalds/linux/blob/master/security/Kconfig.hardening |
| [LH] | https://github.com/anthraxx/linux-hardened/tree/v7.2.10-hardened1 (`kernel.rst`, `ip-sysctl.rst`, `security/Kconfig`, `kernel/user_namespace.c`, `drivers/usb/core/sysctl.c`) |
| [ARCH] | https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config.x86_64 (Arch `linux`; used as a **proxy** because the `linux-omarchy` config source was not found, see the caveat below) |
| [SD] | https://github.com/systemd/systemd/blob/main/sysctl.d/50-default.conf, `50-pid-max.conf`, `50-coredump.conf.in` |
| [OSSH] | https://www.openssh.org/releasenotes.html |
| [SHADOW] | https://github.com/shadow-maint/shadow/blob/master/man/login.defs.5.xml |
| [GRSEC] | https://grsecurity.net/passing_the_baton (2017-04-26: free test patches handed to the community; 4.9 was the last version released to non-subscribers) |
| [GENTOO] | https://www.gentoo.org/news/2017/08/19/hardened-sources-removal.html (`hardened-sources` masked 2017-08-27, removed by the end of 2017-09) |
| [C-CFQ] | https://github.com/torvalds/linux/commit/f382fb0bcef4 "block: remove legacy IO schedulers". `compare f382fb0bcef4...v5.0` = ahead and `...v4.20` = diverged, so it **landed in 5.0** |
| [C-KMEM] | https://github.com/torvalds/linux/commit/bbcd53c96071 "drivers/char: remove /dev/kmem for good" (2021-05, 5.13 merge window) |
| [C-SSP] | https://github.com/torvalds/linux/commit/050e9baa9dc9 "Kbuild: rename CC_STACKPROTECTOR[_STRONG] config variables" (2018-06) |
| [C-VSYS] | https://github.com/torvalds/linux/commit/bf00745e7791 "x86/vsyscall: Remove CONFIG_LEGACY_VSYSCALL_EMULATE" (2022-05) |
| [C-SLAB] | https://github.com/torvalds/linux/commit/2a19be61a651 "mm/slab: remove CONFIG_SLAB from all Kconfig and Makefile" (2023-12) |

**Caveat on the kernel.** I could not locate the `linux-omarchy` kernel config: it is not in the Omarchy tree, and a GitHub repo search found nothing. Every "Arch kernel already has X" statement below is against **Arch `linux`** and is **unverified for `linux-omarchy`**. The kernel role should assert these at runtime, for example with `/proc/config.gz` or `zgrep` on `/lib/modules/$(uname -r)/build/.config`.

Classification legend:
- **VALID** = STILL-VALID
- **SUPERSEDED**
- **REMOVED** = REMOVED or OBSOLETE
- **HARMFUL** = HARMFUL-ON-DESKTOP
- **NO-OP** = already the default; adopting it changes nothing

"Omarchy?" means "does the Omarchy clone already set this?" Anything not checked against a primary source is marked *unverified*.

---

## 1. sysctl (`/etc/sysctl.d/00_securix_sysctl.conf`)

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| kernel.core_uses_pid | 1 | NO-OP | systemd 50-default.conf already sets 1, and it is irrelevant when core_pattern pipes to systemd-coredump | no (systemd does) | — | [K] [SD] |
| kernel.exec-shield (commented) | 1 | REMOVED | Red Hat out-of-tree patch, never in mainline (absent from kernel.rst); NX comes from hardware plus mainline | no | — | [K] |
| kernel.randomize_va_space | 2 | VALID / NO-OP | Keep 2; pair it with vm.mmap_rnd_bits / vm.mmap_rnd_compat_bits set to their maximum (both exist in vm.rst) to recover part of PaX RANDMMAP | no | sysctl | [K] [VM] |
| kernel.panic | 30 | HARMFUL | Auto-reboot 30 s after a panic. On a laptop that loses the panic screen and any unsaved work; acceptable only as an opt-in | no | kernel (opt-in var) | [K] |
| kernel.panic_on_oops | 30 | HARMFUL | Doc semantics are 0 or 1 (nonzero means panic). A GPU or Wi-Fi driver oops would take the whole desktop down. KSPP-style servers want it; desktops should keep 0 by default (opt-in) | no | kernel (opt-in) | [K] |
| kernel.sysrq | 0 | VALID | Arch builds with MAGIC_SYSRQ_DEFAULT_ENABLE=0x0, but systemd raises it to 16 (sync only). 0 or 16 are both fine; 0 also loses emergency sync | no (systemd=16) | sysctl | [K] [SD] [ARCH] |
| fs.suid_dumpable | 0 | VALID | systemd-coredump sets **2** (dumps go root-only through the pipe). 0 is stricter and only affects setuid/privileged processes, so Omarchy's crash-watch keeps working for normal apps | no (systemd=2) | sysctl | [FS] [SD] |
| kernel.shmmax | 268435456 | HARMFUL | Caps SysV shm at 256 MiB, far below the modern default. Can break Xwayland MIT-SHM clients, databases and some electron/GPU apps (breakage specifics *unverified*). Do not adopt | no | — | [K] |
| kernel.kptr_restrict | 2 | VALID | Hides kernel pointers even from root (makes `perf` less useful; 1 is a dev-friendly fallback). Replaces GRKERNSEC_HIDESYM | no | sysctl | [K] |
| vm.mmap_min_addr | 4096 | HARMFUL (weakens) | Arch default CONFIG_DEFAULT_MMAP_MIN_ADDR=65536, and the vm.rst doc recommends 64k. 4096 **lowers** NULL-deref protection. Do not adopt; assert >= 65536 instead | no | sysctl (assert) | [VM] [ARCH] |
| fs.file-max | 65000 | HARMFUL | System-wide cap below Omarchy's own `DefaultLimitNOFILE=65536:524288` (verified in `etc/systemd/system.conf.d/20-omarchy-nofile.conf`). Browsers, IDEs and Docker would hit ENFILE | yes (indirectly, via a higher nofile) | — | [FS] |
| kernel.pid_max | 65536 | HARMFUL | systemd ships 4194304 (50-pid-max.conf). Lowering it shrinks PID space for containers and agent sandboxes | no (systemd sets 4194304) | — | [K] [SD] |
| net.core.optmem_max | 57344 | REMOVED (pointless) | Perf knob from the 2010s; the mainline default is now larger (exact default *unverified*). Skip | no | — | [NET] |
| net.ipv4.ip_forward | 0 | HARMFUL | Omarchy installs **docker** (`install/omarchy-base.packages:24`), and Docker sets ip_forward=1. Forcing 0 breaks container networking. Enforce with firewall FORWARD/routed policy instead | no | firewall | [IP] |
| net.ipv4.tcp_fin_timeout | 15 | VALID (perf, server) | Harmless; little desktop value. Skip | no | — | [IP] |
| net.ipv4.tcp_keepalive_time | 1800 | VALID (perf) | Server tuning. Skip | no | — | [IP] |
| net.ipv4.tcp_window_scaling | 1 | NO-OP | Default | no | — | [IP] |
| net.ipv4.tcp_sack | 0 | HARMFUL / SUPERSEDED | Disabling SACK hurts throughput on lossy Wi-Fi. The 2019 SACK-panic CVEs were fixed in-kernel (fix details *unverified*). Keep 1 | no | — | [IP] |
| net.ipv4.tcp_timestamps | 0 | SUPERSEDED | Mainline value 1 now uses a **random offset per connection** (ip-sysctl.rst), which removes the uptime leak; 0 disables PAWS and RTT measurement. Keep default 1 | no | — | [IP] |
| net.ipv4.icmp_echo_ignore_broadcasts | 1 | NO-OP / VALID | Default is already 1 (*unverified* default value); can be asserted | no | sysctl | [IP] |
| net.ipv4.icmp_ignore_bogus_error_responses | 1 | NO-OP / VALID | Same as above | no | sysctl | [IP] |
| net.ipv4.tcp_no_metrics_save | 1 | VALID (perf preference) | Exists; no security value. Skip | no | — | [IP] |
| net.ipv4.tcp_syncookies | 1 | VALID | Keep and assert 1 | no | sysctl | [IP] |
| net.ipv4.tcp_max_syn_backlog | 4096 | VALID (server) | Skip on a desktop | no | — | [IP] |
| net.ipv4.tcp_syn_retries | 5 | VALID (minor) | Close to the default. Skip | no | — | [IP] |
| net.ipv4.tcp_synack_retries | 2 | VALID (server) | Skip | no | — | [IP] |
| net.ipv4.conf.{all,default}.send_redirects | 0 | VALID | A desktop is not a router; Docker bridges do not need redirects | no | sysctl | [IP] |
| net.ipv4.conf.{all,default}.rp_filter | 1 (strict) | VALID with change | systemd sets **2 (loose)**. Strict mode breaks asymmetric routing with WireGuard/Tailscale (overlay_network role) and multi-homed laptops. Use 2 | no (systemd=2) | sysctl | [IP] [SD] |
| net.ipv4.conf.{all,default}.secure_redirects | 1 | SUPERSEDED | Moot once accept_redirects=0; modern guides set 0 | no | sysctl | [IP] |
| net.ipv4.conf.{all,default}.accept_redirects | 0 | VALID | Keep, and **add** net.ipv6.conf.{all,default}.accept_redirects=0, which Securix lacks because IPv6 was compiled out | no | sysctl | [IP] |
| net.ipv4.conf.{all,default}.log_martians | 1 | VALID (noisy) | Docker, VPN and Wi-Fi roaming generate journal noise; opt-in | no | sysctl (opt-in) | [IP] |
| net.ipv4.conf.{all,default}.proxy_arp | 0 | NO-OP | Default 0 | no | — | [IP] |
| net.ipv4.conf.{all,default}.accept_source_route | 0 | VALID / NO-OP | systemd already sets 0 for default and `*`; add the IPv6 equivalent | no (systemd does) | sysctl | [IP] [SD] |
| net.ipv4.tcp_moderate_rcvbuf | 1 | NO-OP | Default | no | — | [IP] |
| net.ipv4.tcp_max_tw_buckets | 1440000 | VALID (server) | Skip | no | — | [IP] |
| net.ipv4.ip_local_port_range | 1024 64000 | HARMFUL | Ephemeral ports would collide with local dev servers on 3000/5173/8080 etc. Keep the default | no | — | [IP] |
| net.ipv4.ipfrag_high_thresh | 512000 | REMOVED (pointless) | Lowers the reassembly memory cap below the modern default (default *unverified*). Skip | no | — | [IP] |
| net.ipv4.ipfrag_low_thresh | 446464 | REMOVED | ip-sysctl.rst: "(Obsolete since linux-4.17)" | no | — | [IP] |
| net.ipv4.neigh.default.gc_thresh1 | 1024 | VALID (large-L2 perf) | Skip on a desktop | no | — | [IP] |
| net.ipv4.neigh.default.gc_thresh2 | 2048 | VALID (perf) | Skip | no | — | [IP] |
| net.ipv4.neigh.default.gc_thresh3 | 4096 | VALID (perf) | Skip | no | — | [IP] |
| net.ipv6.conf.*.disable_ipv6 (commented) | 1 | HARMFUL | Breaks IPv6-only networks and some apps. Prefer firewalling | no | — | [IP] |
| net.ipv6.conf.default.{router_solicitations, accept_ra_rtr_pref, accept_ra_pinfo, accept_ra_defrtr, autoconf, dad_transmits, max_addresses} (commented, 8 keys) | 0 / 1 | HARMFUL | All exist in mainline, but they kill SLAAC on a roaming laptop. Skip. Instead consider `use_tempaddr=2` (IPv6 privacy addresses) | no | — | [IP] |

**Modern sysctls Securix never had, and the grsecurity feature each replaces.** All were verified to exist in the docs named.

| Sysctl | Recommended value | Replaces | Source |
|---|---|---|---|
| kernel.dmesg_restrict | 1 | GRKERNSEC_DMESG | [K] |
| kernel.yama.ptrace_scope | 1 | GRKERNSEC_HARDEN_PTRACE | [YAMA] |
| fs.protected_{symlinks,hardlinks} | 1 | GRKERNSEC_LINK | [FS] |
| fs.protected_{fifos,regular} | 2 | GRKERNSEC_FIFO | [FS] |
| kernel.unprivileged_bpf_disabled | — | — | [K] |
| net.core.bpf_jit_harden | 2 | — | [NET] |
| kernel.perf_event_paranoid | 3 on linux-hardened, else 2 | — | [K] [LH] |
| kernel.kexec_load_disabled | 1 | — | [K] |
| vm.unprivileged_userfaultfd | 0 | — | [VM] |
| kernel.io_uring_disabled | 1 or 2, with care: some apps use io_uring | — | [K] |
| dev.tty.ldisc_autoload | 0 | — | unverified |
| net.ipv4.tcp_rfc1337 | 1 | — | [IP] |

Notes:
- **ptrace_scope:** 2 breaks user gdb/strace.
- **fs.protected_\*:** systemd already sets all four to 1 ([SD]).
- **kernel.unprivileged_bpf_disabled:** Arch has `BPF_UNPRIV_DEFAULT_OFF=y` ([ARCH]).
- **linux-hardened-only sysctls** ([LH]):
  - `kernel.tiocsti_restrict`
  - `net.ipv4.tcp_simult_connect`
  - `kernel.deny_new_usb`
  - `kernel.unprivileged_userns_clone`: **must stay 1 for Flatpak/bubblewrap and the Chromium/Electron sandbox**. The variable is defined in `kernel/user_namespace.c` and checked in `kernel/fork.c`.

---

## 2. Kernel: grsecurity / PaX (75 enabled lines, grouped)

Umbrella verdict: **REMOVED**. Public grsecurity/PaX test patches ended in 2017, with 4.9 the last version released to non-subscribers ([GRSEC]), and Gentoo removed `hardened-sources` in September 2017 ([GENTOO]). The 2026 replacement is the **linux-hardened** kernel (tag v7.2.10-hardened1, verified), or `linux-omarchy` with KSPP boot parameters, plus the Lockdown LSM, Yama, Landlock and AppArmor.

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| GRKERNSEC, CONFIG_AUTO, CONFIG_SERVER, PRIORITY_PERF, VIRT_* (set by chroot.sh) | y | REMOVED | linux-hardened kernel, or mainline plus a KSPP cmdline (kernel role) | no | kernel | [GRSEC] [LH] |
| gradm RBAC (ACL_HIDEKERN, ACL_MAXTRIES=3, ACL_TIMEOUT=30, NO_RBAC unset; gradm installed) | y | SUPERSEDED | AppArmor (needs `lsm=` to include apparmor: the Arch LSM default is `landlock,lockdown,yama,integrity,bpf`, without apparmor) and Landlock | no | apparmor | [ARCH] |
| PAX_NOEXEC, PAX_PAGEEXEC | y | SUPERSEDED | Hardware NX plus mainline W^X for kernel mappings; nothing to do | no | — | — |
| PAX_EMUTRAMP | y | REMOVED | No mainline equivalent; not needed | no | — | — |
| PAX_MPROTECT | y | HARMFUL (as a global policy) | No global mainline equivalent. Per-service: systemd `MemoryDenyWriteExecute=`. A global version would break browsers, Electron, JVMs, LuaJIT and Mesa shader JITs | no | agent_containment (per-unit) | — |
| PAX_EI_PAX, PAX_PT_PAX_FLAGS, PAX_NO_ACL_FLAGS (+ paxctl, paxtest, pax-utils) | y | REMOVED | No binary markings exist anymore. `pax-utils` (scanelf) is still useful for auditing textrels and RWX segments | no | pacman_integrity (audit) | — |
| PAX_ASLR, PAX_RANDMMAP, PAX_RANDUSTACK | y | SUPERSEDED | `randomize_va_space=2` plus `vm.mmap_rnd_bits` at its maximum | no | sysctl | [K] [VM] |
| PAX_RANDKSTACK | y | SUPERSEDED | `randomize_kstack_offset=on` ([KP]); Arch already defaults it on via RANDOMIZE_KSTACK_OFFSET_DEFAULT=y | no (cmdline) | kernel (assert) | [KP] [ARCH] |
| PAX_MEMORY_SANITIZE | y | SUPERSEDED | `init_on_free=1` ([KP]). Arch has INIT_ON_ALLOC_DEFAULT_ON=y, but not INIT_ON_FREE. Costs a few percent of performance (*unverified* figure) | no | kernel | [KP] [HARD] [ARCH] |
| PAX_REFCOUNT | y | SUPERSEDED | Mainline saturating `refcount_t` (merge version *unverified*) | no | — | — |
| PAX_USERCOPY, PAX_USERCOPY_SLABS | y | SUPERSEDED | HARDENED_USERCOPY (Arch y), plus `slab_nomerge` on the cmdline (exists in [KP]), plus SLAB_FREELIST_HARDENED (Arch y) | no | kernel | [HARD] [KP] [ARCH] |
| PAX_KERNEXEC, PAX_MEMORY_UDEREF (not set) | n | SUPERSEDED | STRICT_KERNEL_RWX plus SMEP/SMAP/PTI in hardware and mainline; nothing to do | no | — | [KP] (pti=) |
| PAX_MEMORY_STACKLEAK (not set) | n | SUPERSEDED | Mainline KSTACK_ERASE (renamed from GCC_PLUGIN_STACKLEAK; both symbols present in [HARD]); enabled in linux-hardened (*unverified*) | no | kernel (linux-hardened) | [HARD] |
| PAX_LATENT_ENTROPY, PAX_SIZE_OVERFLOW (not set) | n | SUPERSEDED / REMOVED | LATENT_ENTROPY is a mainline GCC plugin; SIZE_OVERFLOW was never upstreamed (*unverified*) | no | — | — |
| GRKERNSEC_KMEM | y | SUPERSEDED | STRICT_DEVMEM + IO_STRICT_DEVMEM (Arch y). `/dev/kmem` was removed entirely ([C-KMEM]) | no | — | [C-KMEM] [ARCH] |
| GRKERNSEC_IO (ioperm/iopl) | y | SUPERSEDED | `lockdown=integrity` ([KP]) restricts raw I/O ports (exact list *unverified*) | no | kernel | [KP] |
| GRKERNSEC_MODHARDEN | y | SUPERSEDED / HARMFUL (strict form) | `module.sig_enforce=1` (exists in [KP]) or `kernel.modules_disabled=1`. **HARMFUL with Omarchy's NVIDIA DKMS** (`migrations/1791077437.sh`), where unsigned DKMS modules fail to load. modules_disabled breaks USB/BT hotplug. Opt-in only, or after setting up DKMS signing | no | kernel (opt-in) | [KP] [K] |
| GRKERNSEC_HIDESYM | y | SUPERSEDED | `kptr_restrict=2`, plus `dmesg_restrict=1` (Arch SECURITY_DMESG_RESTRICT=y) | no | sysctl | [K] [ARCH] |
| GRKERNSEC_PROC, PROC_USERGROUP, PROC_ADD, PROC_GID=111, PROC_MEMMAP | y | SUPERSEDED / HARMFUL (global) | `/proc` `hidepid=invisible,gid=` ([PROC]). Globally on a systemd desktop it is known to upset logind/polkit (*unverified*). Prefer per-service `ProtectProc=invisible` | no | agent_containment | [PROC] |
| GRKERNSEC_LINK, GRKERNSEC_FIFO, SYMLINKOWN_GID | y | SUPERSEDED | `fs.protected_symlinks/hardlinks/fifos/regular`; systemd sets 1, raise fifos/regular to 2 | no (systemd=1) | sysctl | [FS] [SD] |
| GRKERNSEC_CHROOT_* (15 options: MOUNT, DOUBLE, PIVOT, CHDIR, CHMOD, FCHDIR, MKNOD, SHMAT, UNIX, FINDTASK, NICE, SYSCTL, CAPS, EXECLOG, CHROOT) | y | SUPERSEDED | chroot is no longer the boundary. Use namespaces + seccomp + Landlock (bubblewrap/Flatpak, systemd sandboxing) | no | flatpak, agent_containment | — |
| GRKERNSEC_EXECLOG, RESLOG, AUDIT_CHDIR, AUDIT_MOUNT, SIGNAL, FORKFAIL, TIME, RWXMAP_LOG, AUDIT_TEXTREL | y | SUPERSEDED | auditd rules (execve, mount, settimeofday/clock_settime, kill), backed by CONFIG_AUDIT (Arch y; Securix had **AUDIT not set**). Desktop exec logging is noisy, so make it opt-in | no | **new: auditd** | [ARCH] |
| GRKERNSEC_HARDEN_PTRACE | y | SUPERSEDED | Yama `kernel.yama.ptrace_scope=1` (Yama is in the Arch LSM list) | no | sysctl | [YAMA] [ARCH] |
| GRKERNSEC_TPE, TPE_ALL, TPE_INVERT, TPE_GID=10, TPE_TRUSTED_GID=10 | y | REMOVED (no mainline) / HARMFUL (if emulated) | No mainline TPE. Emulating it with `noexec` on /home breaks mise, npm, cargo and uv user installs and AppImages. AppArmor profiles or fapolicyd are partial substitutes | no | apparmor | — |
| GRKERNSEC_RANDNET | y | REMOVED | Mainline already randomizes ISNs and ports | no | — | — |
| GRKERNSEC_BLACKHOLE | y | SUPERSEDED | Firewall DROP (ufw `default deny incoming`) | yes (ufw) | firewall | — |
| GRKERNSEC_SYSCTL, SYSCTL_ON, FLOODTIME=10, FLOODBURST=4, PROC_IPADDR, BRUTE | y | REMOVED | No equivalent. BRUTE (fork-respawn slowdown) partially maps to systemd `TasksMax=` / `StartLimitBurst=` | no | — | — |

---

## 3. Kernel: other build options in `hardened-amd64.config`

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| CONFIG_DEFAULT_IOSCHED / IOSCHED_CFQ | cfq | REMOVED | Legacy schedulers removed in **5.0** ([C-CFQ]). Current choices are mq-deadline, kyber and bfq ([IOS]). Omarchy already sets **kyber** for nvme/sd/mmc/vd via udev | **yes** (`etc/udev/rules.d/60-omarchy-io-scheduler.rules`) | — | [C-CFQ] [IOS] |
| `elevator=` boot param (implied era) | — | REMOVED | Absent from the current kernel-parameters.txt; use udev rules (as Omarchy does) | yes | — | [KP] |
| CONFIG_CC_STACKPROTECTOR | not set (!) | SUPERSEDED | Renamed to STACKPROTECTOR(_STRONG) ([C-SSP]); Arch has STACKPROTECTOR_STRONG=y | n/a | kernel (assert) | [C-SSP] [ARCH] |
| CONFIG_SECURITY / DEFAULT_SECURITY_DAC | not set / DAC | SUPERSEDED | Set an `lsm=` cmdline, e.g. `landlock,lockdown,yama,integrity,apparmor,bpf` ([KP] `lsm=`). Arch builds AppArmor but does not list it by default | no | apparmor / kernel | [KP] [ARCH] |
| Lockdown LSM (absent in Securix) | — | VALID (new) | `lockdown=integrity`. `confidentiality` breaks hibernation, some BPF and perf tooling (*unverified* detail). Arch has SECURITY_LOCKDOWN_LSM=y | no | kernel | [KP] [ARCH] |
| CONFIG_SECURITY_DMESG_RESTRICT | not set (grsec did it) | SUPERSEDED | Arch y; also assert the sysctl | no | sysctl | [ARCH] |
| CONFIG_MODULE_SIG | not set | SUPERSEDED | Arch MODULE_SIG=y; enforcement conflicts with DKMS (see MODHARDEN) | no | kernel | [ARCH] |
| CONFIG_NAMESPACES with UTS/IPC/PID/NET_NS off | partly off | HARMFUL | Flatpak/bubblewrap, the Chromium sandbox, Docker and systemd PrivateNetwork= all need these, plus USER_NS (Arch y) | n/a | flatpak | [ARCH] |
| CONFIG_AUDIT | not set | SUPERSEDED | Arch y; auditd optional | n/a | auditd (new) | [ARCH] |
| CONFIG_KEYS | not set | HARMFUL | Needed by fscrypt, systemd-cryptenroll, IMA and dm-crypt keyrings | n/a | — | — |
| CONFIG_SUSPEND, CONFIG_HIBERNATION | not set | HARMFUL | Laptops need suspend. Note that lockdown conflicts with hibernation (*unverified*) | n/a | — | [ARCH] |
| CONFIG_KEXEC | not set | VALID (as runtime) | Arch y; use `kernel.kexec_load_disabled=1` | no | sysctl | [K] [ARCH] |
| CONFIG_RELOCATABLE | not set | SUPERSEDED | Required for KASLR (RANDOMIZE_BASE); modern kernels have KASLR on | n/a | kernel (assert) | — |
| CONFIG_IKCONFIG_PROC | y | VALID (leak, minor) | /proc/config.gz exposes the config; low risk, and useful for the role to assert settings | unverified | — | — |
| CONFIG_KALLSYMS_ALL | y | VALID | Covered by kptr_restrict | — | — | — |
| CONFIG_SECCOMP / SECCOMP_FILTER | y | VALID | Arch y | yes (kernel) | — | [ARCH] |
| CONFIG_SLUB (SLAB not set) | SLUB | NO-OP | CONFIG_SLAB itself was removed in 6.8-era ([C-SLAB]) | — | — | [C-SLAB] |
| CONFIG_COMPAT_BRK | not set | VALID | Keeps heap randomization; linux-omarchy value *unverified* | unverified | kernel (assert) | — |
| CONFIG_LEGACY_VSYSCALL (implied) | — | SUPERSEDED | EMULATE was removed ([C-VSYS]); Arch uses XONLY; `vsyscall=none` exists ([KP]) and is safe on 2026 userspace | no | kernel | [KP] [C-VSYS] [ARCH] |
| CONFIG_IA32_EMULATION | y | VALID (keep) | `ia32_emulation=0` ([KP]) would be **HARMFUL**: it breaks Steam, Wine and Proton 32-bit | n/a | — | [KP] |
| CONFIG_X86_X32 | not set | SUPERSEDED | Renamed X86_X32_ABI; **Arch enables it (=y)**. No runtime disable switch was verified, so consider it for linux-hardened only | n/a | kernel (note) | [ARCH] |
| CONFIG_BINFMT_MISC | y | VALID (keep) | Omarchy relies on binfmt (`etc/systemd/system/systemd-binfmt.service.d`) | yes | — | — |
| CONFIG_IPV6 | not set | HARMFUL | Desktop needs IPv6 | n/a | — | — |
| CONFIG_BT, CONFIG_WIRELESS | not set | HARMFUL | Server-only choice | n/a | — | — |
| CONFIG_FIREWIRE | not set | VALID (idea) | Blacklist DMA-capable legacy buses (firewire-core, firewire-ohci) via modprobe.d. **Do not** blacklist thunderbolt: Omarchy early-loads it on purpose (`etc/mkinitcpio.conf.d/thunderbolt_module.conf`). Rely on IOMMU / bolt authorization instead | partial | kernel (modprobe blacklist) | — |
| CONFIG_USB_STORAGE | y | VALID (idea) | USBGuard, or linux-hardened `kernel.deny_new_usb` | no | **new: usbguard** | [LH] |
| CONFIG_BPF_JIT | not set | SUPERSEDED | Keep the JIT; set `net.core.bpf_jit_harden=2` and unprivileged BPF off | no | sysctl | [NET] [ARCH] |
| CONFIG_MAGIC_SYSRQ / DEBUG_FS / DEBUG_KERNEL | y | VALID (idea) | Boot `debugfs=off` ([KP]); some tools (powertop, perf) need debugfs (*unverified*), so opt-in | no | kernel (opt-in) | [KP] |
| CONFIG_STRICT_DEVMEM | y | NO-OP | Arch y (+ IO_STRICT_DEVMEM) | yes (kernel) | — | [ARCH] |
| CONFIG_PREEMPT=y, HZ_1000 | y / 1000 | NO-OP | Arch has PREEMPT_DYNAMIC + HZ=1000 already; `preempt=full` is optional | yes (kernel) | — | [ARCH] |
| CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE | y | HARMFUL (laptop) | Use amd-pstate/intel_pstate EPP + power-profiles-daemon; a permanent performance governor drains the battery | n/a | — | — |
| CONFIG_TRANSPARENT_HUGEPAGE | not set | SUPERSEDED | THP=madvise is the modern default compromise; not a security item | n/a | — | — |
| CONFIG_MICROCODE (vendor drivers not set) | partial | SUPERSEDED | Early `amd-ucode`/`intel-ucode` loading; `mitigations=auto` ([KP]); `mitigations=auto,nosmt` is an option (perf cost) | unverified (no ucode reference in Omarchy tree; probably handled by archinstall) | kernel | [KP] |
| CONFIG_DM_CRYPT + LUKS `aes-xts-plain -s 512 -h whirlpool` | y | SUPERSEDED | LUKS2 + argon2id + aes-xts-plain64. Omarchy already uses argon2id when rekeying (`bin/omarchy-drive-password:100`). Add FIDO2/TPM2 unlock via systemd-cryptenroll | yes (argon2id) | fido2 | — |

---

## 4. Mount options (`install.sh` fstab template)

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| /boot | noauto,relatime,nodiratime | HARMFUL | With Limine + UKI the ESP must be mounted for kernel and UKI updates. Use `nodev,nosuid,noexec,fmask=0077,dmask=0077` (keeps random-seed and UKI non-world-readable) | no (unverified fstab, made by installer) | **new: mounts** | — |
| / | relatime,nodiratime | NO-OP | relatime is the default and noatime implies nodiratime. Omarchy uses btrfs; no change needed | — | — | — |
| /usr | nodev (separate LV) | REMOVED (layout) | Omarchy has a single btrfs root with subvolumes; separate /usr is not applicable | — | — | — |
| /home | nodev,nosuid | VALID | Per-subvolume mount options work with btrfs (VFS flags). Do **not** add noexec (it breaks mise, npm, cargo and AppImages) | no | mounts | — |
| /var | nodev,nosuid,noexec | HARMFUL | `noexec` on /var breaks **/var/lib/flatpak** (system Flatpaks execute from there) and /var/lib/docker. Use nodev,nosuid at most, only on separate subvolumes | no | mounts | — |
| /tmp | nodev,nosuid,noexec (ext4 LV) | VALID (nodev,nosuid) / HARMFUL (noexec) | systemd tmp.mount (tmpfs) already uses nosuid,nodev (*unverified* exact opts). noexec breaks makepkg/yay builds and installers that exec from /tmp; opt-in only | unverified | mounts | — |
| /var/tmp/portage (tmpfs) | nodev,nosuid | REMOVED (Gentoo) | Not applicable to Arch | — | — | — |
| /proc | defaults | VALID idea | See hidepid above; per-service ProtectProc= preferred | no | agent_containment | [PROC] |

---

## 5. Login, PAM, limits, shell (`login.defs`, `limits.d`, `profile.d`)

Important: per shadow's own man page ([SHADOW]), on a **PAM-enabled** shadow build (Arch) these keys are `condition="no_pam"`, i.e. ignored by login:
- `CONSOLE`
- `ENV_PATH` and `ENV_SUPATH`
- `UMASK` (login path)
- `ULIMIT`
- `FAILLOG_ENAB`
- `LASTLOG_ENAB`
- `MAIL_*`
- `ENCRYPT_METHOD` (chpasswd)

PAM modules do that job instead.

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| FAIL_DELAY | 3 | SUPERSEDED | pam_faildelay / pam_faillock `fail_interval`; on PAM systems the delay comes from PAM | partial (faillock deny=10) | pam_faillock | [SHADOW] |
| LOGIN_RETRIES / LOGIN_TIMEOUT | 5 / 60 | SUPERSEDED | pam_faillock `deny=`. Omarchy sets **deny=10** (`etc/security/faillock.conf`) and sudo `passwd_tries=10`; tighten to deny=5 with unlock_time | yes (deny=10) | pam_faillock | [SHADOW] |
| LOG_UNKFAIL_ENAB | no | VALID | Keeps passwords mistyped into the username field out of logs; keep | no (default no, *unverified*) | pam_faillock (assert) | [SHADOW] |
| LOG_OK_LOGINS / SYSLOG_SU_ENAB / SYSLOG_SG_ENAB | yes | VALID / NO-OP | journald already records PAM sessions | — | — | [SHADOW] |
| CONSOLE /etc/securetty (+ securetty file: console, vc/1, tty1, tty2) | — | SUPERSEDED | Ignored with PAM. Modern approach: lock root (`passwd -l root`) and use pam_access, or `pam_securetty` if desired | unverified (no root-lock found in the Omarchy tree) | **new: login_policy** | [SHADOW] |
| ENV_SUPATH / ENV_PATH | fixed PATHs | SUPERSEDED | Ignored with PAM; sudo `secure_path` | — | login_policy | [SHADOW] |
| UMASK | 027 | SUPERSEDED | pam_umask (`session optional pam_umask.so`) or login.defs `HOME_MODE 0700`; 027/077 is fine on a single-user desktop | no | login_policy | [SHADOW] |
| TTYGROUP / TTYPERM | tty / 0600 | VALID / NO-OP | Defaults; blocks `write`/`wall` to your tty | — | — | — |
| PASS_MAX_DAYS / MIN / WARN | 99999 / 0 / 7 | VALID | No forced rotation is consistent with NIST SP 800-63B (*unverified* citation this session) | — | — | — |
| UID/GID ranges, USERGROUPS_ENAB, CREATE_HOME, DEFAULT_HOME | defaults | NO-OP | — | — | — | — |
| CHFN_RESTRICT | rwh | VALID | Also consider dropping setuid from chfn/chsh, which a single-user desktop does not need | no | pacman_integrity (SUID review) | — |
| ENCRYPT_METHOD | not set | SUPERSEDED | Arch PAM hashes with yescrypt (*unverified*); assert `pam_unix ... yescrypt` | unverified | login_policy | [SHADOW] |
| limits: `* soft/hard core 0` | 0 | SUPERSEDED | systemd: `coredump.conf` Storage=none / ProcessSizeMax=0 and `DefaultLimitCORE=0`. **Conflicts with Omarchy's `bin/omarchy-crash-watch`**, which reads systemd-coredump journal entries (MESSAGE_ID fc2e22bc...). Keep systemd-coredump with Storage=external (root-only), or offer the disable as opt-in | yes (relies on coredumps) | **new: coredump** | [SD] |
| limits: nproc 200 / 1000 / 2000 per group | — | HARMFUL (200) / SUPERSEDED | Browsers and IDEs need hundreds of threads. Use logind/systemd user-slice `TasksMax=` as fork-bomb protection | no | agent_containment | — |
| limits: maxlogins | 3 / 10 | REMOVED (desktop) | Not relevant on a single-user desktop | — | — | — |
| profile: `TMOUT=900` (readonly for non-root) | 900 | HARMFUL | Kills idle terminal shells in Hyprland. Screen lock covers this (Omarchy has `bin/omarchy-apply-lock`); keep TMOUT for TTY/SSH only | — | login_policy (TTY/SSH-scoped) | — |
| profile: `umask 027` | 027 | SUPERSEDED | pam_umask (single place) | no | login_policy | — |
| profile: PROMPT_COMMAND logger of every command (`local5`) + readonly HIST* | on | SUPERSEDED / HARMFUL (privacy) | Trivially bypassed, and it writes secrets typed on command lines into the journal. If needed, use auditd execve or `pam_tty_audit` | no | auditd (opt-in) | — |
| aliases: `rm/chown/chmod/chgrp --preserve-root` | aliases | VALID (minor) | GNU rm already defaults to --preserve-root; aliases are cosmetic | — | — | — |
| /etc/shells: bash, sh only | — | HARMFUL | Restricts chsh to zsh/fish; not worth it on a desktop | — | — | — |
| cron.allow: root | root | REMOVED (Arch) | Omarchy uses systemd timers; cronie not default | — | — | — |

---

## 6. SSH (`sshd_config`), Protocol/feature removals from [OSSH]

Omarchy has an opt-in `bin/omarchy-setup-security-sshd` that writes `/etc/ssh/sshd_config.d/10-omarchy-hardening.conf` (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`) and `ufw limit 22/tcp`.

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| Port | 55522 | VALID (obscurity) | Only cuts log noise; not a control | no | — | — |
| Protocol | 2 | REMOVED | SSH-1 server support removed in **OpenSSH 7.4**; keyword is a no-op | — | — | [OSSH] |
| ServerKeyBits | 2048 | REMOVED | SSH-1-only option, gone with 7.4 | — | — | [OSSH] |
| Ciphers | aes256-cbc,aes256-ctr,blowfish-cbc | REMOVED / HARMFUL | blowfish removed in **7.6** (and disabled by default since 7.2); CBC is weak. Use defaults (chacha20-poly1305, aes-gcm) and modern KEX (PQ hybrid, *unverified* names) | no | **new: sshd** | [OSSH] |
| Compression | yes | HARMFUL | **OpenSSH 10.6 (2026-10-06)** disabled the LZ77 dictionary coder over a chosen-plaintext cross-channel side-channel; pre-auth compression was removed in 7.4. Set `Compression no` | no | sshd | [OSSH] |
| ClientAliveInterval / CountMax | 15 / 3 | VALID | — | no | sshd | — |
| TCPKeepAlive | no | VALID | — | no | sshd | — |
| PermitRootLogin | no | VALID | Not in Omarchy's drop-in (verified grep); add it | no | sshd | — |
| PermitEmptyPasswords / StrictModes / PubkeyAuthentication / IgnoreRhosts / HostbasedAuthentication | safe values | NO-OP | Defaults | — | — | — |
| UsePrivilegeSeparation | yes | REMOVED | Deprecated in **7.5** (always on) | — | — | [OSSH] |
| UseLogin | no | REMOVED | Removed in **7.4** | — | — | [OSSH] |
| RhostsRSAAuthentication | no | REMOVED | SSH-1 option, removed with 7.4 | — | — | [OSSH] |
| AllowGroups | sshusers | VALID | Keep (or AllowUsers) | no | sshd | — |
| UsePAM | no | HARMFUL | Without PAM there is no pam_systemd session, no pam_faillock and no FIDO2/pam_u2f; keep `UsePAM yes` (Arch default, *unverified*) with key-only auth | no | sshd | — |
| PasswordAuthentication (absent in Securix) | — | VALID (gap) | Omarchy opt-in sets `no` | yes (opt-in) | sshd | — |
| UseDNS | no | NO-OP | Default no (*unverified*) | — | — | — |
| PrintLastLog / PrintMotd / Banner | yes / yes / /etc/issue | VALID (cosmetic) | lastlog is being replaced by lastlog2 (*unverified*) | — | — | — |
| MaxAuthTries | 5 | VALID | Use 3 | no | sshd | — |
| AllowTcpForwarding / X11Forwarding / GatewayPorts | no | VALID | Devs may need forwarding, so make it a var; add `AllowAgentForwarding no` | no | sshd | — |
| SyslogFacility AUTH / LogLevel VERBOSE | VERBOSE | VALID | VERBOSE logs key fingerprints | no | sshd | — |
| Subsystem sftp | /usr/lib/misc/sftp-server | REMOVED (path) | Use `internal-sftp` | — | — | — |
| fail2ban `[ssh-iptables]` jail | enabled | SUPERSEDED | Key-only + `ufw limit` (Omarchy) or sshd `PerSourcePenalties` (*unverified* version); fail2ban is unnecessary on a desktop | yes (ufw limit) | firewall | — |

---

## 7. Firewall (`iptables.rules`, `rules-save`)

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| iptables (legacy) via OpenRC | — | SUPERSEDED | nftables (ufw on iptables-nft) | yes (ufw) | firewall | — |
| INPUT policy DROP | DROP | VALID | `ufw default deny incoming` | **yes** (`install/config/firewall.sh:2`) | firewall | — |
| FORWARD policy DROP | DROP | VALID (with Docker care) | `ufw default deny routed` + ufw-docker (Omarchy ships `ufw-docker`) | partial | firewall | — |
| OUTPUT DROP then `-A OUTPUT -j ACCEPT` | effectively allow | VALID / NO-OP | Same as Omarchy `default allow outgoing`; real egress control belongs in **opensnitch** | yes | opensnitch | — |
| conntrack ESTABLISHED,RELATED accept; INVALID drop | — | VALID | ufw before.rules does the same (*unverified* exact rule) | yes (ufw) | firewall | — |
| ICMP chain: allow 0/3/11, echo-request 1/s, log + drop rest | — | VALID / partial | Never drop ICMPv6 ND or PMTU (Omarchy sets `tcp_mtu_probing=1`); rate-limiting echo is fine | yes (ufw defaults) | firewall | — |
| PORTSCAN chain (XMAS/NULL/SYN-RST/SYN-FIN flag drops) | — | SUPERSEDED | Mostly caught by conntrack INVALID; nft `tcp flags` rules are cheap, but they add little | no | firewall (optional) | — |
| Rate-limited LOG of drops | 10/min | VALID | `ufw logging low` | unverified | firewall | — |
| SERVICES chain allows only SSH 55522 | — | VALID | Omarchy opens LocalSend 53317 tcp/udp and Docker DNS; review LocalSend exposure (bind to trusted networks) | yes (opens 53317) | firewall | — |

---

## 8. Services, integrity monitoring, boot, build and package hygiene

| Setting | Securix value | Class | Modern equivalent / note | Omarchy? | Role | Source |
|---|---|---|---|---|---|---|
| rkhunter (+ `--propupd`, daily cron) | installed | SUPERSEDED | Signature-based and largely unmaintained (*unverified* last release). Use `pacman -Qkk` / `paccheck --sha256sum` against the package DB, plus AIDE if you need non-package files | no | pacman_integrity | — |
| unhide / unhide-tcp hourly | installed | REMOVED (low value) | Kernel-level rootkits defeat it; skip | no | — | — |
| SUID/SGID scan vs whitelist (securix-monitor) | daily | VALID | Diff against the package DB; alert on unknown SUID; candidate for setuid removal (chfn, chsh, ...) | no | pacman_integrity | — |
| World-writable file scan (excluding sticky dirs) | daily | VALID | Same role | no | pacman_integrity | — |
| No-owner / no-group file scan | daily | VALID | Same role | no | pacman_integrity | — |
| Entropy check (entropy_avail < 112 → alert, rng-tools) | hourly | REMOVED | Modern RNG no longer blocks after init (*unverified* exact version); entropy_avail is reported but not actionable | no | — | [K] |
| Disk / inode usage alerts | hourly | VALID (ops) | Not hardening; btrfs + snapper already monitored by Omarchy (*unverified*) | — | — | — |
| syslog-ng with separate auth/firewall/grsec/pax/audit logs + logrotate | — | SUPERSEDED | journald (persistent, `SystemMaxUse=`); grsec.log and pax.log are REMOVED | — | — | — |
| Email alerting (ssmtp/mailx) | — | REMOVED | ssmtp is unmaintained; desktop notifications or ntfy (out of scope) | — | — | — |
| openntpd (`-s`) | — | SUPERSEDED | systemd-timesyncd or chrony with **NTS** (authenticated time) | no | **new: time_sync (NTS)** | — |
| smartd | on | VALID (ops) | Not hardening | — | — | — |
| inittab: disable Ctrl-Alt-Del | disabled | VALID | `systemctl mask ctrl-alt-del.target` + `CtrlAltDelBurstAction=none`; matters on VTs | no | login_policy | — |
| GRUB `password --md5` (default hash for `securix_boot`) | MD5, shared default | REMOVED / insecure | Limine: disable the cmdline editor (key name *unverified*) plus **Secure Boot with signed UKIs** (Omarchy has `ENABLE_UKI=yes`); sbctl | partial (UKI yes) | **new: secure_boot** | — |
| Boot cmdline `vga=791 quiet` | — | REMOVED | — | — | — | — |
| Kernel cmdline hardening (absent in Securix; grsec did it in-kernel) | — | VALID (new) | `init_on_free=1 slab_nomerge randomize_kstack_offset=on page_alloc.shuffle=1 vsyscall=none lockdown=integrity lsm=... debugfs=off (opt) iommu.strict=1 (opt) efi=disable_early_pci_dma (opt)`, all present in [KP]. Omarchy appends only quiet/splash flags (`etc/limine-entry-tool.d/omarchy-defaults.conf`); add via `KERNEL_CMDLINE[default]+=` in a separate drop-in | no | kernel | [KP] |
| Gentoo `hardened` profile (SSP, PIE, FORTIFY, RELRO/BIND_NOW toolchain) | on | SUPERSEDED | Arch `makepkg.conf` already ships hardening flags (FORTIFY, stack-clash, CET, relro/now; exact list *unverified*). Audit with `checksec` | — | pacman_integrity (audit) | — |
| CFLAGS `-march=native -O2 -fforce-addr -pipe` | — | REMOVED | `-fforce-addr` is a no-op in modern GCC (*unverified*); N/A for binary Arch | — | — | — |
| USE flags `-X -jit -suid pax_kernel ...` | — | REMOVED / HARMFUL | `-jit` and `-X` are server-only; not applicable to Arch | — | — | — |
| Portage FEATURES `sandbox sfperms strict userfetch` | — | SUPERSEDED | pacman 7 `DownloadUser` / Landlock download sandbox (*unverified* key names); build AUR packages in a clean chroot | no | pacman_integrity | — |
| Portage GPG-verified `emerge-webrsync` (`SYNC=""`) | on | VALID (concept) | pacman `SigLevel = Required DatabaseOptional`, keyring checks, no `TrustAll` | no | pacman_integrity | — |
| Groups admin/operator/service/sshusers/motd; user in wheel | — | VALID (concept) | wheel for sudo; sshusers for AllowGroups | — | sshd | — |
| sudo installed, **no sudoers policy** | — | VALID (gap) | Add `Defaults use_pty, logfile, timestamp_timeout=5`, or consider run0. Omarchy adds `passwd_tries=10` and time-boxed NOPASSWD grants cleared at boot (`etc/tmpfiles.d/omarchy-nopasswd-sudo.conf`); keep those, but review | partial | **new: sudo_policy** | — |
| checksec.sh shipped | — | VALID | `checksec` for binary hardening audits | no | pacman_integrity (audit) | — |
| paxtest | — | REMOVED | — | — | — | — |
| Update phone-home with `SECURIXID` | — | REMOVED | Privacy anti-pattern; do not replicate | — | — | — |
| Proxy env in profile.d | — | REMOVED | N/A | — | — | — |
| Tight perms on own config (`chmod -R 0600 /etc/securix`) | — | VALID (concept) | Roles should install their own files 0644/0600 root:root and assert them | — | all roles | — |
| `vm.swappiness` / I/O scheduler tuning (performance) | CFQ, no swappiness | SUPERSEDED | Omarchy already tunes for zram: `vm.swappiness=150`, vfs_cache_pressure, page-cluster=0, dirty_bytes, BBR+fq, kyber. **Do not override** | **yes** (`etc/sysctl.d/99-omarchy-sysctl.conf`) | — | — |

---

## Top ideas worth adopting, ranked

1. **Kernel cmdline KSPP set** (replaces PaX SANITIZE, RANDKSTACK and USERCOPY_SLABS): `init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none`, as a separate limine-entry-tool drop-in so it does not collide with Omarchy's own file. **kernel**
2. **Lockdown LSM** with `lockdown=integrity`, replacing GRKERNSEC_IO/KMEM/MODHARDEN in spirit. Keep it off `confidentiality` because of hibernation and tooling. **kernel**
3. **`lsm=` including apparmor**, replacing gradm RBAC and partly TPE. **apparmor** (with kernel)
4. **Info-leak sysctls**: `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid>=2`, `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, replacing GRKERNSEC_HIDESYM/DMESG. **sysctl**
5. **`kernel.yama.ptrace_scope=1`**, replacing GRKERNSEC_HARDEN_PTRACE. **sysctl**
6. **`fs.protected_fifos=2`, `fs.protected_regular=2`** (systemd sets 1), replacing GRKERNSEC_LINK/FIFO. **sysctl**
7. **Network sysctls** that are still valid: send_redirects=0, accept_redirects=0 (**plus IPv6**), secure_redirects=0, accept_source_route=0 (plus IPv6), syncookies=1, `rp_filter=2` (not 1, for overlay_network), tcp_rfc1337=1. **sysctl**
8. **Process-hardening sysctls**: `kernel.kexec_load_disabled=1`, `vm.unprivileged_userfaultfd=0`, `fs.suid_dumpable=0`, and assert `vm.mmap_min_addr>=65536` (Securix's 4096 is a regression trap). **sysctl**
9. **Integrity sweeps** from securix-monitor (SUID/SGID, world-writable, no-owner) diffed against `pacman -Qkk`/`paccheck`, plus a SUID-reduction list (chfn, chsh, ...). **pacman_integrity**
10. **Mount hardening** that does not break Flatpak or Docker: ESP `nodev,nosuid,noexec,fmask/dmask=0077`; `/home` nodev,nosuid; `/tmp` nodev,nosuid; **never noexec on /var or /home**. Proposed new role: **mounts**
11. **sshd drop-in**:
    - Compression no (OpenSSH 10.6 side-channel), PermitRootLogin no, MaxAuthTries 3, AllowGroups, LogLevel VERBOSE
    - no agent, TCP or X11 forwarding by default
    - keep UsePAM yes
    - drop Protocol, ServerKeyBits, UseLogin and UsePrivilegeSeparation

    It extends Omarchy's opt-in sshd hardening. Proposed new role: **sshd** (or fold into firewall)
12. **Core-dump policy**: systemd-coredump with restricted storage plus `fs.suid_dumpable=0`. Do **not** copy `core 0` blindly, because it breaks `omarchy-crash-watch`. Proposed new role: **coredump** (or sysctl)
13. **faillock tightening**: deny=5 with unlock_time, replacing login.defs LOGIN_RETRIES/FAIL_DELAY (ignored under PAM). Omarchy uses deny=10. **pam_faillock**
14. **Login policy**: pam_umask 027/077 + HOME_MODE 0700, root account locked, Ctrl-Alt-Del target masked, TMOUT only for TTY/SSH sessions. Proposed new role: **login_policy**
15. **USB and DMA-bus control**: USBGuard (or linux-hardened `deny_new_usb`) plus a firewire modprobe blacklist. **Do not** blacklist thunderbolt (Omarchy loads it deliberately). Proposed new role: **usbguard**, with the blacklist in kernel
16. *(Honourable mentions)*:
    - Secure Boot with signed UKIs, replacing Securix's MD5 GRUB password (**secure_boot**, new)
    - auditd as opt-in for exec/mount/time-change auditing, replacing GRKERNSEC_*LOG (**auditd**, new)
    - per-service `ProtectProc=invisible`, `MemoryDenyWriteExecute=`, `TasksMax=` for agent sandboxes, replacing hidepid, PaX MPROTECT and nproc limits (**agent_containment**)
    - Chrony with NTS (**time_sync**, new)

### Explicitly do **not** adopt (harmful on an Omarchy desktop)

- `ip_forward=0`: breaks Docker.
- `fs.file-max=65000`: below Omarchy's nofile hard limit.
- `kernel.pid_max=65536`
- `kernel.shmmax=256M`
- `vm.mmap_min_addr=4096`: weakens the Arch default of 65536.
- `tcp_sack=0` and `tcp_timestamps=0`
- `ip_local_port_range=1024 64000`
- `panic_on_oops` / `panic=30`: opt-in only.
- strict `rp_filter=1`: breaks overlay networks.
- IPv6 disable / RA kill.
- `noexec` on /var or /home: breaks Flatpak, Docker and dev toolchains.
- global hidepid
- `module.sig_enforce` / `modules_disabled`: breaks NVIDIA DKMS and hotplug.
- `ia32_emulation=0`: breaks Steam and Wine.
- disabling namespaces or `unprivileged_userns_clone=0`: breaks Flatpak/bubblewrap and browser sandboxes.
- `TMOUT` in graphical terminals
- `UsePAM no`
- nproc=200
- performance governor
- overriding Omarchy's zram/kyber/BBR tuning

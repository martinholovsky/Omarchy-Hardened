# Kicksecure security-misc review for Omarchy-Hardened (Aegis)


**Note added on import:** this review was written before decision D-13 changed
the faillock count from the PRD's `deny=3` to `deny=10` (Omarchy's count).
Where it says "deny=3", read "deny=10". Its findings about the tally directory
and `su` apply either way.

- **Source:** https://github.com/Kicksecure/security-misc, shallow clone at
  `9535bf8e9c37bb65d1b4cabb39b7f6bc5ee9f29f` (commit date 2026-09-30).
  Nothing from it was executed.
- **Denominator:** 213 tracked files (`git ls-files | wc -l`). Of those,
  about 150 are config or helper files under `etc/`, `usr/`, `debian/` and
  `rpm_spec/`; the rest are CI, docs, man pages and fuzzing scaffolding.
  Every config file under `etc/` and `usr/lib/`, plus the PAM and helper
  scripts named below, was read. The C sources (`emerg-shutdown.c`,
  `fm-shim-backend.c`) and the Python fm-shim frontend were inventoried but
  not audited.
- **File naming:** files are stored as `path#security-misc-shared` (or
  `-desktop`/`-server`), and `debian/*.install` maps them to their real path.
  The paths below leave the suffix off.
- **Compared against:** `docs/roadmap.md`, the secureblue and Securix
  reviews, the existing role defaults (`roles/sysctl` already sets
  `dmesg_restrict=1`, `kptr_restrict=2`, `kexec_load_disabled=1` and
  `ptrace_scope=1`; `roles/kernel` is a stub), and Omarchy at `dde0d12`
  (5188 files).
- **Primary sources fetched for this review:** `kernel-parameters.txt`,
  `sysctl/{kernel,abi,vm,fs}.rst`, `ip-sysctl.rst` and
  `nf_conntrack-sysctl.rst` from torvalds/linux master. Kernel source:
  `drivers/tty/{Kconfig,tty_io.c}`, `arch/x86/entry/vdso/vdso32-setup.c`,
  `drivers/firmware/efi/efi-pstore.c` and `net/netfilter/nf_conntrack_*.c`.
  The Arch `linux` 7.2.11.arch1 `config.x86_64`. systemd `coredump.conf.xml`
  and `pstore.conf.xml`. BlueZ `src/main.conf` and `src/main.c`. Arch
  util-linux `su.pam`. Limine `CONFIG.md`.
- **Kernel caveat (same as the earlier reviews):** every "Arch has X" below
  is about Arch `linux`, not `linux-omarchy`. The `linux-omarchy` config
  is still unverified.

Classification key:

- **NEW**: not in `roadmap.md`. "NEW (review-only)" means one of the earlier
  research files mentions it, but it never made it into the roadmap.
- **IN-ROADMAP**: already in the roadmap, or already implemented in a role.
- **CONFLICTS**: Kicksecure's default contradicts the roadmap or its
  do-not-adopt list.

## 1. Inventory

### 1a. sysctl (`usr/lib/sysctl.d/990-security-misc.conf`, `30_security-misc_kexec-disable.conf`, `30_security-misc_ptrace-disable.conf`, `30_silent-kernel-printk.conf`)

| Key = KS value | What it does | Class | Omarchy risk | Arch/Ansible | Role |
|---|---|---|---|---|---|
| `kptr_restrict=2`, `dmesg_restrict=1`, `kexec_load_disabled=1` | Kernel info-leak controls, plus no kexec | IN-ROADMAP (implemented) | none | yes | sysctl |
| `kernel.printk=3 3 3 3` (in its own file, paired with `quiet loglevel=0`) | Keeps kernel messages off the console | NEW (review-only, secureblue) | none (Omarchy already boots `quiet loglevel=0`) | yes | sysctl |
| `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `ldisc_autoload=0`, `unprivileged_userfaultfd=0`, `sysrq=0` | Attack-surface sysctls | IN-ROADMAP #1 | low | yes. Arch already has `BPF_UNPRIV_DEFAULT_OFF=y` and `MAGIC_SYSRQ_DEFAULT_ENABLE=0x0` (verified); systemd raises sysrq to 16 | sysctl |
| `perf_event_paranoid=3` | Blocks perf for users without CAP_PERFMON | CONFLICTS (value) | low | see §2 | sysctl |
| **`dev.tty.legacy_tiocsti=0`** | Blocks TIOCSTI keystroke injection into a controlling TTY. Verified: `tty_io.c` registers `legacy_tiocsti`, and Kconfig documents it as a privilege-escalation vector | **NEW** | none (Arch already builds `# CONFIG_LEGACY_TIOCSTI is not set`, so this is an **assert-only** item: write it, then fail if `/proc` says 1) | yes | sysctl |
| **`abi.vsyscall32=0`** (and the `vdso32=0` boot parameter) | No vDSO for 32-bit processes. Verified: `abi.rst` documents it and `vdso32-setup.c` registers the sysctl. `abi.rst` says the default is "enabled if COMPAT_VDSO", but the source says `VDSO_DEFAULT 0` **with** `CONFIG_COMPAT_VDSO` and 1 without. Arch has COMPAT_VDSO unset, so it is **enabled** today | NEW (secureblue had only `vdso32=0`) | low: 32-bit Steam/Wine code falls back to real syscalls, which costs a little time (impact unmeasured) | yes. The key exists only with `IA32_EMULATION` (Arch y) | sysctl |
| `kernel.panic=-1` | Reboot immediately on panic | IN-ROADMAP (optional, secureblue review) | low–med (the panic text is lost) | yes | sysctl (opt-in) |
| `oops_limit=1`/`warn_limit=1`, set **late** by `panic-on-oops.service` (`After=graphical.target`, opt out with `panic-on-oops=0` on the cmdline). The unit is **enabled** by default; the preset does not disable it | Panic on the first oops or WARN after boot | CONFLICTS (value; roadmap #5 says 100) | **high** with limit 1 (NVIDIA/Wi-Fi WARNs reboot the desktop) | yes | sysctl (pattern) |
| `ptrace_scope=3` (**default**, in its own file) | No ptrace at all, irreversible until reboot | CONFLICTS (roadmap: 1 implemented, 2 opt-in) | **high** (gdb, strace, Proton anticheat) | yes | sysctl |
| `io_uring_disabled=2` | io_uring off for everyone | CONFLICTS (roadmap: opt-in, prefers `1` plus `io_uring_group`) | med | yes (verified `kernel.rst`) | sysctl |
| `fs.protected_*` (hardlinks/symlinks 1, fifos/regular 2), `suid_dumpable=0`, `randomize_va_space=2`, `mmap_min_addr=65536`, `max_map_count=1048576` | FS and ASLR basics | IN-ROADMAP #2/#3 | low | yes | sysctl |
| `mmap_rnd_bits`/`compat_bits` through `usr/libexec/security-misc/mmap-rnd-bits`, which reads `CONFIG_ARCH_MMAP_RND_*_MAX` from `/boot/config-*` and writes a sysctl file | Max ASLR entropy without hard-coding it | IN-ROADMAP #3 (the derive-from-config method is a useful pattern). On Arch read `/proc/config.gz`, because there is no `/boot/config-*`. Arch: 28→32 and 8→16 (verified) | low | yes | sysctl |
| `kernel.core_pattern=\|/bin/false` + `limits.d` `* - core 0` | Disable core dumps | CONFLICTS (do-not-adopt) | **high** (`omarchy-crash-watch`) | — | — |
| `kernel.core_uses_pid=1` | `core.PID` naming | NEW, **no-op** under systemd-coredump: `kernel.rst` says it only applies when the pattern lacks `%p`, and a pipe pattern is unaffected | none | yes | skip |
| `vm.swappiness=1` | Avoid swapping secrets | CONFLICTS (do-not-adopt: Omarchy sets 150 for zram, and zram is RAM, not disk) | med (zram stops being used) | — | — |
| `rp_filter=1`, `arp_filter=1`, `arp_ignore=2`, `drop_gratuitous_arp=1` | Strict anti-spoofing | CONFLICTS (do-not-adopt / roadmap uses rp_filter 2) | med | — | — |
| `accept_redirects=0`, `send_redirects=0`, `accept_source_route=0` (v4+v6), `tcp_syncookies=1`, `tcp_rfc1337=1` | Network basics | IN-ROADMAP #4 | none | yes | sysctl |
| `secure_redirects` (KS leaves it commented) | — | roadmap sets 0. KS skips it because `accept_redirects=0` already covers it | none | yes | sysctl |
| `shared_media=0`, `log_martians=1`, `icmp_ignore_bogus_error_responses=1` | Minor network hygiene | NEW (review-only, secureblue said "adopt") | none (`log_martians` adds journal noise) | yes | sysctl |
| `icmp_echo_ignore_all=1` (v4 **and** v6, default) | Host does not answer ping | NEW (review-only, optional) | low (LAN diagnostics; ufw already drops unsolicited inbound) | yes | sysctl (opt-in) |
| **`net.ipv6.conf.*.accept_ra=0`** | Ignore IPv6 Router Advertisements (rogue-RA defence). Verified in `ip-sysctl.rst` | **NEW** | **med–high** on a host that does SLAAC in the kernel (no IPv6 default route). Under NetworkManager the effect is likely **nil**: NM handles RAs in userspace and manages `accept_ra` itself (**unverified**), so this would be a control that reads green and does nothing | yes | do not adopt as a sysctl; see do-not-adopt |
| `tcp_timestamps=0` | Fingerprinting | CONFLICTS (do-not-adopt) | low–med | — | — |
| `tcp_tw_reuse=0` | No TIME_WAIT reuse (KS sets it because timestamps are off) | NEW | low. The mainline default is **2** (loopback only, verified). Pointless unless timestamps are 0 | yes | skip |
| `use_tempaddr=2` (KS ships it **commented**, disabled for breakage) | IPv6 privacy addresses | IN-ROADMAP #4 (see §2) | low on NM | yes | network_privacy |
| `dev.cdrom.autoclose=0`, `autoeject=0`, `debug=0` | Stops scripted tray cycling | NEW | none | yes (key exists only once `cdrom` loads; KS also blacklists cdrom) | skip, trivial |
| `fs.binfmt_misc.status=0`, `user.max_user_namespaces=0`, `unprivileged_userns_clone=0`, `vm.panic_on_oom`, `panic_on_*nmi`, `tcp_sack=0` | All **commented out** in KS | — (KS agrees with our do-not-adopt list) | — | — | — |

### 1b. Kernel command line (`etc/default/grub.d/40_kernel_hardening.cfg`, `40_cpu_mitigations.cfg`, `40_signed_modules.cfg`, `41_quiet_boot.cfg`, `41_recovery_restrict.cfg`, `40_remount_secure.cfg`)

On Omarchy every boot parameter goes in an `/etc/limine-entry-tool.d/` drop-in followed by a UKI rebuild, as roadmap #11 says.

| Parameter (KS default unless noted) | Exists? (`kernel-parameters.txt`) | Class | Omarchy risk | Role |
|---|---|---|---|---|
| `slab_nomerge`, `init_on_alloc=1`, `init_on_free=1`, `page_alloc.shuffle=1`, `randomize_kstack_offset=on`, `vsyscall=none`, `random.trust_cpu=off`, `random.trust_bootloader=off` | yes | IN-ROADMAP #11. Arch already defaults `INIT_ON_ALLOC_DEFAULT_ON=y`, `RANDOMIZE_KSTACK_OFFSET_DEFAULT=y` and `SHUFFLE_PAGE_ALLOCATOR=y`, so several of these are assert-only. `SLAB_MERGE_DEFAULT=y` means `slab_nomerge` is a real change (verified) | low | kernel |
| `iommu=force intel_iommu=on iommu.passthrough=0 iommu.strict=1 amd_iommu=force_isolation efi=disable_early_pci_dma` | yes | IN-ROADMAP #13 | low–med (TB docks) | kernel |
| `mitigations=auto,nosmt`, `nosmt=force` (**default in KS**), plus `spectre_v2=on spectre_bhi=on pti=on kpti=1 ssbd=force-on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full,nosmt retbleed=auto,nosmt kvm.mitigate_smt_rsb=1 gather_data_sampling=force reg_file_data_sampling=on indirect_target_selection=force vmscape=force` | all present. `kpti=` is documented as **[ARM64]** only, so it is a no-op on x86 | CONFLICTS (roadmap #25 makes `nosmt` opt-in). The non-SMT parts (`spectre_bhi`, `tsx=off`, `indirect_target_selection`, `vmscape`, `reg_file_data_sampling`) are NEW relative to secureblue's list | **high** for `nosmt` (halves threads on affected CPUs); low–med for the rest | kernel (opt-in group) |
| `slab_debug=FZ` (**default in KS**) | yes | NEW (review-only, secureblue said opt-in). **KS's own comment:** it turns *off* `%p` pointer hashing unless `hash_pointers=always` is also set (6.17+, verified: "auto - Hash pointers unless slab_debug is enabled"). | med (allocation overhead) | kernel (opt-in; **must** pair with `hash_pointers=always`) |
| `kfence.sample_interval=100` | yes | NEW, **no-op on Arch** (`CONFIG_KFENCE=y`, `CONFIG_KFENCE_SAMPLE_INTERVAL=100`, verified). Assert only | none | kernel (assert) |
| `cfi=kcfi` | yes (`[X86-64]`, "when CONFIG_FINEIBT is enabled") | NEW, **no-op on Arch**: `CONFIG_CC_IS_GCC=y` and no `CONFIG_CFI*` options (verified; kCFI needs clang) | none | skip |
| `vdso32=0` | yes | NEW (review-only) | low | kernel |
| `ia32_emulation=0` (**default in KS**) | yes | CONFLICTS (do-not-adopt with Steam) | high | — |
| **`efi_pstore.pstore_disable=1` + `erst_disable`** | `erst_disable` is in the docs. `efi_pstore.pstore_disable` is not in `kernel-parameters.txt`; it is a module param in `efi-pstore.c` (verified). On Arch `EFI_VARS_PSTORE_DEFAULT_DISABLE=y`, so the EFI half is already a **no-op**. `ACPI_APEI=y`, so `erst_disable` is a real change | **NEW** | low (you lose the panic log that survives a reboot) | kernel |
| **`proc_mem.force_override=ptrace`** | yes | NEW (review-only; secureblue had it with an unverified version gate). Arch is `CONFIG_PROC_MEM_ALWAYS_FORCE=y` (verified), so this **is** a real change. KSPP wants `never` | low–med: writing through `/proc/self/mem` to read-only mappings stops working outside ptrace. Some JIT, instrumentation and anticheat tools may break (**unverified**) | kernel |
| `debugfs=off` | yes | NEW (review-only, optional). Arch `DEBUG_FS_ALLOW_ALL=y` | low–med (powertop, some GPU tools) | kernel (opt-in) |
| `extra_latent_entropy` | **not in mainline** docs (linux-hardened patch, as KS itself says) | NEW, no-op on `linux-omarchy` | none | skip unless on linux-hardened |
| `module.sig_enforce=1`, `lockdown=confidentiality` | yes | both **commented** in KS (agrees with roadmap #19/#20) | — | — |
| `rd.shell=0 rd.emergency=halt`, `GRUB_DISABLE_RECOVERY=true` | dracut/systemd-initrd only | n/a (busybox mkinitcpio; secureblue review already noted this). **Limine analog is NEW:** `editor_enabled: no` (verified in Limine `CONFIG.md`), and `hash_mismatch_panic: yes`. Omarchy's `default/limine/limine.conf` sets `hash_mismatch_panic: no` and does not set `editor_enabled` | low (no ad-hoc cmdline edits at boot; recovery needs a live USB) | secure_boot / kernel |
| `ipv6.disable=1`, `bdev_allow_write_mounted=0`, `oops=panic`, `panic_on_warn`, `panic_on_taint`, SME/SEV | commented in KS | — | — | — |

### 1c. Modules (`etc/modprobe.d/30_security-misc_{disable,blacklist,conntrack}.conf`, `usr/lib/modules-load.d/30_security-misc.conf`, `usr/bin/disabled-*-by-security-misc`)

The method is `install <mod> /usr/bin/disabled-<class>-by-security-misc`, a stub that prints a reason. That gives the same hard block as `/bin/false`, plus a message that tells the user why. The message stub is the NEW part and a better UX than `/bin/false`.

| Group | Class | Omarchy risk | Role |
|---|---|---|---|
| Obscure network protocols (dccp, sctp, rds, tipc, ax25/netrom/rose/x25, decnet, econet, ipx, appletalk, atm, all CAN, n-hdlc, p8022/p8023/psnap, af_802154) | IN-ROADMAP #10 | none/low | module_blocklist |
| firewire*, ohci1394/sbp2/raw1394; floppy; hamradio; legacy framebuffers (vesafb, udlfb, …) | IN-ROADMAP #10 | low | module_blocklist |
| Rare filesystems (incl. **hfsplus, udf**, ceph, ecryptfs, jfs…) | CONFLICTS (roadmap excludes hfsplus/udf) | low–med | module_blocklist (keep the exclusions) |
| Network FS: **cifs, nfs\*, nfsd, ksmbd**, gfs2 (9p commented) | CONFLICTS (roadmap excludes the cifs/nfs clients) | med | module_blocklist: block only the `ksmbd` and `nfsd` servers |
| **thunderbolt, thunderbolt_net, intel-wmi-thunderbolt** (default!) | CONFLICTS (do-not-adopt) | **high** | — |
| **GNSS / garmin_gps** (gnss, gnss-*) | NEW (secureblue listed GNSS under legacy hardware; the roadmap does not) | low (USB GPS dongles) | module_blocklist |
| **Intel PMT** (`pmt_class`, `pmt_crashlog`, `pmt_telemetry`) | NEW | low (Intel telemetry/crashlog readers) | module_blocklist |
| **`joydev`** | NEW | **med** for gaming: legacy `/dev/input/js*` joystick API. Steam and SDL mostly use evdev/hidraw, but some games and emulators use js (**unverified per title**). Omarchy has `omarchy-install-gaming-*` | module_blocklist (opt-in) |
| **`rndis_host`, `usb_f_rndis`** | NEW | **med**: breaks USB tethering from many Android phones (RNDIS) | module_blocklist (opt-in) |
| `bcm43xx`, `brcm80211`, `prism54`, `de4x5`, `eepro100`, `asus_acpi` | NEW | none on Arch: `brcm80211` and `bcm43xx` are not real module names here, so they are no-ops. The real Broadcom modules (`brcmfmac`, `brcmsmac`, `wl`) are untouched, so Omarchy's `broadcom-wl-dkms` is unaffected (inference from names) | skip |
| `blacklist` (soft): `cdrom`, `sr_mod`, `pcspkr`, `snd_pcsp`, `evbug`, `usbkbd`, `usbmouse`, `amd76x_edac`, `ath_pci`, `snd_aw2`, `snd_intel8x0m` | NEW (pcspkr/evbug/usbkbd/usbmouse are new; cdrom is on the roadmap as optional) | none (`usbkbd`/`usbmouse` are boot-protocol stubs; usbhid handles real keyboards) | module_blocklist |
| Opt-in (commented): bluetooth stack, CPU MSR, Intel ME (`mei*`), uvcvideo, vivid | — (KS agrees: Bluetooth stays on) | — | — |
| `options nf_conntrack nf_conntrack_helper=0` | NEW but **no-op**: master has no such module param (checked `nf_conntrack_{core,standalone,helper,proto}.c` and `nf_conntrack-sysctl.rst`). Automatic helper assignment was removed upstream; the exact version is **unverified**. modprobe would log "unknown parameter" | none | skip; assert no helper auto-assign instead |
| `modules-load.d`: `jitterentropy_rng` | NEW but **no-op on Arch**: `CONFIG_CRYPTO_JITTERENTROPY=y` is built in (verified) | none | skip |
| `harden-module-loading.service` → `sysctl kernel.modules_disabled=1` after `systemd-modules-load` (preset **disabled**) | NEW (Securix review mentioned `modules_disabled` only as "harmful") | **high** (hotplug: USB-C docks, Wi-Fi after resume, NVIDIA late load, xpadneo, `modprobe uinput` in `omarchy-dev-install-ydoo`) | do-not-adopt |

### 1d. PAM, login, su, sudo

| Measure (KS path) | What it does | Class | Omarchy risk | Arch/Ansible | Role |
|---|---|---|---|---|---|
| **`etc/security/faillock.conf.security-misc`: `dir = /var/lib/security-misc/faillock`** | **Persistent** tally directory. pam_faillock's default `dir` is `/var/run/faillock` (verified in linux-pam's `faillock.conf`), which is tmpfs, so a **reboot resets the counter** and gives an attacker with physical access unlimited 3-try rounds | **NEW** | low (needs `tmpfiles.d` for the dir; root must `faillock --reset` after reboot too) | yes (`ansible.builtin.lineinfile`, plus `dir=` inline on Omarchy's lines, since inline args win) | pam_faillock |
| same file: `deny=50`, `fail_interval=604800`, `unlock_time=never`, `even_deny_root`, `audit` | Lockout policy | CONFLICTS (value; PRD deny=3/900 s) / IN-ROADMAP #6 (audit, even_deny_root) | see §2 | yes | pam_faillock |
| `usr/share/pam-configs/unix-faillock-security-misc` + `libexec/pam_faillock_not_if_x` | Skip faillock for `sshd`/`dovecot`, so a remote attacker cannot lock the local user out | NEW | low (Omarchy sshd is opt-in; sshd should be key-only anyway) | yes (needs a `pam_exec` helper or a separate sshd PAM stack) | pam_faillock / sshd |
| `faillock-preauth` + `libexec/pam-info` | Shows failed and remaining attempts and the unlock procedure on login | NEW | none (UX only) | yes (pam_exec script) | pam_faillock (optional) |
| `pam-abort-on-locked-password` | Aborts the PAM stack early for a locked (`passwd -S` = L) account, so the attempt is not counted and the root-locked message is clear | NEW | none | yes | login_policy |
| **`wheel-security-misc`: `pam_wheel.so group=sudo` for `su` only** | Restricts `su` to the admin group | **NEW** | low (Omarchy's user is in wheel; it uses `sudo`/`pkexec`, not `su`). **Arch-specific gap found:** Arch's `/etc/pam.d/su` (util-linux `su.pam`, verified) uses `pam_unix.so` **directly** and does not include `system-auth`, so Omarchy's and Aegis's faillock **does not cover `su`**. The pam_wheel line is already there, commented | yes: uncomment `auth required pam_wheel.so use_uid` in `/etc/pam.d/su` and `su-l`, and consider adding faillock there too | login_policy |
| `umask-security-misc`: `pam_umask umask=027` for uid≠0, 022 for root; `mkhomedir umask=027`; `sudoers.d/security-misc`: `Defaults umask_override, umask=0022` | 027 user umask, but files created through sudo stay world-readable | IN-ROADMAP #26 (pam_umask). **The sudo `umask_override=0022` companion is NEW** and needed: without it a user umask of 027 leaks into `sudo tee /etc/...` (Omarchy does this a lot: `as_root tee /etc/pam.d/...`) and leaves files root-only-readable that should be world-readable | med (Docker bind mounts, group sharing); low with the sudo override | yes | login_policy |
| `permission-lockdown` (`chmod o-rwx /home/*` once per user, with a state file) | Home directory privacy | IN-ROADMAP #26 (HOME_MODE 0700) | low | yes | login_policy |
| `console-lockdown-security-misc` + `etc/security/access-security-misc.conf` (pam_access: only groups `console`/`sudo` on ttys, **default off**) | Restricts who may log in on a console | NEW | med (lockout if the groups are wrong) | yes | login_policy (opt-in) |
| `etc/securetty.security-misc` (empty file) | No root login on any console | NEW. Securix review called securetty superseded; note that on Arch it **only works if `pam_securetty` is in `/etc/pam.d/login`** (**unverified** for current Arch `login.pam`). Locking root (roadmap #26) supersedes it | low | partial | login_policy (skip; lock root instead) |
| `block-unsafe-logins` | Kicksecure user/sysmaint split | n/a (needs `user-sysmaint-split`) | — | no | — |
| `etc/systemd/system/{emergency,rescue}.service.d/override.conf`: `SYSTEMD_SULOGIN_FORCE=1` | **Passwordless** rescue shell, so a locked root can still be rescued | NEW, and it is a **trade-off**: it pairs with "lock root". It is only safe if the Limine editor is disabled (`editor_enabled: no`), because otherwise `systemd.unit=rescue.target` gives a root shell after LUKS unlock | med (physical access) | yes | login_policy + secure_boot, together |
| `sudoers.d/security-misc-desktop`: `Defaults !fqdn` | No DNS lookup of the hostname | NEW, probably a **no-op**: sudoers(5) documents `fqdn` as off by default (**unverified this session**) | none | yes | skip |
| `limits.d`: `* - core 0` | No core files | CONFLICTS (do-not-adopt) | high | — | — |

### 1e. Permissions, SUID, mounts, /proc, /sys

| Measure (path) | What it does | Class | Omarchy risk | Arch/Ansible | Role |
|---|---|---|---|---|---|
| `usr/bin/permission-hardener` + `usr/lib/permission-hardener.d/30_default.conf` (`nosuid` over `/usr/bin`, `/usr/lib`, `/opt`, …) + `25_default_whitelist_*.conf` (keeps sudo, bwrap, unix_chkpwd, pkexec, polkit-agent-helper, fusermount, dbus-launch-helper, ssh-agent; **drops** SUID from `passwd`, `mount`, `umount` with an explicit `0755`) | Global SUID/SGID strip with an allowlist. It persists on Debian through `dpkg-statoverride` and runs at install time (the boot unit is preset-disabled) | CONFLICTS (do-not-adopt "global setuid stripping") | **high**: pacman resets modes on every upgrade (there is no statoverride analog). Stripping `/opt` breaks Electron apps whose `chrome-sandbox` is setuid: they abort when the helper is present but not setuid (**unverified per app**). `passwd` without SUID stops users changing their own password | partial: needs a pacman `PostTransaction` hook | pacman_integrity (inventory only, as roadmap #8 says) |
| same, the **narrow** version: strip `chfn`, `chsh`, `newgrp`, `gpasswd`, `expiry`, `chage` plus a pacman hook that re-applies it | Small, reversible SUID reduction | NEW (Securix review suggested chfn/chsh; the roadmap only inventories) | low (none of these are used by Omarchy, from a grep of `bin/`; not exhaustive) | yes (`/etc/pacman.d/hooks/aegis-suid.hook`) | pacman_integrity |
| `30_default.conf` modes: `/boot 0700`, `/root 0700`, `/usr/lib/modules 0700`, `/usr/src 0700`, `/etc/sudoers.d 0700`, `/etc/ssh/sshd_config 0600`, `/etc/cron* 0700` | Hides kernel images, module trees and sudo rules from users | NEW (ESP `fmask/dmask=0077` is on the roadmap, #17) | `/usr/lib/modules 0700`: **med**. Unprivileged `modinfo`, `lsmod -v`, DKMS status and some Flatpak and NVIDIA user tools read it (**unverified**). `/etc/sudoers.d 0700`: low | yes, but pacman resets `/usr/lib/modules` | pacman_integrity (sudoers.d/sshd_config only) |
| `usr/lib/systemd/system/remount-secure.service` + `usr/bin/remount-secure` (preset **disabled**, "in development"): `nosuid,nodev` on `/home /root /tmp /var/tmp /srv /media /dev/shm /run`, `nosuid,nodev,noexec` on `/boot /boot/efi /var/log /sys`, `nodev` on `/usr`, optional `noexec` levels | Bind-remounts at boot | IN-ROADMAP #17 (mounts). The NEW pieces are `/var/log` noexec, `/dev/shm` nosuid,nodev, and `/usr` nodev | low for the nosuid/nodev set; **high** for its `noexec` levels 2/3 on `/home` (do-not-adopt) | yes (fstab/`x-systemd` options are better than a boot script) | mounts |
| `proc-hidepid.service` (preset **disabled**): `hidepid=2,gid=proc` | Users cannot see each other's processes | IN-ROADMAP (do-not-adopt global hidepid, Securix). KS itself makes it opt-in and notes it is incompatible with `pkexec`. Omarchy uses `pkexec` in ≥6 `bin/` scripts | high | — | — |
| `hide-hardware-info.service` + `etc/hide-hardware-info.d/30_default.conf` (preset **disabled**, "testers-only"): `chmod og-rwx /proc/cpuinfo /proc/bus /proc/scsi`, `o-rwx /sys/*` with group whitelists `sysfs`/`cpuinfo`; `user@.service.d/sysfs.conf` gives the user session `SupplementaryGroups=sysfs` | Hides hardware IDs from sandboxed or unprivileged code | NEW | **high**: the Hyprland/Quickshell shell, `omarchy-hw-*` detection (reads sysfs), btop, brightness and battery widgets. The whitelist group gives everything in the user session full access again, so the gain on a single-user desktop is about nil | yes | do-not-adopt |
| `remove-system-map.service` + `etc/kernel/postinst.d/30_remove-system-map` | Shreds `System.map*` | NEW | none | yes, but low value: Arch ships no `/boot/System.map`; `/usr/lib/modules/*/System.map` may exist (**unverified**). `kptr_restrict` already covers it | pacman_integrity (assert only) |

### 1f. Services, coredump, logging, pstore, Bluetooth, network

| Measure (path) | What it does | Class | Omarchy risk | Arch/Ansible | Role |
|---|---|---|---|---|---|
| `usr/lib/systemd/coredump.conf.d/30_security-misc.conf`: `Storage=none` | No stored cores. Per `coredump.conf(5)` (verified), with `none` "the core dumps may be logged (**including the backtrace if possible**), but not stored permanently" | IN-ROADMAP #14. **This resolves the roadmap's open question:** `omarchy-crash-watch` (which reads journal `MESSAGE_ID`) keeps working, but Omarchy's `default/agents/skills/diagnose-crash/SKILL.md:61` runs `coredumpctl dump`, and that needs a stored core. `Storage=none` breaks that step | med (AI crash diagnosis loses the core) | yes | coredump: use `ProcessSizeMax`/`ExternalSizeMax`/`MaxUse` caps, not `none` |
| **`usr/lib/systemd/pstore.conf.d/30_security-misc.conf`: `Storage=none`** | systemd-pstore does not copy kernel panic and oops records out of pstore to `/var/lib/systemd/pstore` (verified: with `none` "the tool exits without processing") | **NEW** | low (you lose post-mortem panic logs; pairs with `erst_disable`) | yes | coredump |
| `usr/lib/systemd/journald.conf.d/30_security-misc.conf`: `ForwardToWall=no` | No emergency wall broadcasts to terminals | NEW | none | yes | login_policy (trivial) |
| **`etc/bluetooth/30_security-misc.conf`**: `PairableTimeout=30`, `DiscoverableTimeout=30`, `MaxControllers=1`, `AutoEnable=false`, `Privacy=network/on` | Bluetooth exposure limits | **NEW**, with two findings. (1) **It is probably a no-op as shipped**: upstream `bluetoothd` loads only `main.conf` (`src/main.c`: `snprintf(..., "%*s/main.conf")`, verified), and Debian's bluez patch series has no drop-in patch (by patch name). So `/etc/bluetooth/30_security-misc.conf` is never read (**not tested on a running system**). Aegis must edit `/etc/bluetooth/main.conf` (`community.general.ini_file`). (2) **`AutoEnable=false` CONFLICTS with Omarchy**: `migrations/1786380259.sh` and `install/hardware/bluetooth.sh` deliberately reverted it ("all it bought was Bluetooth coming up off on every boot"; `omarchy-bluetooth-power` keeps the state in rfkill) | Timeouts: low. `Privacy=network/on`: low–med (BlueZ's `main.conf` warns "may not be compatible with some" peers that use identity addresses). `MaxControllers=1`: low (machines with two adapters, which `omarchy-bluetooth-power` explicitly handles). `AutoEnable=false`: **high** | yes (ini_file on `main.conf`, leaving AutoEnable alone) | network_privacy (or a new bluetooth sub-task) |
| `usr/lib/NetworkManager/conf.d/80_randomize-mac.conf`, `80_ipv6-privacy.conf`, `networkd.conf.d/80_ipv6-privacy-extensions.conf` | MAC randomization and IPv6 privacy, **all commented out** in KS (broke VirtualBox/root-server DHCP) | IN-ROADMAP #15 | low (use `stable`, not `random`) | yes | network_privacy |
| `etc/usbguard/usbguard-daemon.conf.security-misc` + `rules.d/30_security-misc.conf` | `ImplicitPolicyTarget=block`, `PresentDevicePolicy=allow`; rejects HID+other-class combos (BadUSB), RNDIS, and undefined classes; one keyboard and one mouse at a time; allows audio/video/storage/hub | IN-ROADMAP #23 (opt-in). **The rule set is NEW and reusable.** Caveat for Omarchy: "reject HID combined with anything else" would block **FIDO2 keys that also expose CCID/OTP-keyboard interfaces** (YubiKey OTP+FIDO+CCID = 03 + 0b), and "only one keyboard" blocks a dock keyboard plus a laptop USB keyboard. Allow-list FIDO first, as roadmap #23 already says | high if default; med as opt-in | yes (`extra/usbguard`) | usb_policy |
| `usr/share/polkit-1/actions/org.freedesktop.Flatpak.policy.security-misc` (+ hides `rules.d/org.freedesktop.Flatpak.rules`) | Every Flatpak install/update/remote change needs `auth_admin_keep` | NEW | low (Omarchy installs Flatpak only on demand) | yes (a polkit **rules** file in `/etc/polkit-1/rules.d/` overriding `wheel` → `auth_admin_keep` is cleaner than replacing the action file) | flatpak |
| `usr/lib/systemd/system/haveged.service.d/30_security-misc.conf`: `SystemCallFilter=getrandom` | Sandboxes haveged | n/a (Omarchy does not ship haveged; it is obsolete since 5.6+ RNG) | — | — | — |
| `emerg-shutdown` (C binary, `usr/lib/udev/rules.d/95-emerg-shutdown.rules`, dracut module, `etc/security-misc/emerg-shutdown/30_security_misc.conf`: Ctrl+Alt+End, or **power off when the boot drive is removed**), `ensure-shutdown`, `block-shutdown`, memlockd | Panic button / dead-man switch against cold-boot and seizure | NEW | med (Ctrl+Alt+End may collide with a Hyprland binding (**unverified**); the dracut-only initramfs part does not port to mkinitcpio) | partial (the C source would need packaging and audit; not audited here) | do-not-adopt for now (see below) |
| `usr/bin/fm-shim-frontend` + `fm-shim-backend.c` + `usr/lib/systemd/user/fm-shim.service` | Intercepts `org.freedesktop.FileManager1` D-Bus calls and asks before an app opens a folder | NEW | low–med (Chromium/Electron "Show in folder" prompts) | partial (Python + C, not audited) | agent_containment (idea only) |

### 1g. Application configs

| Measure (path) | Class | Omarchy risk | Notes / role |
|---|---|---|---|
| `etc/ssh/sshd_config.d/30_security-misc.conf`: `MaxAuthTries 3`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin prohibit-password`, no agent/TCP/X11 forwarding, Ed25519-only `HostKey`/`HostKeyAlgorithms`/`PubkeyAcceptedAlgorithms`, pinned `Ciphers`/`MACs`/`KexAlgorithms` (`sntrup761x25519`, `mlkem768x25519-sha256`) | IN-ROADMAP #16 for most of it. NEW: `PasswordAuthentication no`/`KbdInteractive no` and Ed25519-only keys | low for opt-in sshd. `PasswordAuthentication no` locks out a user who has no key yet | sshd. Do **not** pin Kex/Ciphers (they freeze today's list against future OpenSSH defaults; the claim that OpenSSH ≥10 already prefers mlkem768x25519 is **unverified this session**). Keep the roadmap's `PermitRootLogin no` |
| `etc/ssh/ssh_config.d/30_security-misc.conf` (client): `HostKeyAlgorithms`/`PubkeyAcceptedAlgorithms` **Ed25519 only**, pinned ciphers/kex, `VisualHostKey yes` | NEW | **med–high** for a developer: cannot connect to ECDSA/RSA-only hosts (network gear, older servers), cannot use RSA user keys. Omarchy already ships `/etc/ssh/ssh_config.d/20-omarchy-keepalive.conf`, and a `30-` file would sort after it | do-not-adopt globally |
| `etc/gitconfig`: `core.symlinks=false`, `transfer/fetch/receive.fsckobjects=true` | NEW | `fsckObjects`: low (some old repos have fsck warnings and fail to clone; **unverified frequency**). `core.symlinks=false`: **high** (breaks every repo with symlinks, which many dev repos and Omarchy's own tree use) | commit_signing: adopt `fsckobjects` only, opt-in |
| `etc/skel/.gnupg/gpg.conf` (no-emit-version, SHA512 prefs, long key IDs, `no-honor-keyserver-url`) | NEW | none | skel-only, so it affects new users only. Most of it is GnuPG 2.2+ default already (**unverified**). commit_signing (optional) |
| `usr/share/glib-2.0/schemas/30_security-misc.gschema.override`: Nautilus `show-image-thumbnails="never"` (also Thunar/Dolphin) | NEW (secureblue only removed PDF thumbnailers) | low (no image previews). Omarchy uses Nautilus and installs `ffmpegthumbnailer` (`install/omarchy-base.packages:45`), so video and image parsers run on file-manager browse | agent_containment / new opt-in: set the gsetting system-wide via a dconf/glib override |
| `etc/apt/apt.conf.d/40sandbox`, `40error-on-any`; `etc/dracut.conf.d` `reproducible=yes` | n/a (Debian/dracut) | — | pacman already drops privileges for downloads (`DownloadUser`, pacman 7) (**unverified on Omarchy's pacman.conf**) |
| `usr/lib/issue.d/20_security-misc.issue` (legal banner) | NEW | none | cosmetic; skip |
| `etc/apparmor.d/tunables/home.d/security-misc` (an alias for securetty) | n/a | — | — |
| `usr/libexec/security-misc/virusforget` | NEW | — | Qubes-style dotfile-tamper restore; not reviewed in depth; skip |

## 2. Value disagreements with the roadmap

1. **`kernel.yama.ptrace_scope`**: KS ships **3** by default; Aegis implements 1, with 2 opt-in. **Ours is better** for a dev desktop. 3 is irreversible until reboot and kills gdb, strace, Proton and anticheat. KS can afford it because its users are not debugging.
2. **`perf_event_paranoid`**: KS uses 3, the roadmap uses 2. **Ours is better on `linux-omarchy`.** Mainline `kernel.rst` documents levels only up to `>=2` (verified); 3 is a Debian/linux-hardened patch. On mainline, 3 is accepted but behaves as 2, so asserting "3" proves nothing.
3. **`oops_limit`/`warn_limit`**: KS uses **1/1** (on through an enabled late-boot unit), the roadmap uses 100/100. **Ours is better** for the default, because a single NVIDIA or Wi-Fi WARN would reboot the desktop. `warn_limit` defaults to 0 (= unlimited) and `oops_limit` to 10000 (verified). **Adopt KS's mechanism, though:** set the limits late (after `graphical.target`) and allow a `panic-on-oops=0` cmdline escape hatch, so boot-time driver noise does not count.
4. **faillock**: KS uses `deny=50`, a 7-day window, `unlock_time=never` and a persistent `dir`; the PRD uses `deny=3`, 900 s and the tmpfs dir. The deny count is a policy call; **keep the PRD**, because `deny=3` + `never` would be a trivial lockout DoS. **KS is better on `dir`**: a tmpfs tally resets on reboot, so adopt a persistent dir regardless. KS's sshd exclusion only makes sense with a high deny count. With `deny=3`, prefer key-only sshd (then no PAM auth attempts happen at all).
5. **`io_uring_disabled`**: KS uses 2, the roadmap uses opt-in `1` + `io_uring_group`. **Ours is better** (QEMU, libuv and databases).
6. **`rp_filter`**: KS uses 1, the roadmap uses 2. **Ours** (WireGuard/Tailscale).
7. **`use_tempaddr=2` / NM `ip6-privacy=2` / MAC randomization**: KS **disabled all three** because of VirtualBox and root-server DHCP breakage; the roadmap #4/#15 enables them. **Ours is fine for Omarchy** (an NM desktop; `omarchy-windows-vm` is QEMU, not VirtualBox), but add KS's breakage case to the role's test notes. Use `cloned-mac-address=stable`, not `random`.
8. **CPU mitigations**: KS turns on `nosmt=force` and every `,nosmt` variant by default; the roadmap #25 makes it opt-in. **Ours is better** for a workstation. The non-SMT extras KS adds (`spectre_bhi=on`, `tsx=off`, `indirect_target_selection=force`, `vmscape=force`, `reg_file_data_sampling=on`; all verified present) can join the roadmap's opt-in mitigation group.
9. **`slab_debug=FZ`**: KS has it on by default; secureblue had it opt-in. **Opt-in is better**, and **KS documents a trap neither review caught**: `slab_debug` disables `%p` hashing (`hash_pointers=auto`), so it leaks kernel addresses unless `hash_pointers=always` is also set (verified in `kernel-parameters.txt`).
10. **Module blocklist scope**: KS blocks `thunderbolt`, `cifs`, `nfs*`, `hfsplus` and `udf` by default. **Ours is better** (the roadmap's exclusions stand). Use KS's per-class stub messages instead of `/bin/false`.
11. **Core dumps**: KS stacks `core_pattern=|/bin/false` + `core 0` + `Storage=none`; the roadmap uses size caps. **Ours.** `Storage=none` would break the `coredumpctl dump` step of Omarchy's diagnose-crash skill.
12. **sshd `PermitRootLogin`**: KS uses `prohibit-password`, the roadmap uses `no`. **Ours is stricter and fine.** KS adds `PasswordAuthentication no`, which is worth taking (see top list).
13. **`kexec`/`printk`/`kptr`/`dmesg`**: the same values as ours. No disagreement.

## 3. Top NEW items to add (ranked)

1. **Persistent faillock tally dir** (`dir=/var/lib/aegis/faillock` in `faillock.conf` **and** inline on Omarchy's `system-auth` and `omarchy-lock-password` lines, plus a `tmpfiles.d` entry). This closes the reboot-resets-counter bypass of the PRD's `deny=3`. Role **pam_faillock**. Risk: low.
2. **Cover `su` on Arch**: uncomment `pam_wheel.so use_uid` in `/etc/pam.d/su` and `su-l`, and add `pam_faillock` (or `auth include system-auth`) there. Arch's `su.pam` bypasses `system-auth`, so today `su` escapes the faillock policy (verified from Arch packaging). Role **login_policy**. Risk: low.
3. **sudo `Defaults umask_override, umask=0022`** as the required companion to roadmap #26's `pam_umask 027`. Without it, every `sudo tee /etc/...` in Omarchy's own scripts creates root-only files. Role **login_policy**. Risk: low.
4. **Limine boot-time lockdown**: `editor_enabled: no` and `hash_mismatch_panic: yes` (both verified in Limine `CONFIG.md`; Omarchy sets `hash_mismatch_panic: no`). This is the Limine analog of KS's `GRUB_DISABLE_RECOVERY`/`rd.shell=0`, and a prerequisite before any locked-root plus passwordless-rescue scheme. Role **secure_boot** (or **kernel**). Risk: low (recovery then needs a live USB).
5. **`dev.tty.legacy_tiocsti=0` as an assert** (Arch already builds it off; the assert catches a kernel that does not). Role **sysctl**. Risk: none.
6. **Crash-record minimisation**: `pstore.conf.d` `Storage=none` plus `erst_disable` (the EFI pstore backend is already default-off on Arch). Kernel oops and panic text, which can include memory contents, then stops landing in `/var/lib/systemd/pstore`. Role **coredump**. Risk: low.
7. **`proc_mem.force_override=ptrace`** (Arch defaults to `ALWAYS_FORCE`, verified). It blocks the `/proc/self/mem` write-to-read-only-page primitive outside ptrace. Role **kernel**. Risk: low–med; VM-test with Steam/Proton and JIT-heavy apps first.
8. **Bluetooth exposure limits, written into `/etc/bluetooth/main.conf`** (not a drop-in, which bluetoothd ignores): `PairableTimeout=30`, `DiscoverableTimeout=30`, `Privacy=network/on` as an option. **Leave `AutoEnable` alone** (Omarchy reverted it). Role **network_privacy**. Risk: low.
9. **Module blocklist additions with reason stubs**: GNSS, Intel PMT, `pcspkr`/`snd_pcsp`, `evbug`, `usbkbd`/`usbmouse`, the `ksmbd` and `nfsd` **servers** only. `joydev` and `rndis_host` as opt-ins. Use a `/usr/local/libexec/aegis-module-blocked` stub per class instead of `/bin/false`, so users see why a module failed. Role **module_blocklist**. Risk: low (opt-ins med).
10. **Narrow SUID strip with a pacman hook** (`chfn`, `chsh`, `newgrp`, `gpasswd`, `expiry`, `chage`), re-applied in a `PostTransaction` hook, plus `/etc/sudoers.d 0750`. This is the subset of `permission-hardener` that survives Arch. Role **pacman_integrity**. Risk: low.
11. (Honourable mentions) `sshd`: `PasswordAuthentication no` + `KbdInteractiveAuthentication no` once a key exists. The Flatpak polkit `auth_admin_keep` rule. Git `fsckObjects` opt-in. The system-wide Nautilus thumbnail-off option. `abi.vsyscall32=0`/`vdso32=0`. `printk=3 3 3 3`, `shared_media=0`, `log_martians=1` (review-only items that dropped out of the roadmap).

## 4. Do-not-adopt (only items not already on our list)

- **`net.ipv6.conf.*.accept_ra=0`**: under NetworkManager it is likely a false-green no-op (NM processes RAs in userspace; **unverified**). Without NM it breaks IPv6 SLAAC.
- **`ptrace_scope=3` as default**, **`oops_limit=1`/`warn_limit=1`**, **`kernel.panic=-1` by default**: these are KS defaults that turn a desktop driver WARN or a debugger into a reboot or a dead end.
- **`kernel.modules_disabled=1` after boot** (`harden-module-loading`): breaks hotplug (docks, resume, `omarchy-dev-install-ydoo`'s `modprobe uinput`, xpadneo).
- **`hide-hardware-info`** (`/sys`, `/proc/cpuinfo` lockdown): breaks the Omarchy shell and hardware detection, and the session whitelist undoes it anyway on a single-user box.
- **`/usr/lib/modules 0700`, `/boot 0700` as file modes**: pacman resets them, and they break unprivileged module tooling. Mount options (roadmap #17) are the durable route for the ESP.
- **Bluetooth `AutoEnable=false`** and **`MaxControllers=1`**: Omarchy reverted AutoEnable deliberately and supports multi-adapter machines.
- **Global SSH client algorithm pinning** (Ed25519-only `HostKeyAlgorithms`/`PubkeyAcceptedAlgorithms`, fixed Kex/Ciphers): breaks connections to RSA/ECDSA hosts and freezes the algorithm list. The same applies to pinning Kex/Ciphers in sshd.
- **`git core.symlinks=false`**: breaks every repo with symlinks.
- **`SYSTEMD_SULOGIN_FORCE=1` (passwordless rescue)** unless the Limine editor is disabled and Secure Boot is on; otherwise it is a root shell for anyone at the keyboard after LUKS unlock.
- **No-ops on Arch** (would read as controls but change nothing): `cfi=kcfi` (GCC-built kernel), `kfence.sample_interval=100` (already the default), `efi_pstore.pstore_disable=1` (already default-disabled), `extra_latent_entropy` (linux-hardened only), `jitterentropy_rng` modules-load (built in), `options nf_conntrack nf_conntrack_helper=0` (no such param on master), `kernel.core_uses_pid=1` (pipe pattern), `kpti=1` (ARM64 only), `tcp_tw_reuse=0` (only meaningful with timestamps off), `Defaults !fqdn` (believed default-off, unverified). The Bluetooth drop-in **file** also belongs here: bluetoothd ignores it.
- **`emerg-shutdown`** (boot-drive-removal and panic-key power-off): unaudited C plus a dracut-only initramfs part. Interesting for a later threat-model discussion; not a hardening default.
- **USBGuard rule "reject HID + any other interface"** as written: blocks multi-interface FIDO2/OTP keys. Needs FIDO allow-list rules first (roadmap #23 opt-in only).

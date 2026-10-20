# secureblue review for Omarchy-Hardened (Aegis)

- **Reviewed:** https://github.com/secureblue/secureblue at commit `5be4f13f70f1cfc31434c50a264d750965a1df01` (commit date 2026-10-20). Reviewed from a shallow clone: 518 files outside `.git`. Nothing in it was executed. I only read it with grep, sed and cat. One JSON file was parsed with `python3 -I`, and that ran my own one-line script, not code from the repo.
- **Omarchy baseline:** basecamp/omarchy at `dde0d12`.
- **Package checks:** fetched 2026-10-20 from the `archlinux.org/packages/search/json` and `aur.archlinux.org/rpc/v5` endpoints. The results are in section 6.
- **Method:** each measure was traced from the actual file that sets it (recipes, `files/system/**`, `files/scripts/**`, ujust recipes, Python toggles). The README was not used as a source. In fact `docs/README.md` holds no technical claims that matched my greps.

Risk legend: **none / low / med / high**, followed by what breaks on Omarchy.

---

## 1. Inventory table

### 1a. Sysctls: `files/system/usr/lib/sysctl.d/55-hardening.conf`
Server-only extras are in `files/system/server/usr/lib/sysctl.d/56-server-hardening.conf` (`tcp_sack=0`, `tcp_dsack=0`).

Omarchy ships `etc/sysctl.d/90-omarchy-arp.conf`, `90-omarchy-file-watchers.conf` and `99-omarchy-sysctl.conf`. Those cover arp, inotify and VM/BBR tuning only, with no security sysctls.

All entries port directly to an Ansible `sysctl.d` drop-in. Aegis role: **sysctl**.

| Setting(s) | Omarchy breakage risk | Omarchy does it? | Notes |
|---|---|---|---|
| `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.printk=3 3 3 3` | low (`omarchy-debug` already runs `sudo dmesg`) | no | Adopt. |
| `net.core.bpf_jit_harden=2`, `kernel.unprivileged_bpf_disabled=1` | low | no | Adopt. Mainline's default is already "unpriv off" when `CONFIG_BPF_UNPRIV_DEFAULT_OFF` is set. Not verified for `linux-omarchy`. |
| `kernel.sysrq=0` | low (lose the SysRq rescue keys) | no | Adopt, or use `4` to keep SAK only. |
| `kernel.perf_event_paranoid=3` | low | no | **Caveat:** `3` comes from a Debian/linux-hardened patch. Mainline only defines levels up to 2. Use `2` and assert on it. Not verified against the `linux-omarchy` config. |
| `kernel.kexec_load_disabled=1` | low (no kexec reboot; Limine does not use it) | no | Adopt. |
| `kernel.oops_limit=100`, `kernel.warn_limit=100`, `kernel.panic=-1` | low | no | Adopt the limits. `panic=-1` reboots immediately on panic, so the panic text is lost from the screen. Make it optional. |
| `kernel.yama.ptrace_scope=1` | none | not set explicitly (kernel default) | secureblue keeps 1 and does the real restriction through SELinux booleans (see 1g). The Arch equivalent is 2 (admin-only). Medium risk: breaks `gdb -p` and `strace -p` as a normal user, and some anticheat. |
| `fs.protected_{regular,fifos}=2`, `fs.protected_{hardlinks,symlinks}=1`, `fs.suid_dumpable=0` | low | partly (systemd's `50-default.conf` already sets hardlinks/symlinks=1 and regular/fifos=1; not re-verified on Arch this session) | Adopt. |
| `dev.tty.ldisc_autoload=0`, `vm.unprivileged_userfaultfd=0` | low | no | Adopt. |
| `vm.mmap_rnd_bits=32`, `vm.mmap_rnd_compat_bits=16`, `kernel.randomize_va_space=2`, `vm.mmap_min_addr=65536`, `vm.max_map_count=1048576` | low | max_map_count yes, through Arch's `filesystem` package (not re-verified this session) | Adopt. Assert that `mmap_rnd_bits` does not exceed `CONFIG_ARCH_MMAP_RND_BITS_MAX`. |
| `kernel.io_uring_disabled=2` | **med** (QEMU `aio=io_uring`, some databases, and libuv/Node or Bun file I/O fast paths. The libuv fallback is not verified. Docker is unaffected as far as I know.) | no | Prefer `1` plus `kernel.io_uring_group`, or make it opt-in with a test matrix. |
| `fs.binfmt_misc.status=0` (plus `files/system/usr/lib/udev/rules.d/99-secureblue.rules`, which re-applies it when the module loads) | **high**: Omarchy ships `qemu-user-static-binfmt` and `etc/systemd/system/systemd-binfmt.service.d/10-eager-mount.conf`, so this breaks `docker buildx --platform` cross-arch builds and running foreign-arch binaries | no (the opposite: Omarchy *enables* binfmt) | **Do not adopt by default.** |
| `kernel.core_pattern=\|/bin/false` (plus `limits.d/60-disable-coredump.conf` and `DumpCore=no` in `system.conf.d` and `user.conf.d`) | **high**: breaks `systemd-coredump`, which `bin/omarchy-crash-watch` (journal `MESSAGE_ID` of coredumps) and `bin/omarchy-agent-crash` (`coredumpctl`) depend on | no | **Do not copy.** Use `fs.suid_dumpable=0` plus `/etc/systemd/coredump.conf.d/` with `Storage=none` or small `ProcessSizeMax`/`ExternalSizeMax` caps. I believe `Storage=none` still journals the crash metadata that crash-watch reads, but that is **unverified** and needs a test. |
| `net.ipv4.tcp_syncookies=1`, `tcp_rfc1337=1`, `icmp_echo_ignore_broadcasts=1`, `icmp_ignore_bogus_error_responses=1` | none | no | Adopt. |
| `net.ipv4.icmp_echo_ignore_all=1`, `net.ipv6.icmp.echo_ignore_all=1` | low (host not pingable; LAN diagnostics) | no | Optional. ufw already drops unsolicited inbound traffic. |
| `net.ipv4.tcp_timestamps=0` | low (small perf/PAWS cost) | no | Optional. |
| `rp_filter=1` (all and default) | **med**: strict mode can drop asymmetric traffic on WireGuard/Tailscale policy routing and on docks | no | Use `2` (loose) when the `overlay_network` role is active. |
| `*.send_redirects=0`, `*.accept_redirects=0`, `*.accept_source_route=0`, `shared_media=0`, `log_martians=1` | none | no | Adopt. `log_martians` adds journal noise. |
| `arp_filter=1`, `arp_ignore=2`, `drop_gratuitous_arp=1` | **med**: Omarchy deliberately set `arp_ignore=1`/`arp_announce=2` (`migrations/1791147791.sh`: "so a dock and Wi-Fi on one network keep their routes"). `arp_ignore=2` and `arp_filter=1` change that same multi-homed behaviour. | conflicting value | **Keep Omarchy's values.** Leave these out. |
| `ipv6 use_tempaddr=2` (also `files/system/usr/lib/NetworkManager/conf.d/40-secureblue.conf` `ipv6.ip6-privacy=2`) | none | no | Adopt. |
| Server: `tcp_sack=0`, `tcp_dsack=0` | low–med (throughput) | no | Skip on a workstation. |

### 1b. Kernel boot args
Sources:
- `files/system/usr/lib/bootc/kargs.d/10-secureblue.toml`: the defaults, baked into the image.
- `files/system/usr/libexec/secureblue/shared/kargs_hardening.py`: opt-in sets `DISABLE_32_BIT`, `FORCE_NOSMT` and `UNSTABLE_KARGS`.
- `set_kargs_hardening.py` / `ujust set-kargs-hardening`: an interactive opt-in.

Portable through a Limine drop-in at `/etc/limine-entry-tool.d/NN-aegis.conf` using `KERNEL_CMDLINE[default]+="..."`, the same mechanism as Omarchy's `etc/limine-entry-tool.d/omarchy-defaults.conf`, followed by a `limine-update` / UKI rebuild. Omarchy builds a UKI (`omarchy-uki.conf: ENABLE_UKI=yes`), so the cmdline is embedded in it. Aegis role: **kernel**.

| Karg(s) | Risk on Omarchy | Omarchy? | Recommendation |
|---|---|---|---|
| `init_on_alloc=1`, `page_alloc.shuffle=1`, `slab_nomerge`, `randomize_kstack_offset=on`, `vsyscall=none`, `vdso32=0` | low (a few percent of perf for init_on_*; `vsyscall=none` breaks very old static binaries) | no | Adopt. |
| `init_on_free=1` | low–med (more perf cost, especially on memory-heavy workloads such as AI tooling builds) | no | Adopt, and measure. |
| `pti=on`, `spectre_v2=on`, `spec_store_bypass_disable=on`, `ssbd=force-on`, `l1tf=full,force`, `l1d_flush=on`, `kvm-intel.vmentry_l1d_flush=always`, `kvm.mitigate_smt_rsb=1`, `gather_data_sampling=force` (unstable set) | low–med (perf; `gather_data_sampling=force` can disable AVX on affected CPUs) | no | Adopt the first group as an option. Keep `gather_data_sampling` opt-in. |
| `mitigations=auto,nosmt` | **med**: disables SMT on vulnerable CPUs, with a large hit to multi-core builds | no | Opt-in. `nosmt=force` is opt-in in secureblue too. |
| `iommu=force`, `intel_iommu=on`, `iommu.strict=1`, `iommu.passthrough=0`, `amdgpu.iommu_perfopt=0`, `efi=disable_early_pci_dma` (unstable), `amd_iommu=force_isolation` (unstable) | low–med (strict IOMMU costs some GPU/NVMe throughput; `force_isolation` and early PCI DMA can break some boards and TB docks) | no | Adopt the strict IOMMU group. It is the DMA defence that matters most given Omarchy keeps Thunderbolt enabled. Keep the unstable ones opt-in. |
| `random.trust_cpu=off`, `random.trust_bootloader=off` | low (slower entropy at early boot) | no | Adopt. |
| `hash_pointers=always`, `proc_mem.force_override=ptrace` | low | no | Adopt only when the running kernel supports them. Both are recent options and the minimum versions are **unverified**, so assert through `/proc/cmdline` plus a version gate. |
| `debugfs=off` (unstable) | low–med (some GPU and power tools read debugfs) | no | Optional. |
| `lockdown=confidentiality` | **high**: breaks hibernation (`bin/omarchy-hibernation-setup` exists), unsigned DKMS modules, `/dev/mem`/`iopl` tools, some BPF tracing. Needs `CONFIG_SECURITY_LOCKDOWN_LSM` in `linux-omarchy`, which is **unverified**. | no | Do not adopt by default. `integrity` mode only after the secure-boot work. |
| `module.sig_enforce=1` | **high**: Omarchy installs `dkms`, `broadcom-wl-dkms`, `nvidia-open-dkms` (n1x) and `macbook12-spi-driver-dkms`, and those modules are unsigned unless you add a MOK/sbctl signing hook | no | Not by default. Pair with a signing hook later. |
| `kvm-*.nested=0`, `kvm_amd.sev*=1` | low (breaks nested virt inside `omarchy-windows-vm` guests only) | no | Optional. |
| `loglevel=0` | none | **yes** (`omarchy-defaults.conf`) | Already done. |
| `rd.shell=0`, `rd.emergency=halt` | n/a | no | These are dracut/systemd-initrd options. Omarchy x86 uses a busybox mkinitcpio (`HOOKS=(base udev ... encrypt ...)` in `etc/mkinitcpio.conf.d/omarchy_hooks.conf`), so they **do not apply**. Do not cargo-cult them. |
| `slab_debug=FZ` | med (memory and CPU overhead) | no | Opt-in. |
| `oops=panic`, `bdev_allow_write_mounted=0`, `mem_encrypt=on` (unstable) | med (`oops=panic` turns driver warnings into reboots) | no | Opt-in. |
| `ia32_emulation=0` | **high** for Steam/Wine (`bin/omarchy-install-gaming-steam` installs native Steam, which needs 32-bit) | no | Opt-in, and refuse it when Steam is installed. |
| `systemd.ssh_auto=no` | none | no | Adopt (systemd ≥ 256 ssh-generator). |

### 1c. Module blacklists
Sources:
- `files/system/usr/lib/modprobe.d/secureblue.conf`: `install <mod> /bin/false`, about 260 modules.
- `files/system/usr/lib/modprobe.d/secureblue-framebuffer.conf`: `blacklist` for legacy fbdev drivers.
- `files/system/etc/dracut.conf.d/99-omit{firewire,thunderbolt}.conf`.
- Toggles: `inner/bluetooth.py` writes `/etc/modprobe.d/99-bluetooth.conf` with `install bluetooth /sbin/modprobe --ignore-install bluetooth`. `inner/webcam.py` writes `99-disable-webcam.conf` (uvcvideo and IPU modules).
- `ujust override-enable-module` (`files/justfiles/common/toggles.just`).

`install ... /bin/false` is the important detail. Unlike `blacklist`, it also blocks explicit and dependency loads. These port as `/etc/modprobe.d/aegis-*.conf`. Aegis role: **kernel**, or a new `module_blocklist` role.

| Group | Risk on Omarchy | Omarchy? | Recommendation |
|---|---|---|---|
| Obscure network protocols (dccp, sctp, rds, tipc, ax25/netrom/rose/x25, decnet, econet, ipx, appletalk, atm, can*, 6lowpan, batman-adv, mctp, smc, rdma*, rxrpc, gpib, n-hdlc) | none/low (WebRTC SCTP runs in userspace) | no | **Adopt.** These are the frequent CVE vectors. |
| Debug/test modules (vivid, vimc, vim2m, visl, vkms, scsi_debug, dummy_hcd, nandsim, mtdram, mce-inject, hwpoison-inject, aer_inject, ring_buffer_benchmark, netconsole, xsk_diag, vsock_diag) | none | no | **Adopt.** Leave out `v4l2loopback`, which secureblue does not block. |
| Legacy hardware (parport*, ppdev, lp, gameport, floppy, firewire*, ohci1394…, cdrom/sr_mod, x86-android-tablets, ath_pci, automotive PHYs, GNSS) | low (`cdrom`/`sr_mod` kills optical drives; GNSS kills USB GPS) | no | Adopt, but keep `cdrom`/`sr_mod` optional. |
| Rare filesystems (cramfs, freevxfs, jffs2, hfs, hfsplus, udf, gfs2, reiserfs, kafs/afs, orangefs, adfs, affs, befs, ceph, coda, ecryptfs, jfs, minix, nilfs2, ocfs2*, romfs, ubifs, zonefs, sysv, ufs, dlm) | low–med (`hfsplus` blocks Mac-formatted USB drives; `udf` blocks DVDs and some USB media) | no | Adopt, minus `hfsplus` and `udf` unless the user opts in. |
| `squashfs` | low (AppImage uses FUSE. Omarchy's `omarchy-install-t3code-app` uses `--appimage-extract` in userspace. Loop-mounting ISOs/snaps breaks.) | no | Optional. |
| Network filesystems (`cifs`, `nfs*`, `sunrpc`, `lockd`, `grace`, `ksmbd`, `9p*`) | **med**: Omarchy ships `gvfs-nfs` (needs kernel NFS for mounts) and users mount SMB with `cifs`. `gvfs-smb` runs in userspace and is unaffected. `9p` blocks QEMU/virtiofs-style shares. | no | Block `ksmbd`/`nfsd` (server side). Make client NFS/CIFS opt-in. |
| IPsec / xfrm / esp / ah / l2tp / `af_key` | med: breaks IPsec/L2TP VPNs (strongSwan, libreswan, NM-l2tp). WireGuard and Tailscale are unaffected. | no | Adopt with a toggle. Note that `xfrm_user` is used by Docker Swarm encrypted overlays. |
| `bluetooth`, `btusb` | **high**: Omarchy installs `bluez`, enables `bluetooth.service` (`install/hardware/bluetooth.sh`) and ships a Bluetooth TUI/menu | no | **Do not block by default.** Offer as an opt-in toggle using secureblue's `--ignore-install` override pattern. |
| `thunderbolt`, `thunderbolt_net` (plus dracut omit) | **high**: Omarchy force-loads `thunderbolt` into the initramfs (`etc/mkinitcpio.conf.d/thunderbolt_module.conf`) and ships `bolt`. Blocking it breaks docks, USB4/TB displays and eGPUs. | no (the opposite) | **Do not adopt.** Rely on IOMMU strict mode plus bolt's security level instead. |
| Framebuffer `blacklist` (vesafb, udlfb, sisfb…) | low | no | Adopt. |
| Webcam toggle (uvcvideo, IPU) | high if forced (video calls) | no | Opt-in toggle only. |

### 1d. hardened_malloc
Sources:
- `recipes/common/common-packages.yml`: installs `hardened_malloc` and `no_rlimit_as`.
- `files/scripts/set-ld-preload.sh`: writes `/etc/ld.so.preload` = `libhardened_malloc.so libno_rlimit_as.so`. This is a **global** preload.
- `files/system/usr/bin/with-standard-malloc`: the escape hatch. It enters a mount namespace (plus a userns when not root), bind-mounts `/dev/null` over `/etc/ld.so.preload`, `runcon`s to `unconfined_t`, drops caps with `capsh`, then execs. It has its own SELinux domain `stdmalloc_t` (`files/scripts/selinux/stdmalloc/*`). Tests: `.github/workflows/tests/stdmalloc_tests.bats`.
- **Exceptions list:** there is no central list. It is ad hoc:
  - `files/scripts/plasma-apps-standard-malloc.sh` rewrites `Exec=` lines for KDE `systemsettings` and `ibus-ui-gtk3`.
  - `files/justfiles/desktop/steam.just` unsets `LD_PRELOAD` for the Steam Flatpak.
  - `files/scripts/removesuid.sh` whitelists the hardened_malloc `.so`s from its setuid sweep.
- **Flatpak preload:** `files/system/desktop/usr/libexec/secureblue/harden_flatpak.py` sets the global override `--filesystem=host-os:ro --env=LD_PRELOAD=/var/run/host/usr/lib64/glibc-hwcaps/<x86-64-vN>/libhardened_malloc.so` (picking the best hwcap from `ld.so --help`) plus `ELECTRON_OZONE_PLATFORM_HINT=auto`. It runs automatically at first login through `secureblueflatpaksetup`.
- **Audit:** `audit_hardened_malloc()` requires the preload file to be exactly `["libhardened_malloc.so", "libno_rlimit_as.so"]`, and flags WARN for the `light`/`pkey` variants.

Portability:
- **Arch: AUR only.** `hardened_malloc 13-1`: last modified 2024-10-14, **flagged out of date since 2026-02-23**. `hardened-malloc-git` was last modified 2025-03-11. The library installs to `/usr/lib/libhardened_malloc.so` according to the PKGBUILD.
- `no_rlimit_as` is not packaged on Arch: it is in neither the official repos nor the AUR.
- The `glibc-hwcaps` variants are not built by the AUR package.

Omarchy risk:
- **High** if the preload is global. Hyprland, Chromium and Electron behaviour under hardened_malloc is untested here (**unverified**). Native Steam and anything that sets `RLIMIT_AS` hit the problem `no_rlimit_as` exists to fix.
- Injecting the host Arch `.so` into Flatpak runtimes with an older glibc is likely to fail symbol-version checks (**unverified**).

Omarchy does nothing here. Aegis role: **hardened_malloc**. Copy the *pattern*: opt-in, a per-app escape-hatch wrapper, an audit that checks the exact preload content, and bats tests for the wrapper. Do not copy the global default.

### 1e. Unprivileged user namespaces
See section 2. Sources:
- `files/scripts/selinux/user_namespace/harden_userns.cil`
- `harden_container_userns.cil`
- `userns_deny_unconfined_relabels.cil`
- `set_unconfined_userns.py`
- `set_container_userns.py`
- `recipes/common/common-packages.yml` (`bubblewrap` replaced from secureblue's COPR plus `bubblewrap-selinux`; `bubblejail`)
- `removesuid.sh` (strips setuid from everything in `/usr`, so `bwrap` relies on userns)

Aegis roles: **apparmor**, **flatpak**, **agent_containment**.

### 1f. USBGuard
Source: `ujust setup-usbguard` (`files/justfiles/common/utilities.just`). It generates a policy from the currently attached devices, creates a `usbguard` group, adds it to `IPCAllowedGroups`, enables `usbguard.service`, and enables `usbguard-notifier --user` on desktops. The packages `usbguard` and `usbguard-notifier` come from `desktop-packages.yml`. It is **opt-in**, and `audit_usbguard()` FAILs until it is enabled.

On Arch, `extra/usbguard 1.1.4` is available. `usbguard-notifier` is AUR only (0.1.1, last updated 2024-03-21).

Risk on Omarchy: **high** as a default. Omarchy shipped USB and Thunderbolt device approval with usbguard, then **removed it**: `migrations/1791769486.sh` says "Remove approval for new USB and Thunderbolt devices" and that it "shipped briefly to edge and dev". A default-deny policy breaks keyboards on a new dock, YubiKeys and phones, and it runs straight against LocalSend/MTP workflows.

Aegis role: a new **usb_policy** role (opt-in) or under **fido2**. If it is ever enabled, allow-list the FIDO2 key classes first.

### 1g. ptrace / Yama
Sources:
- sysctl `ptrace_scope=1`, plus SELinux booleans `deny_ptrace=on` and `container_allow_ptrace=off` (`files/scripts/set-selinux-booleans.sh`, `selinux/ptrace/container-ptrace.cil`).
- `ujust set-ptrace` (`shared/ptrace.py`) has states disabled / admin-only / container-only / restricted / unrestricted.
- `audit_ptrace()`: WARN at scope=1, PASS only when fully disabled.

On Arch, the AppArmor equivalent is profiles without `ptrace` rules (confined processes only). The global knob is `ptrace_scope=2` (admin-only) or 3 (none, irreversible until reboot).

Risk on Omarchy:
- 2 is **med**: developers lose `gdb -p` and `strace -p` without sudo.
- 3 is **high**: no debugging at all, and some anticheat breaks.

Aegis role: **sysctl**. Offer 2 as an option, and keep 1 plus AppArmor `deny ptrace` for agent profiles.

### 1h. Flatpak hardening
Sources:
- `secureblueflatpaksetup` and `secureblue-flatpak-setup.{service,timer}` (a user unit): adds the remote `flathub-verified` with `--subset=verified`, runs `harden-flatpak`, installs Flatseal.
- `ujust flatpak-permissions-lockdown` (`files/justfiles/desktop/flatpak.just`, opt-in): a global `flatpak override --user` that does `--unshare=network,ipc`, `--nosocket` for x11/fallback-x11/pulseaudio/session-bus/system-bus/ssh-auth/gpg-agent/cups/pcsc, `--nodevice=all,shm,kvm,input,usb`, `--disallow=bluetooth,canbus,devel,multiarch,per-app-dev-shm`, and `--nofilesystem=home,host,host-etc` plus dangerous paths (`~/.bashrc`, `/run/media`…). It denies about 40 known session-bus and about 20 system-bus names, then grants `--persist=.`, `--socket=wayland --device=dri`, and Flatseal talk-names.
- `audit_flatpak_remotes()` FAILs on non-Flathub URLs and non-verified subsets. `audit_flatpak_permissions()` with the per-permission severity table in `audit_flatpak/__init__.py` and `filesystem.py`: x11=FAIL, session-bus=FAIL, gpg-agent=FAIL (sandbox escape), device=all=FAIL, pulseaudio=WARN, network=INFO…
- Bazaar store curation (`files/system/desktop/usr/share/bazaar/blocklist.yaml`).
- `flatpak-system-update.timer` / `flatpak-user-update.timer`.

On Arch, `extra/flatpak 1.18.4` is available. Everything except the hardened_malloc preload ports to Ansible (`community.general.flatpak_remote` plus templated override files in `~/.local/share/flatpak/overrides/global`).

Risk on Omarchy:
- Low for the verified-remote and audit parts.
- **High** for the lockdown: it breaks most apps until the user tunes each one. On Hyprland, `--nosocket=x11` also breaks Steam and older Electron Flatpaks (Omarchy keeps Xwayland on: `default/hypr/envs.lua`).
- Omarchy only installs `flatpak` on demand (`omarchy-install-gaming-geforce-now`).

Aegis role: **flatpak**. Adopt the verified-only remote, a permission audit and auto-update. Make the lockdown opt-in.

### 1i. Browser policies
secureblue ships its own Chromium fork, **Trivalent**: `files/scripts/install-trivalent.sh` installs the RPM after **`slsa-verifier verify-artifact`** against GitHub provenance. The hardening policies live in the separate Trivalent repo, which was **not reviewed**.

The only policy written from this repo is DoH, in `inner/dns.py`: `/etc/trivalent/policies/managed/10-securedns-browser.json` = `{"DnsOverHttpsMode":"secure","DnsOverHttpsTemplates":…}`.

On Arch, `trivalent-bin` exists in the AUR (155.0.8059.84, third-party maintainer). That is not a trust upgrade over Arch's `chromium`.

Omarchy:
- Ships `default/chromium/policies/omarchy.json` (`DefaultBrowserSettingEnabled:false`).
- Manages `/etc/{chromium,opt/chrome,opt/edge,brave}/policies/managed` with root-ownership hardening (`install/helpers/browser-policy.sh`) and a sudoers-gated `omarchy-theme-set-browser-policy` that writes `color.json`.

Risk: low if Aegis adds a separate `aegis-*.json` in those directories and leaves Omarchy's files alone. Aegis role: a new **browser_policy** role, or **apparmor**. Copy the DoH policy idea (keep it optional because of the VPN-leak caveat secureblue itself prints). Take the actual hardening policy set from Trivalent or Brave, which needs a separate review.

### 1j. Privilege model: sudo, run0, polkit, PAM
| Measure (path) | Portable? | Omarchy risk | Omarchy? | Aegis role |
|---|---|---|---|---|
| Remove sudo (`files/scripts/removesudo.sh`, `unprotectsudo.sh`) and use `run0` (`etc/profile.d/sudo-missing-message.sh`, `run0edit` package) | yes. `run0` is in systemd; `run0edit` is AUR only | **high**: Omarchy depends on sudo throughout (`etc/sudoers.d/omarchy-{dns,locale-generate,theme-browser,tzupdate,passwd-tries}`, `omarchy-update-time` uses `sudo`, `as_root` helpers) | no | Do not adopt. Instead **audit** the NOPASSWD sudoers drop-ins (`pacman_integrity` check-only). |
| Strip all setuid/setgid in `/usr`, delete `su`/`sudo`/`pkexec`/`chsh`/`chfn`, replace with file caps (`files/scripts/removesuid.sh`) | technically yes, but pacman restores the bits on every upgrade, so it does not persist | **high** (sudo, pkexec for the Docker TUI polkit flow, `fusermount3`, `chrome-sandbox` setups) | no | Do not adopt. Check-only: diff the setuid inventory against an allow-list in `pacman_integrity`. |
| Separate admin account, remove wheel from the daily user (`ujust create-admin` → `inner/admin.py`; `audit_groups()` FAILs if the user is in wheel) | yes | **high** for Omarchy UX (every `%wheel NOPASSWD` rule and every menu action) | no | Document only. |
| Dangerous-group audit (`audit_groups()`: docker/libvirt/lxd = FAIL, systemd-journal = WARN, any unknown group = WARN) | yes | none (read-only) | Omarchy **already** avoids the docker group (`install/config/docker.sh` comment) | **pacman_integrity** / a new audit role. **Adopt.** |
| polkit: rpm-ostree upgrade without auth only (`usr/share/polkit-1/rules.d/org.projectatomic.rpmostree1.rules`) | n/a (rpm-ostree specific) | n/a | n/a | none |
| faillock (`etc/security/faillock.conf`: `audit`, `deny=50`, `unlock_time=86400`, `even_deny_root`; `authselect enable-feature with-faillock`) | yes | low. Omarchy has `deny=10` (`etc/security/faillock.conf`). `unlock_time=86400` is a 24h lockout and a DoS risk. | partly | **pam_faillock**. Copy `audit` and `even_deny_root`. Keep Omarchy's count with a shorter unlock time. |
| pwquality (`etc/security/pwquality.conf`: minlen 8, all classes, dictcheck, `enforce_for_root`) | yes (`extra/libpwquality`) | low (only for new passwords) | no | **pam_faillock**, or a new pam role. |
| `login.defs`: `UMASK 027`, `YESCRYPT_COST_FACTOR 8` (`files/scripts/hardenlogindefs.patch`) | yes | UMASK 027 is **med** (group-shared dirs, Docker bind mounts, file sharing); yescrypt cost is low | no | Adopt the yescrypt cost. UMASK is optional. |
| Bash environment lockdown (`toggle-bash-environment-lockdown`: `chattr +i` on `~/.bashrc`, `.bash_profile`, `.profile`, `~/.bashrc.d`, `~/.config/environment.d` …; `audit_bash_env_lockdown()` FAILs otherwise) | yes | **high**: Omarchy's installer and migrations edit user dotfiles, and immutable files make migrations fail | no | **agent_containment** idea only. Protect dotfiles from *agents* through the sandbox's write deny-list, not with `chattr`. |
| `/etc/environment` drift audit (`audit_environment_file()` compares against `/usr/share/secureblue/etc/environment`) | yes | none | no | **pacman_integrity**. **Adopt the pattern.** |

### 1k. SELinux-specific items and their AppArmor (or other) equivalents
| secureblue SELinux item (path) | What it does | Arch/AppArmor equivalent | Risk | Aegis role |
|---|---|---|---|---|
| `harden_userns.cil` + `userns_deny_unconfined_relabels.cil` | default-deny userns, allow-list of domains, anti-relabel | see section 2 (no mainline equivalent for unconfined processes) | — | apparmor / agent_containment |
| `harden_container_userns.cil` | deny userns inside containers (podman/distrobox) | Docker's default seccomp profile already blocks `unshare(CLONE_NEWUSER)` in containers (**unverified this session**). AppArmor `docker-default` | low | agent_containment |
| `deny_ptrace` / `container-ptrace.cil` | global ptrace deny | `ptrace_scope=2/3`, AppArmor `deny ptrace` | med | sysctl / apparmor |
| `selinux/sockets/*.cil`: deny AF_ALG for non-bluetooth domains, deny key/xfrm (IPsec), packet radio, obscure families; optional audit of netlink sockets | reduces kernel attack surface per socket family | the module blocklist covers most families. Per-service `RestrictAddressFamilies=`; AppArmor `deny network <family>` in agent/browser profiles. **AF_ALG:** bluez (and iwd, which Omarchy disables) use it, so mirror secureblue's "allow bluetooth only" exception. | low–med | kernel / apparmor / agent_containment |
| `selinux/flatpakfull`, `systemsettings`, `nvidia-container`, `stdmalloc` modules, `check-selinux-fcontext.sh` | domain plumbing | n/a, apart from the wrapper idea | — | — |
| `label-external-drives` | relabel USB for Trivalent | n/a | — | — |

### 1l. Network, DNS, time
| Measure (path) | Portable? | Omarchy risk | Omarchy? | Aegis role |
|---|---|---|---|---|
| DNS: `dnsconfd` plus Unbound (`etc/unbound/conf.d/secureblue.conf`, `unbound.service.d/secureblue.conf` systemd sandbox, `NetworkManager/conf.d/dnsconfd.conf`, `setup-dnsconfd.sh`); `systemd-resolved` disabled (`disableresolved.sh`, preset) | Unbound yes (`extra/unbound 1.26.1`). **dnsconfd is not on Arch** (neither repos nor AUR) | **high** if you swap the resolver: Omarchy's `bin/omarchy-dns` rewrites `/etc/systemd/resolved.conf`, and Docker DNS relies on `etc/systemd/resolved.conf.d/20-docker-dns.conf` (`DNSStubListenerExtra=172.17.0.1`) plus a ufw rule | Omarchy runs resolved with `DNSOverTLS=opportunistic` for Cloudflare/Google presets | **firewall** or a new **dns** role. Keep resolved. |
| DoT global DNS (`dns_selector.py`, `inner/dns.py` → NM `[global-dns] resolve-mode=exclusive`, `servers=dns+tls://…`), provider list `usr/share/secureblue/secure-dns-providers.json` (Control D, Quad9, Mullvad…) | yes (NM global-dns, or a resolved drop-in with `DNSOverTLS=yes`) | med: strict DoT breaks captive portals; VPN DNS leaks (secureblue's own audit FAILs "Unbound + VPN without global DNS") | opportunistic only | dns. Offer `DNSOverTLS=yes` as an option. |
| DNSSEC validation (`/etc/dnsconfd.conf dnssec_enabled: yes`; the audit FAILs when it is off) | yes (resolved `DNSSEC=allow-downgrade`/`yes`) | med (`yes` breaks broken resolvers and some captive/corporate DNS) | no | dns. `allow-downgrade` is low risk. |
| LLMNR off (`etc/systemd/resolved.conf.d/10-disable-llmnr.conf`) | yes | none | **yes** (`10-disable-multicast.conf`, LLMNR=no, MulticastDNS=no) | already done |
| MAC randomization (`ujust toggle-mac-randomization` → `/etc/NetworkManager/conf.d/rand_mac.conf`: `wifi.scan-rand-mac-address=yes`, `ethernet.cloned-mac-address=stable`, `wifi.cloned-mac-address=stable\|random`; audit FAILs if missing) | yes (NM drop-in) | low with `stable`. `random` breaks captive-portal sessions and DHCP reservations. | no (only `omarchy-wifi-powersave.conf`) | new **network_privacy** role (or firewall). **Adopt `stable`.** |
| DHCP hostname sending off (`inner/dhcp_hostname_sending.py` → `ipv4/ipv6.dhcp-send-hostname=0`) | yes | low (router no longer shows the host name) | no | network_privacy. Adopt. |
| IPv6 privacy (`NetworkManager/conf.d/40-secureblue.conf ip6-privacy=2`) | yes | none | no | network_privacy. Adopt. |
| NetworkManager systemd sandbox (`usr/lib/systemd/system/NetworkManager.service.d/40-sandbox.conf`: `ProtectSystem=strict`, `ProtectHome=read-only`, syscall filter, `DeviceAllow=/dev/net/tun`…) and `40-killmode.conf` | yes (drop-in) | **med**: VPN plugins, WireGuard key files under `/etc`, Tailscale interplay, `/proc/sys/net` writes. Needs testing. | no | new **service_sandbox** role. Adopt later with tests. |
| Remove NM VPN plugins (`common-packages.yml` remove list) | yes | low | n/a | — |
| Firewall: firewalld zone `FedoraWorkstation.xml` emptied (no open ports, `<forward/>` only) | n/a (firewalld). The equivalent is ufw default-deny incoming | none | **yes**: ufw default deny in, allow out, LocalSend 53317 tcp/udp, Docker DNS, `ufw-docker` (`install/config/firewall.sh`) | firewall. Already done. |
| NTS time: chrony (`etc/chrony.conf`: 6 NTS servers plus 1 NIST server without NTS, `minsources 3`, `authselectmode prefer`, `cmdport 0`, `noclientlog`, `rtcsync`; `setchronysysconfig.sh -F1 -r` seccomp; `audit_chronyd()`) | yes (`extra/chrony 4.9`) | **med**: Omarchy's `bin/omarchy-update-time` does `sudo systemctl restart systemd-timesyncd`, and `docs/update-process.md` refers to timesyncd. Swapping to chrony makes that command a silent no-op or failure. NTS on UDP 4460 plus TCP 4460 key exchange can be blocked on some networks. | no (timesyncd, no NTS) | new **time_sync** role. Adopt, and provide an `omarchy-update-time` compatible override (`chronyc makestep`). |
| Avahi off (`disableavahidaemon.sh`, preset; `avahi-daemon.service.d/40-secureblue.conf StopWhenUnneeded`) | yes | **med**: Omarchy enables `avahi-daemon` and `nss-mdns` (`install/config/enable-services.sh`) for printer discovery (cups-browsed) and `.local` names | Omarchy enables it | firewall / service role. Optional. |

### 1m. Service disabling (presets: `usr/lib/systemd/system-preset/40-secureblue.preset`, `desktop/.../35-secureblue-desktop.preset`, plus `files/scripts/disable*.sh`, `mask*.sh`)
| Service(s) | Omarchy risk | Omarchy state | Recommendation (new **service_minimization** role) |
|---|---|---|---|
| `bluetooth.service` masked (`maskbluetoothservices.sh`); toggle via `set-bluetooth-modules` | **high** (Bluetooth menu, headsets) | enabled | opt-in only |
| CUPS `cups.socket`/`.service`/`cups-browsed`/`cups.path` masked (`disablecups.sh`); toggle `set-cups` (`set_cups.py`, `inner/cups.py`); `audit_print_services()` | **high** (printing). Omarchy enables cups and sandboxes cups-browsed (`etc/systemd/system/cups-browsed.service.d/10-omarchy.conf`) | enabled | Opt-in. Could switch `cups.service` to socket activation only. |
| sshd and its sockets, `sshd-vsock` disabled | none (Omarchy has an opt-in `omarchy-setup-security-sshd`) | not enabled by default (as far as I can tell) | assert disabled unless opted in |
| `ModemManager`, `geoclue` (plus hiding the demo agent), `iscsid`, `nfs-*`, `rpcbind`, `gssproxy`, `sssd`, `systemd-homed`, `alsa-state`, `tumblerd`, `uresourced`, `low-memory-monitor`, `thermald` | low (`thermald` matters on some Intel laptops for throttling; keep it) | most are not installed on Omarchy | Assert disabled when installed; skip `thermald`. |
| libvirt daemons all disabled (`35-secureblue-libvirt-daemons.preset`, toggle `set-libvirt-daemons`) | low | n/a | — |
| `docker.service`/`docker.socket` disabled by preset | **high**: Omarchy enables `docker.socket` | enabled | do not copy |
| PDF thumbnailers removed (`remove-pdf-thumbnailers.sh`), `audit_thumbnailing()` | low (no PDF previews in Nautilus) | Nautilus may thumbnail | optional (parser attack surface) |
| GNOME JIT off (`etc/profile.d/gnome-disable-jit.sh`: `JavaScriptCoreUseJIT=0`, `GJS_DISABLE_JIT=1`) | none/low (WebKitGTK apps get slower) | no | optional |
| Xwayland disabled per DE (`set_xwayland.py`, `sericea/etc/sway/config.d/99-noxwayland.conf`; `audit_xwayland()`) | **high**: Hyprland `xwayland` is used for Steam, JetBrains, some Electron apps; Omarchy configures it (`default/hypr/envs.lua`, `windows.lua`) | enabled | Do not adopt. Possibly audit-only INFO. |

### 1n. Updates, signing, provenance, firmware
| Measure (path) | Arch analog | Omarchy risk | Omarchy? | Aegis role |
|---|---|---|---|---|
| Signed OS image: `modules/secureblue-signing/policy.json` (`default: reject`, `sigstoreSigned` per registry with pinned keys in `usr/share/pki/containers/*.pub`), `audit_signed_image()` (FAIL on `ostree-unverified-registry`), `securebluecleanup` auto-rebases to signed | pacman `SigLevel = Required DatabaseOptional` plus keyring trust. `policy.json` covers podman/skopeo only, **not Docker** | none for the check-only part | pacman defaults (not re-verified on the target) | **pacman_integrity**: assert SigLevel, no `TrustAll`, no `SigLevel = Never` repos. |
| SLSA provenance: `usr/libexec/secureblue/verify-provenance.sh` (`crane digest` plus `slsa-verifier verify-image --source-uri --source-branch`); `ujust update-system` verifies before updating; Trivalent RPM verified at build | `extra/crane` exists; `slsa-verifier` is AUR only (2.7.1). Useful for agent-tool binaries that ship SLSA provenance (GitHub releases). | none | no | **agent_containment** / **pacman_integrity**: verify downloaded agent CLIs. |
| Container registry key pinning (`etc/containers/registries.d/*.yaml`) | podman only | none | n/a | — |
| HTTPS-only mirrors (`httpsmirrors.sh`) | assert `/etc/pacman.d/mirrorlist` has only `https://` | none | unverified | **pacman_integrity**. **Adopt.** |
| Out-of-date notifier (`securebluecheckoutofdate`, timer: notify if the image is older than 7 days) | parse `/var/log/pacman.log` for the last `-Syu`; notify after N days | none | unknown | **pacman_integrity**. **Adopt.** |
| Firmware checks (`secureblue-firmware-check.timer`, `firmwarecheckoutofdate`, `update_firmware.py`, preset `fwupd-refresh.timer`) | `extra/fwupd` (not checked this session); Omarchy does not list fwupd in its base packages | none | no | new **firmware** role (low priority) |
| Secure Boot: shim/MOK enrollment (`enroll_secure_boot_keys.py`), signed kmods (`signmodules.sh`), UKI with own PK/KEK/db (`uki/*`), `audit_secureboot()`, key-enrollment-verification timer | `extra/sbctl 0.18`, `core/systemd-ukify`; Limine plus UKI already present | med (user firmware interaction; DKMS signing hook needed) | UKI yes; Secure Boot not configured by Omarchy (as far as I found) | new **secure_boot** role, check-only first |
| `libdnf5-clear-history.sh`, `disablecountme.sh` (telemetry) | pacman has no countme | none | n/a | — |
| `podman-auto-update`, flatpak auto-update timers, `upgrade-on-boot.service` | Omarchy controls updates (`omarchy-update`) | med (unattended pacman upgrades are risky on Arch) | no | do not adopt |

### 1o. Misc
- **udev FIDO/U2F rules:** `usr/lib/udev/rules.d/70-u2f.rules`, `70-titan-key.rules`, 232 non-blank lines, `TAG+="uaccess"`. Arch's `libfido2` ships comparable rules (**unverified this session**). Aegis role: **fido2**.
- **LUKS TPM2/FIDO2 unlock helpers:** `usr/libexec/luks-{enable,disable}-{tpm2,fido2}-*.sh`, `ujust setup-luks-fido2-unlock`. They are `systemd-cryptenroll` wrappers. Omarchy's busybox `encrypt` hook does **not** support `systemd-cryptenroll` tokens. You would need the `sd-encrypt` hook, a **high-risk** initramfs change. Aegis role: **fido2**, later.
- **dracut `excludepcsc.sh`:** n/a.
- **NetworkManager `KillMode`:** n/a.
- **Server sshd hardening:** `server/etc/ssh/sshd_config.d/30-hardening.conf`: `MaxAuthTries 3`, no forwarding, `PermitRootLogin no`. Adopt in Omarchy's opt-in `omarchy-setup-security-sshd` path. Aegis role: **firewall**/sshd.
- **`check-local-overrides`:** `diff -r /usr/share/secureblue/etc /etc` with an exclude list. See section 3.

---

## 2. How secureblue handles unprivileged user namespaces vs Flatpak/bwrap

**What secureblue does (from source):**

1. **Default-deny in the policy, not the kernel.** secureblue never sets `user.max_user_namespaces=0` or `kernel.unprivileged_userns_clone`. I grepped `55-hardening.conf` and the whole tree and found no such key. The kernel feature stays on, and SELinux decides *which process domains* may call `unshare(CLONE_NEWUSER)`.
2. **Allow-list by domain** (`harden_userns.cil`):
   - `userns_privileged_domain` = `init_t install_t kernel_t` plus, where the type exists (`optional` blocks): `bubblewrap_domain`, `container_domain`, `container_runtime_domain`, `spc_t`, `flatpak_t`, `flatpak_helper_t`, `passt_t`, `stdmalloc_t`, `systemsettings_t`, `thumb_t`, and `trivalent_domain`/`trivalent_script_domain` (the browser's own sandbox).
   - Every other domain gets `deny … self (user_namespace (create))`, which in practice means the user's `unconfined_t` shell and every app it launches. It also gets a `noatsecure` deny on transitions into privileged domains, so `LD_PRELOAD`-style environment variables are scrubbed when an unprivileged process execs `bwrap`/`flatpak`.
3. **Anti-relabel guard** (`userns_deny_unconfined_relabels.cil`): no domain except `init_t`/`kernel_t`/`install_t` may relabel files to or from `bwrap`/`flatpak`/`container_runtime`/`trivalent` exec types. A user therefore cannot copy an arbitrary binary and label it as `bubblewrap_exec_t` to get userns.
4. **bwrap is not setuid.** `removesuid.sh` strips setuid from everything in `/usr`. bwrap comes from secureblue's COPR rebuild plus `bubblewrap-selinux`, which gives it its own domain. So Flatpak works *because* bwrap is a privileged **domain**, not a setuid binary.
5. **Two runtime toggles:**
   - `ujust set-unconfined-userns on|off`, which disables or enables the `harden_userns` module. The prompt text says this is "e.g. for bubblejail".
   - `ujust set-container-userns`, which toggles `harden_container_userns.cil`: containers cannot nest userns. It is needed for podman rootless and distrobox, and it stops containers first.

   The audit FAILs when unconfined userns is allowed and WARNs when container userns is allowed.

**Why this cannot be copied directly to Arch + AppArmor:**
- **Verified against mainline `security/apparmor/lsm.c` (torvalds master, fetched 2026-10-20).** `apparmor_userns_create()` only mediates when the label is **not unconfined** (`if (!unconfined(label)) …aa_profile_ns_perm(…AA_USERNS_CREATE)`).
- The sysctls registered by mainline are `unprivileged_userns_apparmor_policy`, `apparmor_display_secid_mode` and `apparmor_restrict_unprivileged_unconfined`. **Ubuntu's `kernel.apparmor_restrict_unprivileged_userns` is not in mainline**, and that is the knob that makes unconfined userns default-deny. Arch kernels, and presumably `linux-omarchy` (**unverified**: it is not in the Arch repos and I did not inspect its config), therefore cannot do secureblue-style "deny all, allow bwrap/flatpak/browser".
- On mainline AppArmor you get the *inverse*: **allow by default, deny for the processes you confine** (profiles without a `userns,` rule).
- Global kernel knobs are all-or-nothing:
  - `user.max_user_namespaces=0` (mainline).
  - `kernel.unprivileged_userns_clone=0`, which exists only in `linux-hardened`. Verified in `anthraxx/linux-hardened` `kernel/fork.c`: `if ((clone_flags & CLONE_NEWUSER) && !unprivileged_userns_clone)`. `extra/linux-hardened 7.2.10.hardened1` is available, but switching kernels away from `linux-omarchy` is a large change.
  - A global deny breaks: Flatpak (unless bwrap is setuid; `bubblewrap-suid` is **not** in the Arch repos or the AUR as of the check), Chromium/Electron's namespace sandbox (falls back to the setuid `chrome-sandbox` only where installed setuid. Omarchy's `omarchy-install-hermes-cli` installs `chrome-sandbox` as **0755**, not setuid), Steam's pressure-vessel runtime, rootless Docker/podman, `bubblejail`, and **Claude Code's own Linux sandbox, which uses bubblewrap**. That last one matters for the `agent_containment` role.

**Recommended decision for Aegis (my proposal, for you to decide):**
1. **Keep unprivileged userns enabled globally.** That is what Omarchy, Flatpak, Chromium, Electron, Steam and agent sandboxes need.
2. **Confine the high-risk, untrusted-input processes with AppArmor and leave `userns` out of their profiles.** That covers AI agent CLIs outside their own bwrap sandbox, and possibly LocalSend and document viewers. This is the AppArmor version of secureblue's "restricted domain": it denies userns to the confined process, not to the whole system. Processes that *must* nest a sandbox (the agent's bwrap, browsers) get an explicit `userns,` rule. That is the AppArmor version of secureblue's allow-list.
3. For **agent_containment**, add seccomp or systemd-level denies (`RestrictNamespaces=` on agent services or scopes, or a seccomp filter on `unshare`/`clone3` with `CLONE_NEWUSER`) on processes that do not need nesting. Docker containers already get a default seccomp profile (Docker's blocking of `CLONE_NEWUSER` there is **unverified this session**).
4. **Copy secureblue's toggle-plus-audit UX:** a role variable `aegis_userns_mode: open | confined | hardened_kernel`, plus an audit that reports per mode, e.g. `unshare -U true` as the unprivileged user (PASS/WARN) and `aa-status` listing the confined profiles.
5. **Also copy the `noatsecure` lesson:** whatever path is allowed to create userns should not inherit attacker environment variables. Run `bwrap` and `flatpak` from clean environments, and add `env_reset`-style scrubbing in wrappers.

---

## 3. secureblue's audit (`ujust audit-secureblue`) and what to copy

**How it is built** (`files/system/usr/libexec/secureblue/audit_secureblue.py`, 1,423 lines; framework in `auditor/__init__.py`; flatpak rules in `audit_flatpak/`; i18n under `files/po/`):

- **Checks as generators.** Each check is an `@audit` function that yields `Report(title, Status, notes, recs)`. `Status` is ordered PASS < INFO < WARN < FAIL, with UNKNOWN, and it only moves down through `status.downgrade_to()`, so one function cannot hide a worse result behind a better one.
- **Dependencies and shared state.** `@depends_on("audit_modprobe", "audit_ptrace")` and a `state` dict let later checks reuse facts. Example: the flatpak bluetooth-permission severity depends on whether the bluetooth module actually loaded.
- **Categories and skips.** `@categorize("flatpak", "skip-if-root")`, `--skip a,b` and `~/.config/secureblue/audit.toml` let users silence accepted risks without editing code. `-j/--json` gives one JSON object per check, and CI parses it.
- **CI golden file.** `.github/workflows/integration_tests/expected-audit-silverblue-main-hardened.txt` holds the expected JSON lines for a built image, and `check_audit_results.sh` compares them. That makes the audit itself a regression test of the hardening.
- **The key trick: the audit reads the shipped config as its source of truth.**
  - `audit_sysctl()` parses `/usr/lib/sysctl.d/55-hardening.conf` and compares each key, including globs like `net.ipv4.conf.*.…`, against `/proc/sys/...`.
  - `audit_kargs()` builds the expected set from the same `kargs_hardening.DEFAULT_KARGS` TOML that sets them, with separate WARN severities for the opt-in and unstable sets.
  - `audit_modprobe()` parses the blocklist files and FAILs on any blocked module that **is loaded anyway**, checking runtime state rather than file presence.
  - `audit_environment_file()` and `audit_container_policy()` compare `/etc` files byte for byte with pristine copies in `/usr/share/secureblue/…`. `ujust check-local-overrides` diffs `/usr/share/secureblue/etc` against `/etc`.
- **Remediation in every finding.** Every non-PASS result carries a copy-pasteable fix command, and recommendations are merged across apps (`Recommendation.NAMES_PLACEHOLDER`).
- **Honest limits.** When it is run as root, user-scope checks are skipped and the output says so ("CAUTION: Some checks skipped due to running as root"). Unreadable sysctls become INFO "run as root", not PASS.

**What to copy into Aegis** (`pacman_integrity` check-only plus the verify-after-apply asserts):

1. **Single source of truth.** Generate the asserts from the *same* variable that templates the file: the same `aegis_sysctl` dict, the same `aegis_kargs` list, the same blocklist. Then assert against **runtime** (`/proc/sys`, `/proc/cmdline`, `/proc/modules`), not against the file. A file-presence assert passes on a machine where the setting never applied (for example a sysctl overridden by a later `sysctl.d` file, or a karg missing because the UKI was not rebuilt).
2. **"Blocked but loaded" check.** For every blocklisted module, FAIL if it shows up in `/proc/modules`. This catches initramfs-embedded modules, which is exactly the Omarchy thunderbolt case.
3. **Four-level status plus accepted-risk config.** Map to Ansible as `failed_when` only for FAIL, with WARN/INFO collected into a report fact. Use an `aegis_audit_skip: []` list for accepted risks, and emit JSON lines to `/var/lib/aegis/audit.jsonl` for diffing between runs.
4. **Golden-file CI.** Run the role in a VM or container and compare the JSON audit output with a committed expected file, as secureblue does with `expected-audit-*.txt`.
5. **Pristine-copy drift detection.** Keep a copy of every Aegis-managed `/etc` file under `/usr/share/aegis/` (or compare checksums) and report drift. That is the pacman-world equivalent of `check-local-overrides`. Add `pacman -Qkk` for package-owned files.
6. **Behavioural probes, not only config reads.** secureblue tests userns with `unshare -U true` and `podman unshare true` when it cannot read the policy. Do the same in Aegis: run `unshare -U true` as the user, inside the agent sandbox and outside it.
7. **Check list worth porting:**
   - groups (`docker`/`libvirt`/`wheel`/`systemd-journal` membership)
   - Flatpak remotes (verified subset only) and per-app permission severity table (x11, session-bus, gpg-agent, device=all = FAIL)
   - MAC randomization file present
   - DNS mode (DNSSEC, DoT, VPN-leak combination)
   - time sync service active and not failed (`is-enabled` plus `is-failed`)
   - Secure Boot state
   - ptrace scope
   - USBGuard (as INFO on Omarchy, not FAIL)
   - `/etc/environment` drift
   - last-update age

---

## 4. Ranked top 15 to adopt without breaking Omarchy

Ordered by security value per unit of breakage risk. All are compatible with Hyprland, Docker, Steam, Electron, Bluetooth, printing, suspend and LocalSend as scoped here.

1. **Module blocklist, safe subset** (`install X /bin/false`): obscure network protocols, debug/test modules, legacy hardware, rare filesystems. **Exclude** bluetooth, btusb, thunderbolt, cifs/nfs/sunrpc client, hfsplus, udf, squashfs, IPsec (toggle). Pair it with a "blocked-but-loaded" assert. Role: **kernel**. Source: `usr/lib/modprobe.d/secureblue.conf`.
2. **Kernel/info-leak sysctls:** `kptr_restrict=2`, `dmesg_restrict=1`, `printk=3 3 3 3`, `bpf_jit_harden=2`, `unprivileged_bpf_disabled=1`, `kexec_load_disabled=1`, `ldisc_autoload=0`, `unprivileged_userfaultfd=0`, `perf_event_paranoid=2` (not 3), `oops_limit`/`warn_limit=100`, `sysrq=0`. Role: **sysctl**.
3. **Filesystem and ASLR sysctls:** `protected_regular=2`, `protected_fifos=2`, `protected_hardlinks/symlinks=1`, `suid_dumpable=0`, `mmap_rnd_bits=32`, `mmap_rnd_compat_bits=16`. Role: **sysctl**.
4. **Network sysctls that do not conflict with Omarchy:** syncookies, rfc1337, ICMP broadcast/bogus ignore, no redirects or source routing, `shared_media=0`, `use_tempaddr=2`, `rp_filter=2` (loose). **Leave Omarchy's `arp_ignore=1`/`arp_announce=2` alone.** Role: **sysctl**.
5. **Kernel cmdline, low-risk set** through a Limine drop-in plus UKI rebuild: `init_on_alloc=1`, `init_on_free=1`, `page_alloc.shuffle=1`, `slab_nomerge`, `randomize_kstack_offset=on`, `vsyscall=none`, `vdso32=0`, `random.trust_cpu=off`, `random.trust_bootloader=off`, `systemd.ssh_auto=no`, version-gated `hash_pointers=always` and `proc_mem.force_override=ptrace`. Assert through `/proc/cmdline`. Role: **kernel**.
6. **IOMMU strict DMA protection:** `intel_iommu=on`, `iommu=force`, `iommu.strict=1`, `iommu.passthrough=0`, `amdgpu.iommu_perfopt=0`. This is especially valuable because Thunderbolt stays enabled. Role: **kernel** (test on AMD and Intel and with TB docks).
7. **Audit framework modelled on `audit_secureblue.py`:** single source of truth, runtime comparison, PASS/INFO/WARN/FAIL, JSON lines, skip list, golden-file CI. Role: **pacman_integrity** (check-only) plus every role's verify step.
8. **Coredump hardening that keeps Omarchy crash capture:** `suid_dumpable=0` plus `coredump.conf.d` storage and size limits, *not* `core_pattern=|/bin/false`. First verify that `omarchy-crash-watch` still sees `MESSAGE_ID=fc2e22bc…` entries. Role: **sysctl** (or a new **coredump** role).
9. **MAC randomization (stable), DHCP hostname off, IPv6 privacy in NetworkManager:** `wifi.cloned-mac-address=stable`, `ethernet.cloned-mac-address=stable`, `wifi.scan-rand-mac-address=yes`, `dhcp-send-hostname=0`, `ip6-privacy=2`. New role: **network_privacy**.
10. **Dangerous-group, sudoers-NOPASSWD, setuid-inventory and `/etc/environment` drift audits** (check-only). Omarchy already keeps users out of the docker group, so this guards against regressions. Role: **pacman_integrity**.
11. **pacman supply-chain asserts** (the Arch counterpart of signed-image and HTTPS-mirror checks): `SigLevel` Required, no `Never`/`TrustAll`, HTTPS-only mirrorlist, plus a "last full upgrade older than N days" notifier modelled on `securebluecheckoutofdate`. Role: **pacman_integrity**.
12. **Flatpak, non-invasive part:** add Flathub only as `--subset=verified` (when the user installs Flatpak), a permission-severity audit, and auto-update timers. **Not** the global lockdown and **not** the hardened_malloc preload. Role: **flatpak**.
13. **userns strategy from section 2:** keep it globally enabled. Use AppArmor profiles without `userns` for agents and untrusted-input apps, an explicit `userns,` only where nested sandboxes are needed, plus `RestrictNamespaces` and seccomp in agent units, and a mode variable with a behavioural audit. Roles: **apparmor** and **agent_containment**.
14. **PAM:** faillock `audit` plus `even_deny_root` on top of Omarchy's `deny=10`, but with a short `unlock_time` (not 86400). pwquality for new passwords. `YESCRYPT_COST_FACTOR 8`. Role: **pam_faillock**.
15. **NTS time sync with chrony** (`extra/chrony 4.9`), using secureblue's `chrony.conf` model (`minsources 3`, `authselectmode prefer`, `cmdport 0`, `noclientlog`, `-F1` seccomp). It is **only safe if** Aegis also overrides `omarchy-update-time` (it restarts `systemd-timesyncd`) and masks timesyncd consistently. New role: **time_sync**.

Honourable mentions, opt-in only:
- DoT strict plus DNSSEC `allow-downgrade` as a resolved drop-in. This must coexist with `omarchy-dns`, which rewrites `resolved.conf`, and with the Docker DNS stub.
- `ptrace_scope=2`.
- `io_uring_disabled=1` with a group.
- The NetworkManager systemd sandbox drop-in.
- The sshd hardening drop-in for Omarchy's opt-in sshd.
- Toggles for bluetooth, webcam and CUPS modules and services.
- `mitigations=auto,nosmt`.

**Do not adopt** (they break Omarchy):
- `fs.binfmt_misc.status=0` (Docker cross-arch)
- `core_pattern=|/bin/false` (crash capture)
- `arp_ignore=2`/`arp_filter=1` (dock plus Wi-Fi)
- blocking bluetooth or thunderbolt
- removing sudo and global setuid stripping
- separate-admin-only wheel removal
- bash dotfile `chattr +i`
- Xwayland off
- global `/etc/ld.so.preload` hardened_malloc (the AUR package is stale and `no_rlimit_as` is unpackaged)
- default USBGuard (Omarchy just reverted device approval)
- `lockdown=confidentiality` and `module.sig_enforce=1` before a DKMS signing path exists
- `ia32_emulation=0` with Steam installed
- dnsconfd/Unbound replacing resolved
- disabling `docker.socket`
- dracut-only `rd.*` kargs

---

## 5. Open questions and unverified items

- The `linux-omarchy` kernel config was **not inspected**: `CONFIG_SECURITY_LOCKDOWN_LSM`, the AppArmor in the default `lsm=`, `ARCH_MMAP_RND_BITS_MAX`, the default for `BPF_UNPRIV_DEFAULT_OFF`, and support for `hash_pointers=` and `proc_mem.force_override=`. All karg and sysctl asserts should check the running kernel.
- Whether `systemd-coredump` with `Storage=none` still emits the journal entry `omarchy-crash-watch` uses is **unverified**. Test it.
- Docker's default seccomp blocking of `CLONE_NEWUSER` is **unverified** this session.
- How hardened_malloc behaves with Hyprland and Chromium on Arch, and whether the host `.so` can be injected into Flatpak runtimes, is **unverified**.
- Trivalent's own Chromium policy set lives in another repository and was **not reviewed**.
- fwupd and libfido2 udev rules on Arch were **not fetched**.

## 6. Package availability (fetched 2026-10-20)
Official repos (archlinux.org JSON API):
- `extra/usbguard 1.1.4`
- `extra/chrony 4.9`
- `extra/unbound 1.26.1`
- `extra/apparmor 4.1.8` (5.0.2 in extra-testing)
- `extra/bubblewrap 0.13.1`
- `extra/crane 0.22.1`
- `extra/opensnitch 1.7.2`
- `extra/linux-hardened 7.2.10.hardened1`
- `extra/flatpak 1.18.4`
- `extra/sbctl 0.18`
- `core/systemd-ukify 262.1`
- `extra/firejail 0.9.80`
- `extra/libpwquality 1.4.5`

**Not** in the official repos:
- `hardened_malloc`
- `bubblejail`
- `slsa-verifier`
- `dnsconfd`
- `run0edit`
- `no_rlimit_as`
- `usbguard-notifier`
- `bubblewrap-suid`
- `linux-omarchy` (comes from Omarchy's own repository)

AUR (RPC v5):
- `hardened_malloc 13-1`: modified 2024-10-14, flagged out of date 2026-02-23.
- `hardened-malloc-git 13+r728`: modified 2025-03-11.
- `bubblejail 0.10.4`: modified 2026-08-30.
- `slsa-verifier 2.7.1` and `slsa-verifier-bin`.
- `run0edit 1.2.1`.
- `trivalent-bin 155.0.8059.84`.
- `usbguard-notifier 0.1.1`.
- Not found in the AUR: `dnsconfd`, `no_rlimit_as`, `bubblewrap-suid`.

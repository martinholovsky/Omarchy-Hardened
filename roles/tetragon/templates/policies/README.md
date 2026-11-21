# Tetragon policies (D-37)

Six monitor-only `TracingPolicy` files. Each ends in `Post` (with a 1-minute
rate limit where a hook can repeat); none has `Sigkill`, `Override`,
`Signal` or `NotifyEnforcer`, and the role's read-back refuses any other
action. The audit summarises their events as `tetragon.<name>` findings.

## Where they come from

There is no maintained, production Tetragon rule set to adopt. Checked on
2026-11-20 (details in `docs/research/ebpf-netns-review.md` §9):

- `cilium/tetragon` `examples/policylibrary/` (7 files) and
  `examples/tracingpolicy/` (77): Apache-2.0. Upstream's own README calls
  the latter "samples only" with no "security observability guarantees".
  CI parses all of them but loads only `bpf.yaml` and `tcp-connect.yaml`.
- The v1.8.0 release tarball ships no policies.
- Other public collections are demos, unlicensed, or copies of the examples.
  The best is gccloudone-aurora/tetragon-policies (MIT, 2 stars), which is
  container-scoped.
- Falco's rules (Apache-2.0) cannot be translated mechanically. They served
  as a checklist of techniques only.

So each policy below adapts an upstream example. Every file names its
source at `cilium/tetragon` v1.8.0 (`a5a6678`) and says what was modified,
as Apache-2.0 §4(b) requires. The licence text is the repository's
`LICENSE` (also Apache-2.0); upstream has no NOTICE file to carry.

| Policy | Hook | Watches | ATT&CK | Adapted from |
|---|---|---|---|---|
| `aegis-cred-access` | kprobe `security_file_open` | SSH/age keys, AWS credentials, `/etc/shadow`, GnuPG/pass/gh/docker/kube tokens, keyrings and browser profiles, opened by a program outside each one's allowlist | T1552.004, T1552.001, T1555.003, T1539, T1003.008 | `lsm_file_open.yaml`, `quickstart/file_monitoring.yaml` |
| `aegis-persistence` | kprobe `security_file_permission`, write mask | user units, XDG autostart, Hyprland config, shell startup files, `authorized_keys`, Omarchy shell plugins and `shell.json` (D-38); `/etc/systemd`, `ld.so.preload`, sudoers, PAM, `profile.d` outside pacman | T1543.002, T1546.004, T1547.013, T1098.004, T1574.006, T1548.003, T1556.003, T1547 | `quickstart/file_monitoring.yaml` |
| `aegis-kernel-modules` | kprobes `security_kernel_read_file` (READING_MODULE), `security_kernel_load_data` (LOADING_MODULE) | every module load; the audit WARNs only on modules outside `/usr/lib/modules/` or loaded from memory | T1547.006, T1014, T1620 | `policylibrary/modules.yaml` |
| `aegis-bpf-load` | kprobe `bpf_check` | BPF programs loaded by anything but systemd, Tetragon (and `tetra probe`), OpenSnitch and the container runtimes | T1014, T1562.001 | `policylibrary/bpf.yaml` |
| `aegis-process-injection` | syscall kprobes `ptrace` (ATTACH, SEIZE, POKETEXT, POKEDATA), `process_vm_writev` | one process attaching to or writing into another, outside debuggers | T1055.008, T1055 | `tracingpolicy/sys_ptrace.yaml` |
| `aegis-exec-writable` | kprobe `security_bprm_check` | programs run from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user` or a memfd | T1204.002, T1059, T1620 | `tracingpolicy/security_bprm_check.yaml` |

## Limits

- **Program allowlists match the executed path.** A malicious program at
  an allowed path, such as a replaced `/usr/bin/ssh`, is not reported. Package
  drift (`pacman_integrity`) covers that case.
- **The persistence policy sees `write()` calls.** A file replaced by
  `rename()` of a temporary file is seen through the temporary file's own
  writes, which lie under the same prefix.
- **The audit splits events by time.** Events during the playbook run itself
  (its own writes to `/etc/pam.d` and unit files) are counted apart. So is
  anything else that happens in those minutes. Events from an earlier run
  are skipped only when they fall in that run's recorded window and come
  from an Ansible module (`/AnsiballZ_` in the arguments). A program that
  fakes that name and acts during a run is not reported.
- **One bad policy stops everything.** Tetragon exits at start if any policy
  fails to unmarshal. The role then fails the run (`tetragon.service` not
  active), and the container test checks that every value is a string.
- **Containers are out of scope** for the `/etc` selectors (host mount
  namespace only), because a container's own `/etc` has the same paths.
- **A memfd program has no path in Tetragon's events.** It is caught at
  `execveat(AT_EMPTY_PATH)`, so the event names the program that started
  it, and the target is the hook with the file descriptor.
- **Allowlists come from a fresh VM.** Programs that fired legitimately were
  `systemd-userwork` (shadow), `updatedb` (browser profiles) and `tetra probe` (BPF). Tetragon reports the path a program was started by, so a symlink (`/usr/local/bin/tetra`) is listed as such. A real
  desktop will add more; list them in `aegis_tetragon_known` or in the
  policy.
- **What is not watched:** network behaviour (OpenSnitch and D-25 do that),
  privilege escalation through setuid (too noisy on a desktop without a
  baseline; a later policy), and container workloads.

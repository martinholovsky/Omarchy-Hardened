@AGENTS.md

## Where project data lives

Before creating, moving or deleting project data or memory, place it by this table and follow the
move/delete rules below.

The repo folder is `/Volumes/speedy/Github/Omarchy-Hardened`. `~/Github` is a symlink
to `/Volumes/speedy/Github`, so `~/Github/Omarchy-Hardened` is the same folder (compare
with `stat -f %d:%i` or `realpath`, never by listing or `diff -r`: a folder
compared with itself is "identical"). Time Machine (`iMac-backup`) backs up the
speedy volume, ignored directories included: `tmutil isexcluded` printed
`[Included]` on 2026-11-23 for the repo folder, `evidence/`, `.claude-memory/`,
`tests/vm/.state/`, the VM folder, the ISO folder and `~/.claude`. So anything in
the repo folder survives a reboot, a move of the disk to another Mac, and a disk
failure. `/private/tmp` and the session scratchpad do not. Audited 2026-11-23.
Sizes and counts are from that day.

| Tier | What | Where in this project | Rule |
|---|---|---|---|
| 1 Tracked | Code, docs, test data, small reference results | `roles/`, `docs/`, `tests/` (fixtures in `tests/fixtures/`), `tests/vm/iso.lock` (ISO SHA-256), `requirements.yml`, `uv.lock` | Anything a doc, commit, handoff or committed result cites lives here, or its exact regenerate command sits beside the citation. Upstream Omarchy files are cited at a pinned commit (`docs/upstream-baseline.md`): regenerate with `git clone https://github.com/basecamp/omarchy && git -C omarchy checkout <commit>`. The research repos in `docs/research/*.md` are pinned the same way |
| 2 Local-durable | In the repo, git-ignored, **never deleted** | `tests/vm/.state/` (61 files, 7.7 MB: the VM's only SSH key `id_ed25519`, `become-password` which is also the VM's LUKS and root password, `known_hosts`, every VM run log and screenshot). `.claude-memory/` (Claude memory, 6 files; excluded in `.git/info/exclude`; sessions write there through `autoMemoryDirectory`, see below). `evidence/` (68 MB on 2026-11-24): `scratchpads/<session>/` (8 sessions, 1294 files: 1275 copied from 7 earlier session scratchpads on 2026-11-23, the rest this session's logs and probes) and `automem-test/` (the `autoMemoryDirectory` probe note). `.claude/settings.local.json` (`autoMemoryDirectory` and local permissions; excluded in `.git/info/exclude`) | Losing `tests/vm/.state/` locks you out of every VM snapshot. New evidence goes in `evidence/` (or in `tests/vm/.state/` for VM runs). Add new directories only under `evidence/`, `runs/` or `results/`, and ignore them in `.gitignore` |
| 3 Rebuildable | In the repo, git-ignored, delete freely | `.venv/` (87 MB): `uv sync --frozen`. `.collections/` (27 MB): `uv run --frozen ansible-galaxy collection install -r requirements.yml`. `.ansible/` (empty; ansible-lint creates it). `.mypy_cache/`, `.ruff_cache/`, `__pycache__/`: the tools rebuild them. `tests/container/.out/`: `run.sh` deletes and recreates it on every run | No secrets here, short-lived tokens included (this project has none). No gate or test may depend on a file here. The container test copies only what git would commit into the container (`tests/container/inside.sh`). The `.venv` interpreter lives in `~/.local/share/uv/python` on the internal disk, so after a move run `rm -rf .venv && uv sync --frozen` |
| 4 Ephemeral | Throwaway only | The session scratchpad `/Volumes/speedy/scratch/claude/claude-501/-Volumes-speedy-Github-Omarchy-Hardened/<session>/`, `/tmp`, `$TMPDIR` | Cleanup removes it, even though it is on speedy. Never cite a path here in a doc, commit or result file. Before a session ends, copy anything worth keeping into tier 1 or 2 (`evidence/scratchpads/<session>/`) |
| 5 Outside by design | On speedy, not in the repo | `/Volumes/speedy/VirtualBox/images/aegis-omarchy/` (the test VM: `.vbox`, disks, `Snapshots/`, 15 GB; snapshots `pre-aegis` > `pre-aegis-updated` > `pre-aegis-hw` and `pre-aegis-450`). `/Volumes/speedy/VirtualBox/iso/omarchy-4.0.6.iso` (+ `.sig`, `.sha256`, which matches `tests/vm/iso.lock`). `/Volumes/speedy/VirtualBox/extpack/Oracle_VirtualBox_Extension_Pack-7.2.22.vbox-extpack` (+ `.sha256`, computed locally and not checked against Oracle's list) | The VM cannot be rebuilt as it is: the snapshots hold an install, an enrolled YubiKey (`pre-aegis-hw`) and a 4.5.0 update. Its passwords are in tier 2. Podman holds nothing to archive: the container test pulls `archlinux` by digest (`tests/container/run.sh`), removes its container on exit and creates no volumes |

No tool in this project writes input paths into a result file: the VM tests
write their logs to `tests/vm/.state/` (resolved from the script's own
location), and the container test writes to `tests/container/.out/`. VM logs
from before 2026-11-23 name the Mac's home directory, through a `preflight` bug
fixed that day (CHANGELOG).

### Machine-bound (lost when speedy moves to another Mac)

- `~/.claude/hooks/memory-guard.py` (a PreToolUse hook in `~/.claude/settings.json` that asks
  before any `rm`/`mv`/`rmdir`/`unlink`/`ln` touching a memory folder) and
  `~/.claude/prompts/where-project-data-lives.md` (the setup prompt behind this section), and the
  "Where project data lives" pointer section in `~/.claude/CLAUDE.md` that sends every session there.
- `~/.claude/projects/-Volumes-speedy-Github-Omarchy-Hardened/` (session transcripts)
  and the `memory` symlinks in that key and in
  `~/.claude/projects/-Users-martinholovsky-Github-Omarchy-Hardened/`. The memory itself is
  in `.claude-memory/` (tier 2). Sessions find it through `autoMemoryDirectory` in
  `.claude/settings.local.json`, which travels with the repo folder; the two symlinks are a
  fallback for a session that does not read that setting.
- VirtualBox: the VM registration in `~/Library/VirtualBox/VirtualBox.xml` and the
  default machine folder setting. The extension pack is installed on this Mac but the
  test does not need it (docs/operating-notes.md §6); its copy on speedy is optional.
- Podman machine registration (`~/.config/containers`, `~/.local/share/containers`).
- uv's managed Pythons (`~/.local/share/uv/python`), which `.venv` points at.
- `~/.ssh`, `gh auth` (pushes and PRs), and the `~/Github` symlink. No CLI keys under
  `~/.config/<cli>`: this project uses none (searched 2026-11-24).
- The YubiKey used by `pre-aegis-hw` is hardware and moves with you.

### Setup on a new Mac

```bash
ln -s /Volumes/speedy/Github ~/Github
# VirtualBox 7.2.22 (the version the VM was made with), then:
VBoxManage setproperty machinefolder /Volumes/speedy/VirtualBox/images
VBoxManage registervm /Volumes/speedy/VirtualBox/images/aegis-omarchy/aegis-omarchy.vbox
VBoxManage snapshot aegis-omarchy list        # expect pre-aegis-450 among them
# ~/.claude/hooks/memory-guard.py, ~/.claude/prompts/, the hook entry in ~/.claude/settings.json
# and the pointer section in ~/.claude/CLAUDE.md:
# restore from Time Machine (~/.claude was [Included], 2026-11-23); check with
# `python3 ~/.claude/hooks/memory-guard.py --selftest`
# Claude memory: .claude/settings.local.json (in the repo folder) already sets autoMemoryDirectory;
# the symlinks are the fallback
for k in -Volumes-speedy-Github-Omarchy-Hardened -Users-martinholovsky-Github-Omarchy-Hardened; do
  mkdir -p ~/.claude/projects/$k && ln -s /Volumes/speedy/Github/Omarchy-Hardened/.claude-memory ~/.claude/projects/$k/memory
done
cd ~/Github/Omarchy-Hardened
rm -rf .venv && uv sync --frozen
uv run --frozen ansible-galaxy collection install -r requirements.yml
podman machine init && podman machine start   # any machine; the test image is pulled by digest
gh auth login
```

Then run the checks in AGENTS.md ("Verify a change").

### Moving, deleting and restoring

- Before any `mv`, `cp`, `ln` or `rm`, run `ls -ld --` and `readlink --` on the
  source and the destination. A path that should not exist may already be a
  symlink, and `mv src link-to-dir` moves `src` into the link's target.
- `~/.claude/projects/` entries start with `-`: write them as `./-name` or after
  `--`, or `ls`, `readlink` and `rm` read them as options and do nothing.
- Copy, `diff -r`, count the files, list the copy through every path that should
  see it, and only then remove the original, one checked step per command. Never
  gate a destructive step on `[ ... ] && [ ... ]` under `set -e`.
- In Claude Code sessions `grep` is a shell function that runs ugrep with
  `--ignore-files -I`: it skips files a `.gitignore` inside the searched tree
  ignores, and binaries. Call `/usr/bin/grep` for an absence claim (`xargs grep`
  already runs the binary).
- To restore, browse Time Machine in Finder (Cmd+Shift+. shows hidden folders).
  Mounting a local snapshot with `mount_apfs` was refused without `sudo` and
  restored nothing with it (contextips-redteam, 2026-11-23). After a restore, list
  the folder before trusting it.

### How sessions find the memory (tested 2026-11-23, Claude Code 2.1.331)

`.claude/settings.local.json` sets `"autoMemoryDirectory":
"/Volumes/speedy/Github/Omarchy-Hardened/.claude-memory"`. Claude Code documents the setting as
ignored in the checked-in `.claude/settings.json`; in `settings.local.json` it is honoured. Tested
with headless `claude -p` sessions:
- pointed at an empty test folder, a new session wrote its probe note there (1 file; the real
  memory stayed at 6; the note is kept in `evidence/automem-test/`);
- without the setting, a session reported the default key path
  `~/.claude/projects/-Volumes-speedy-Github-Omarchy-Hardened/memory/` (the symlink);
- with it, sessions started from `/Volumes/speedy/Github/Omarchy-Hardened` and from
  `~/Github/Omarchy-Hardened` both reported `.claude-memory/`.

Unverified: an interactive session. The binary has a message that a folder declaring this setting
"changes where automatic memory is written", which may ask you to trust the folder once. If a
session declines or ignores it, the symlinks still lead to the same folder. Check any time with
`claude -p --model haiku -- 'Print MEMDIR= and the absolute path of your memory directory from your
instructions.'`

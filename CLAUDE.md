@AGENTS.md

## Where project data lives

The repo folder is `/Volumes/speedy/Github/Omarchy-Hardened`. `~/Github` is a symlink
to `/Volumes/speedy/Github`, so `~/Github/Omarchy-Hardened` is the same folder (compare
with `stat -f %d:%i`, not by the path). Time Machine backs up the whole speedy
volume, ignored directories included. So anything in the repo folder survives a
reboot, a move of the disk to another Mac, and a disk failure. `/private/tmp` and the
session scratchpad do not. Audited 2026-11-23. Sizes and counts are from that day.

| Tier | What | Where in this project | Rule |
|---|---|---|---|
| 1 Tracked | Code, docs, test data, small reference results | `roles/`, `docs/`, `tests/` (fixtures in `tests/fixtures/`), `tests/vm/iso.lock` (ISO SHA-256), `requirements.yml`, `uv.lock` | Anything a doc, commit, handoff or committed result cites lives here, or its exact regenerate command sits beside the citation. Upstream Omarchy files are cited at a pinned commit (`docs/upstream-baseline.md`): regenerate with `git clone https://github.com/basecamp/omarchy && git -C omarchy checkout <commit>`. The research repos in `docs/research/*.md` are pinned the same way |
| 2 Local-durable | In the repo, git-ignored, **never deleted** | `tests/vm/.state/` (61 files, 7.7 MB: the VM's only SSH key `id_ed25519`, `become-password` which is also the VM's LUKS and root password, `known_hosts`, every VM run log and screenshot). `.claude-memory/` (Claude memory, 6 files; excluded in `.git/info/exclude`). `evidence/scratchpads/<session>/` (1275 files, 68 MB, copied from 7 earlier session scratchpads on 2026-11-23). `.claude/settings.local.json` | Losing `tests/vm/.state/` locks you out of every VM snapshot. New evidence goes in `evidence/` (or in `tests/vm/.state/` for VM runs). Add new directories only under `evidence/`, `runs/` or `results/`, and ignore them in `.gitignore` |
| 3 Rebuildable | In the repo, git-ignored, delete freely | `.venv/` (87 MB): `uv sync --frozen`. `.collections/` (27 MB): `uv run --frozen ansible-galaxy collection install -r requirements.yml`. `.ansible/` (empty; ansible-lint creates it). `.mypy_cache/`, `.ruff_cache/`, `__pycache__/`: the tools rebuild them. `tests/container/.out/`: `run.sh` deletes and recreates it on every run | No long-lived secrets here. No gate or test may depend on a file here. The container test copies only what git would commit into the container (`tests/container/inside.sh`). The `.venv` interpreter lives in `~/.local/share/uv/python` on the internal disk, so after a move run `rm -rf .venv && uv sync --frozen` |
| 4 Ephemeral | Throwaway only | The session scratchpad `/Volumes/speedy/scratch/claude/claude-501/-Volumes-speedy-Github-Omarchy-Hardened/<session>/`, `/tmp`, `$TMPDIR` | Cleanup removes it, even though it is on speedy. Before a session ends, copy anything worth keeping into tier 1 or 2 (`evidence/scratchpads/<session>/`) |
| 5 Outside by design | On speedy, not in the repo | `/Volumes/speedy/VirtualBox/images/aegis-omarchy/` (the test VM: `.vbox`, disks, `Snapshots/`, 15 GB; snapshots `pre-aegis` > `pre-aegis-updated` > `pre-aegis-hw` and `pre-aegis-450`). `/Volumes/speedy/VirtualBox/iso/omarchy-4.0.6.iso` (+ `.sig`, `.sha256`, which matches `tests/vm/iso.lock`). `/Volumes/speedy/VirtualBox/extpack/Oracle_VirtualBox_Extension_Pack-7.2.22.vbox-extpack` (+ `.sha256`, computed locally and not checked against Oracle's list) | The VM cannot be rebuilt as it is: the snapshots hold an install, an enrolled YubiKey (`pre-aegis-hw`) and a 4.5.0 update. Its passwords are in tier 2. Podman holds nothing to archive: the container test pulls `archlinux` by digest (`tests/container/run.sh`), removes its container on exit and creates no volumes |

### Machine-bound (lost when speedy moves to another Mac)

- `~/.claude/projects/-Volumes-speedy-Github-Omarchy-Hardened/` (session transcripts)
  and the `memory` symlinks in that key and in
  `~/.claude/projects/-Users-martinholovsky-Github-Omarchy-Hardened/`. The memory itself is
  in `.claude-memory/` (tier 2).
- VirtualBox: the VM registration in `~/Library/VirtualBox/VirtualBox.xml` and the
  default machine folder setting. The extension pack is installed on this Mac but the
  test does not need it (docs/operating-notes.md §6); its copy on speedy is optional.
- Podman machine registration (`~/.config/containers`, `~/.local/share/containers`).
- uv's managed Pythons (`~/.local/share/uv/python`), which `.venv` points at.
- `~/.ssh`, `gh auth` (pushes and PRs), and the `~/Github` symlink.
- The YubiKey used by `pre-aegis-hw` is hardware and moves with you.

### Setup on a new Mac

```bash
ln -s /Volumes/speedy/Github ~/Github
# VirtualBox 7.2.22 (the version the VM was made with), then:
VBoxManage setproperty machinefolder /Volumes/speedy/VirtualBox/images
VBoxManage registervm /Volumes/speedy/VirtualBox/images/aegis-omarchy/aegis-omarchy.vbox
VBoxManage snapshot aegis-omarchy list        # expect pre-aegis-450 among them
# Claude memory: both path keys point at the repo copy
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

# Product Requirements Document (PRD)
**Project Name:** Project Aegis (Hardened Omarchy/Arch Baseline)
**Objective:** To retrofit an Omarchy/Arch Linux installation with extreme defense-in-depth, achieving a security posture comparable to Secureblue or Sécurix, while retaining the curated Hyprland UI and agentic developer workflows.

## 1. Executive Summary
Omarchy provides a highly productive, opinionated developer environment but sacrifices endpoint security for convenience (e.g., weakened PAM, unsandboxed plugins, mainline kernel). Project Aegis defines the technical requirements to secure this environment against local privilege escalation, memory corruption, supply chain compromises, and AI prompt injection, targeting developers in high-threat environments.

## 2. Goals & Non-Goals
### Goals
*   Implement kernel, memory, and filesystem hardening comparable to Fedora Atomic/Secureblue.
*   Isolate the AI agent and community plugin ecosystem to prevent system compromise via prompt injection or malicious code execution.
*   Enforce strict, zero-trust network boundaries.
*   Automate the deployment of these configurations via Infrastructure-as-Code (Ansible) to bypass Omarchy's lack of root-level plugin support.

### Non-Goals
*   Upstreaming these changes to the official Omarchy repositories (due to fundamental philosophical differences with the upstream maintainers).
*   Building a completely new Linux distribution from scratch.

## 3. Technical Requirements

### 3.1 Kernel & Memory Hardening (P0)
*   **Kernel Replacement:** Replace the mainline Arch kernel with `linux-hardened` to implement exploit mitigation patchsets.
*   **Memory Allocation:** Replace the standard glibc allocator with a secure allocator (e.g., GrapheneOS `hardened_malloc` or `scudo`) to neutralize heap overflows and use-after-free vulnerabilities.
*   **Sysctl Lockdown:** Apply a strict `/etc/sysctl.d/99-hardened.conf` to enforce:
    *   `kernel.dmesg_restrict=1` (Restrict kernel log access).
    *   `kernel.kptr_restrict=2` (Hide kernel pointers).
    *   `kernel.kexec_load_disabled=1` (Prevent kernel replacement).
    *   `kernel.yama.ptrace_scope=1` (Restrict cross-process memory inspection).
    *   Disable unprivileged user namespaces where possible.

### 3.2 Authentication & Access Control (P0)
*   **PAM Remediation:** Revert Omarchy's relaxed `faillock` settings. Enforce a maximum of 3 failed login attempts (`deny = 3`) and a 15-minute lockout (`unlock_time = 900`).
*   **Hardware-Backed Identity:** Require physical FIDO2/YubiKey presence for LUKS full-disk decryption at boot and for all `sudo` privilege escalations.

### 3.3 Application, Plugin & Agent Isolation (P1)
*   **Mandatory Access Control (MAC):** Deploy and enforce strict AppArmor profiles for all network-facing applications (browsers, chat clients).
*   **Application Sandboxing:** Transition user application installations from AUR/pacman to Flatpak with strict Bubblewrap sandbox constraints.
*   **Plugin UI Isolation:** Omarchy QML plugins must not run with arbitrary host access. High-risk components should be evaluated for IPC bridging.
*   **AI Agent Containment:** 
    *   Agents must operate within a Distrobox container or strict sandbox.
    *   Require explicit user confirmation prompts before the agent executes any shell command modifying the filesystem or network state.
    *   **Cryptographic Verification:** Enforce GPG/SSH commit signing so compromised agents cannot silently push malicious code to developer repositories.

### 3.4 Network & Zero-Trust Architecture (P1)
*   **Inbound Protection (UFW):** Enable a strict default-deny incoming firewall policy. Explicitly remove Omarchy’s default allowances for Port 22 (SSH) and Port 53317 (LocalSend).
*   **Outbound Interception:** Install `OpenSnitch` to intercept and manually verify every outbound network connection attempt by the OS, plugins, and AI agents.
*   **Overlay Networks:** Bind sensitive services (like SSH) exclusively to encrypted overlay networks (Tailscale/WireGuard) to remain invisible on local untrusted networks.

### 3.5 Supply Chain & Update Security (P2)
*   **Mitigate `curl | sh`:** Ban the use of raw script piping for system updates or tooling installation.
*   **Update Verification:** Ensure update mechanisms respect The Update Framework (TUF) threat models, preventing indefinite freeze attacks and rollback attacks (e.g., relying on strict APT/Pacman signature verification and validating mirror freshness).
*   **Delivery Mechanism:** The hardening suite must be delivered as a standalone Ansible Playbook (`omarchy-harden.yml`) run locally, rather than an Omarchy plugin, to maintain strict separation of security tooling from unsandboxed UI widgets.

### 3.6 Immutability & State Management (P3 - Aspirational)
*   Evaluate migrating the root filesystem to a read-only architecture (A/B partitioning via OSTree or systemd-sysupdate) or adopting an Ephemeral Root (Impermanence via `tmpfs` mounting) to guarantee rootkit destruction upon reboot.

## 4. Delivery Strategy
Since modifying Omarchy directly via plugins is insecure, this project will be distributed as an open-source Ansible Playbook. Users will run the default Omarchy installer, clone the Aegis repository, and execute the playbook to bring the system into compliance with the PRD.

# Annexes

This is a project management script integrated with my personal Tmux and pentest workflows. It is public primarily to serve as a reference for others looking to grab code snippets or workflow ideas.

This is not a general purpose tool. It is hardcoded to my specific file structures and preferences. Do not run this blindly. Review the code and adapt the functions to fit your own environment.

## Overview

The script acts as a central manager for engagement/project directories. It handles:

- **Project Management:** Creates consistent directory structures (logs, loot, assets) and manages a `~/current` symlink for quick navigation.
- **Tmux Integration:** Automates session creation, window layouts, and capturing pane history to log files.
- **Pentest Automation:** Wrappers for standard tasks like IP logging, file serving, and triggered scanning (nmap, nuclei, feroxbuster).

## Shell Environment

This is written in Bash for system level efficiency but is used daily within a Zsh environment. Depending on your shell configuration, minor adjustments may be required.

## Dependencies

The script relies on the following tools to function correctly. Without them, specific functions will fail.

- **Core:** `tmux`, `zip`, `python3`
- **System:** `sudo`, `ip` (iproute2)
- **Visual:** `flameshot`
- **Recon:** `nmap`, `feroxbuster`, `nuclei`, `enum4linux-ng`
- **Resources:** `seclists` (Expects `/usr/share/seclists` for wordlists)
- **Editors:** `typora` or `vnote` (Optional, used for the `edit` function)

## Usage

Check the script source for implementation details. The primary dispatcher handles the following:

- `init / box`: Project generation
- `link / list`: Symlink management
- `shot`: Screenshot with automatic markdown linking
- `tmux`: Session and layout management
- `scan`: Automated nmap/web/smb reconnaissance

```bash
Usage:
  annexes init [--force] [--no-relink] <name>    Create project and point ~/current to it
  annexes box  [--force] [--no-relink] <name>    Create project with engagment files and point ~/current to it
  annexes link <name>                            Point ~/current to existing project
  annexes list                                   List projects (mark current with *)
  annexes edit                                   Open project in GUI editor (Typora/VNote)
  annexes shot                                   Flameshot to ~/current/screens
  annexes host <ip> <hostname>                   Adds and edits /etc/hosts file
  annexes archive                                Archives the current project
  annexes scan [-u] <ip>                         Deep nmap scan with triggered Nuclie, AD and Feroxbuster scans 

Tmux Helpers:
  annexes tmux                                   Launches pre-configured layout for standard engagement
  annexes cap                                    Save current pane visible text to logs (strips color)
  annexes hist                                   Save entire pane scrollback to logs (strips color)

Pentest Helpers:
  annexes ip                                     Print IP of tun0 (useful for payloads)
  annexes serve [port]                           Start HTTP server in current projects /tmp
  annexes scope <ip/range>                       Add target to scope.txt
  annexes note <text>                            Quickly append line to notes.md
  annexes scan [-u] <ip>                         Deep nmap scan with triggered nuclie, enum4linux and feroxbuster scans

Options:
  -f, --force     Reuse existing directory if it already exists
  --no-relink     Create project but do not modify ~/current
  -u              Performs an additional --top 100 UDP scan
```


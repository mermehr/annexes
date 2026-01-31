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
- **Recon:** `grc`, `nmap`, `feroxbuster`, `nuclei`, `enum4linux-ng`
- **Resources:** `seclists` (Expects `/usr/share/seclists` for wordlists)
- **Editors:** `typora`

## Usage

Check the script source for implementation details.

```bash
Usage:
  init [--force] [--no-relink] <name>     Create standard project
  ctf  [--force] [--no-relink] <name>     Create CTF-style project
  link <name>                             Link existing project to ~/current
  list                                    List projects (* = current)
  edit                                    Open current project in editor
  shot                                    Flameshot → assets/ + link in notes.md
  archive                                 Zip current project → archive/
  ip                                      Show VPN IP (tun0 fallback eth0)
  host <ip> <hostname>                    Add/update /etc/hosts entry
  serve [port]                            Python HTTP server in ./tmp
  scope <ip/range>                        Append to scope.txt
  note <text>                             Append timestamped line to notes.md
  tmux                                    Launch pre-configured tmux layout
  cap                                     Save visible pane to logs/
  hist                                    Save full scrollback to logs/
  scan [-u] <ip>                          Deep nmap + smart follow-ups
  rdp <ip> <user> <pass>                  Quick xfreerdp with dynamic res

Options:
  --force      Reuse existing directory
  --no-relink  Create project without changing ~/current
  -u           Add top-1000 UDP scan (with scan command)
```

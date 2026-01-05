#!/usr/bin/env bash
# What you read is what you get
# ~/bin/anx
# Projects in /opt/annexes/<name>
# Active symlink at ~/current
# Screenshots to ~/current/screens
# Scan logs to ~/current/logs

set -euo pipefail

BASE="/opt/annexes"
LINK="$HOME/current"
VPN_IFACE="tun0"

mkdir -p "$BASE"

usage() {
  cat <<'EOF'
                           _
                          / \   _ __  _ __   _____  _____  ___
                         / _ \ | '_ \| '_ \ / _ \ \/ / _ \/ __|
                        / ___ \| | | | | | |  __/>  <  __/\__ \
                       /_/   \_\_| |_|_| |_|\___/_/\_\___||___/


Usage:
  annexes init [--force] [--no-relink] <name>    Create project and point ~/current to it
  annexes box  [--force] [--no-relink] <name>    Create project with engagment files and point ~/current to it
  annexes link <name>                            Point ~/current to existing project
  annexes list                                   List projects (mark current with *)
  annexes edit                                   Open project in GUI editor (Typora/VNote)
  annexes shot                                   Flameshot to ~/current/screens
  annexes host <ip> <hostname>                   Adds and edits /etc/hosts file
  annexes archive                                Archives the current project

Tmux Helpers:
  annexes tmux                                   Launches pre-configured layout for standard engagement
  annexes cap                                    Save current pane visible text to logs (strips color)
  annexes hist                                   Save entire pane scrollback to logs (strips color)

Pentest Helpers:
  annexes ip                                     Print IP of tun0 (useful for payloads)
  annexes serve [port]                           Start HTTP server in current project's /tmp
  annexes scope <ip/range>                       Add target to scope.txt
  annexes note <text>                            Quickly append line to notes.md
  annexes scan [-u] <ip>                         Deep nmap scan will trigger prompts for further scans

Options (init):
  -f, --force     Reuse existing directory if it already exists
  --no-relink     Create project but do not modify ~/current
  -u              Performs an additional --top 100 UDP scan
EOF
}

# ---- helpers ----

safe_link() {
  local target="$1" link="$2"
  if [[ -e "$link" && ! -L "$link" ]]; then
    echo "[!] $link exists and is NOT a symlink. Move/rename it first." >&2
    exit 1
  fi
  ln -sfn "$target" "$link"
}

mkfile_if_absent() {
  local path="$1" content="${2:-}"
  if [[ ! -e "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    printf "%s" "$content" > "$path"
  fi
}

require_active() {
  if [[ ! -L "$LINK" ]]; then
    echo "[!] No active project (~/current). Use init/link."
    exit 1
  fi
}

ensure_tmux() {
  if [[ -z "${TMUX:-}" ]]; then
    echo "[!] This command requires running inside tmux." >&2
    exit 1
  fi
}

strip_colors() {
  # regex to strip ANSI color codes
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"
}

# --- commands ----

init_project() {
  local force=0 norelink=0 name=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f|--force) force=1; shift ;;
      --no-relink) norelink=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) name="$1"; shift ;;
    esac
  done

  [[ -z "${name:-}" ]] && { echo "[!] Project name required"; exit 1; }

  local proj="$BASE/$name"

  if [[ -d "$proj" ]]; then
    if (( force==0 )); then
      echo "[!] $proj already exists. Use --force to reuse." >&2
      exit 1
    fi
  else
    # Initial dirs
    mkdir -p "$proj"/{logs,assets,tmp,loot}
  fi
  # Initial files for standard proj
  mkfile_if_absent "$proj/notes.md"  "## Notes - $name"
  mkfile_if_absent "$proj/scope.txt" ""
  mkfile_if_absent "$proj/logs/commands.log" ""

  if (( norelink==0 )); then
    safe_link "$proj" "$LINK"
    echo "[+] Project ready: $proj"
    echo "[+] Symlink set:  $LINK -> $proj"
  else
    echo "[+] Project created: $proj (not relinked)"
  fi
}

init_box() {
  # Same as init_project just with different files
  local force=0 norelink=0 name=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f|--force) force=1; shift ;;
      --no-relink) norelink=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) name="$1"; shift ;;
    esac
  done

  [[ -z "${name:-}" ]] && { echo "[!] Project name required"; exit 1; }

  local proj="$BASE/$name"

  if [[ -d "$proj" ]]; then
    if (( force==0 )); then
      echo "[!] $proj already exists. Use --force to reuse." >&2
      exit 1
    fi
  else
    # Initial dirs
    mkdir -p "$proj"/{logs,assets,tmp,loot}
  fi
  # Initial files for standard box
  mkfile_if_absent "$proj/notes.md"  "## Notes"
  mkfile_if_absent "$proj/Overview.md"  "## Overview"
  mkfile_if_absent "$proj/Enum.md"  "## Enumeration"
  mkfile_if_absent "$proj/Services.md"  "## Service Discovery"
  mkfile_if_absent "$proj/Foothold.md"  "## Foothold"
  mkfile_if_absent "$proj/Privsec.md"  "## Privilege Escalation"
  mkfile_if_absent "$proj/Post.md"  "## Post Exploit and Appendix"
  mkfile_if_absent "$proj/scope.txt" ""
  mkfile_if_absent "$proj/logs/commands.log" ""

  if (( norelink==0 )); then
    safe_link "$proj" "$LINK"
    echo "[+] Project ready: $proj"
    echo "[+] Symlink set:  $LINK -> $proj"
  else
    echo "[+] Project created: $proj (not relinked)"
  fi
}

link_project() {
  # Checks if $proj exists and links it ro ~/current
  local name="${1:-}"
  [[ -z "$name" ]] && { echo "[!] Project name required"; exit 1; }
  local proj="$BASE/$name"
  [[ -d "$proj" ]] || { echo "[!] $proj does not exist"; exit 1; }
  safe_link "$proj" "$LINK"
  echo "[+] Symlink set: $LINK -> $proj"
}

list_projects() {
  # Lists $proj and highlights * current
  shopt -s nullglob
  for d in "$BASE"/*; do
    [[ -d "$d" ]] || continue
    local mark=""
    if [[ -L "$LINK" && "$(readlink -f "$LINK")" == "$(readlink -f "$d")" ]]; then
      mark=" *"
    fi
    echo "$(basename "$d")$mark"
  done
}

take_screenshot() {
  # Takes a selectable screenshot and dumps it in project folder w/markdown link
  require_active
  command -v flameshot >/dev/null || { echo "[!] flameshot not installed"; exit 1; }

  local proj dir file relpath
  proj="$(readlink -f "$LINK")"
  dir="$proj/assets"
  mkdir -p "$dir"
  file="$dir/$(date +%Y%m%d-%H%M%S).png"

  flameshot gui -p "$file" || { echo "[!] flameshot canceled"; return; }

  relpath="assets/$(basename "$file")"
  echo -e "\n![screenshot]($relpath)" >> "$proj/notes.md"
  echo "[+] Screenshot saved: $file"
  echo "[+] Linked in: $proj/notes.md"
}

edit_project() {
  # Set this to quick open the $proj in your flavour of editors
  require_active
  local proj
  proj="$(readlink -f "$LINK")"

  if command -v typora &>/dev/null; then
      echo "[+] Opening $proj in Typora..."
      typora "$proj" &>/dev/null &
  elif command -v vnote &>/dev/null; then
      echo "[+] Opening $proj in VNote..."
      vnote "$proj" &>/dev/null &
  else
      echo "[!] No GUI editor found."
  fi
}

archive_project() {
  # Warning with this function, this is highly recomended to edit as it can destroy data
  # Also will depend on how you manage your data ie: I use VNote and like archived backups
  require_active

  # Check for zip dependency
  if ! command -v zip &>/dev/null; then
      echo "[!] 'zip' command not found. Please install it."
      exit 1
  fi

  local proj
  proj="$(readlink -f "$LINK")"
  local name
  name="$(basename "$proj")"

  local vnote_root="$HOME/vnote/pentest"
  local archive_dir="$BASE/archive"
  local timestamp
  timestamp=$(date +%Y%m%d)

  # Safety check: ensure destination doesn't already exist in VNote
  if [[ -d "$vnote_root/$name" ]]; then
      echo "[!] Archive failed: $vnote_root/$name already exists."
      exit 1
  fi

  mkdir -p "$vnote_root"
  mkdir -p "$archive_dir"

  # Create the Zip Backup
  echo "[*] Zipping project to $archive_dir..."
  if (cd "$BASE" && zip -r -q "$archive_dir/${name}_${timestamp}.zip" "$name"); then
      echo "[+] Backup created: $archive_dir/${name}_${timestamp}.zip"
  else
      echo "[!] Zip failed. Aborting archive to prevent data loss."
      exit 1
  fi

  # Move to VNote
  echo "[*] Moving $name to VNote..."
  mv "$proj" "$vnote_root/"

  # Remove the symlink since the source is gone
  rm "$LINK"
  echo "[+] Moved to $vnote_root/$name. Run 'VNote' to rescan."
}

# --- Tmux Functions ---

tmux_htb() {
  # Customizable tmux session helper
  require_active
  local session="pen"

  # Check if session exists
  if tmux has-session -t "$session" 2>/dev/null; then
    if [[ -n "${TMUX:-}" ]]; then
        tmux switch-client -t "$session"
    else
        tmux attach -t "$session"
    fi
    return
  fi

  # Create detached session, explicitly naming window 'htb'
  tmux new-session -d -s "$session" -n "main" -c "$HOME/current"

  # Target window by NAME 'pen' (safe for base-index 0 or 1)
  # tmux split-window -v -t "${session}:htb" -c "$HOME/current"

  tmux new-window -d -t "${session}:" -n "scans" -c "$HOME/current"

  tmux select-window -t "${session}:main"
  tmux select-pane   -t "${session}:main.1"

  if [[ -n "${TMUX:-}" ]]; then
      tmux switch-client -t "$session"
  else
      tmux attach -t "$session"
  fi
}

tmux_cap_screen() {
  # Captures terminal screen and dumps it to file
  require_active
  ensure_tmux

  local proj
  proj="$(readlink -f "$LINK")"
  local timestamp
  timestamp=$(date +%Y%m%d-%H%M%S)
  local outfile="$proj/logs/${timestamp}_screen.log"

  # -p: print to stdout
  tmux capture-pane -p | strip_colors > "$outfile"

  echo "[+] Screen text captured to: $outfile"
}

tmux_cap_hist() {
  # Captures scrollback buffer and dumps it to file
  require_active
  ensure_tmux

  local proj
  proj="$(readlink -f "$LINK")"
  local timestamp
  timestamp=$(date +%Y%m%d-%H%M%S)
  local outfile="$proj/logs/${timestamp}_history.log"

  # -S - : start from the very beginning of history
  tmux capture-pane -p -S - | strip_colors > "$outfile"

  echo "[+] Full history captured to: $outfile"
}

# --- Pentest Functions ---

get_ip() {
  # Gets vpn interface ip, cleaner than "ip -a" or "ifconfig tun0"
  local ip
  ip=$(ip -4 addr show "$VPN_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
  if [[ -z "$ip" ]]; then
     ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "127.0.0.1")
     echo "[!] $VPN_IFACE not found, using alternative: $ip" >&2
  fi
  echo "$ip"
}

host_add() {
  # Manages the host file, will detect, add, update or remove entries
    if [ "$#" -ne 2 ]; then
        echo "Usage: annexes host <IP> <HOSTNAME>"
        return 1
    fi
    local ip=$1
    local hostname=$2
    local hosts_file="/etc/hosts"

    if grep -q "[[:space:]]$hostname" "$hosts_file"; then
        echo "[-] Removing existing entry for $hostname..."
        sudo sed -i "/[[:space:]]$hostname/d" "$hosts_file"
    fi

    if grep -q "^$ip[[:space:]]" "$hosts_file"; then
        echo "[+] IP $ip found. Appending $hostname..."
        sudo sed -i "/^$ip[[:space:]]/ s/$/ $hostname/" "$hosts_file"
    else
        echo "[+] IP $ip not found. Creating new entry..."
        echo "$ip $hostname" | sudo tee -a "$hosts_file" > /dev/null
    fi
    grep "^$ip" "$hosts_file"
}

serve_files() {
  # Starts a python http.server in ./tmp/
  require_active
  local port="${1:-8000}"
  local proj
  proj="$(readlink -f "$LINK")"
  local serve_dir="$proj/tmp"
  mkdir -p "$serve_dir"
  echo "[+] Serving $serve_dir on port $port"
  echo "[+] URL: http://$(get_ip):$port/"
  (cd "$serve_dir" && python3 -m http.server "$port")
}

add_scope() {
  # Quick add to scope
  require_active
  local item="${1:-}"
  [[ -z "$item" ]] && { echo "[!] Target IP/Range required"; exit 1; }
  local proj
  proj="$(readlink -f "$LINK")"
  echo "$item" >> "$proj/scope.txt"
  echo "[+] Added to scope: $item"
}

quick_note() {
  # Quick note with timestamp
  require_active
  local note="${*:-}"
  [[ -z "$note" ]] && { echo "[!] Note text required"; exit 1; }
  local proj
  proj="$(readlink -f "$LINK")"
  local timestamp
  timestamp=$(date "+%H:%M")
  echo -e "\n- **$timestamp**: $note" >> "$proj/notes.md"
  echo "[+] Note added."
}

# --- Recon Functions ---

scan_target() {
  require_active
  local udp=0
  local ip=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--udp) udp=1; shift ;;
      *) ip="$1"; shift ;;
    esac
  done

  [[ -z "$ip" ]] && { echo "[!] Target IP required"; exit 1; }

  local proj
  proj="$(readlink -f "$LINK")"
  local nmap_dir="$proj/nmap"
  mkdir -p "$nmap_dir"

  # --- Tmux Setup ---
  local sess
  sess=$(tmux display-message -p '#S')

  if ! tmux list-windows -t "${sess}:" | grep -q "scans"; then
      tmux new-window -t "${sess}:" -n "scans" -c "$proj"
      echo "[+] Created 'scans' window for background tasks."
  fi

  # Target the 'scans' window explicitly
  local target_win="${sess}:scans"

  # --- UDP Scan ---
  if (( udp == 1 )); then
      echo "[*] UDP Scan requested. Prompting for sudo..."
      tmux split-window -t "$target_win" -c "$proj" \
        "echo '[*] Starting UDP Top 100...'; sudo nmap -Pn -n -sU --top-ports 100 -v -oA '$nmap_dir/udp_top100' '$ip'; echo '[+] UDP Done'; read"
      tmux select-layout -t "$target_win" tiled
  fi

  # --- TCP Fast Scan ---
  echo "[*] Starting Fast TCP Scan on $ip..."
  nmap -Pn -n -T4 --min-rate 1000 -p- -oG "$nmap_dir/all_ports.gnmap" "$ip" > /dev/null

  local ports
  ports=$(cat "$nmap_dir/all_ports.gnmap" | grep "Ports:" | awk -F 'Ports: ' '{print $2}' | tr ',' '\n' | awk '/open/ {print $1}' | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//')

  if [[ -z "$ports" ]]; then
    echo "[!] No open TCP ports found."
    return
  fi

  echo "[+] Open TCP Ports: $ports"

  # --- TCP Deep Scan ---
  echo "[*] Starting Version/Script Scan on active ports..."
  nmap -Pn -n -sC -sV -v -p "$ports" -oA "$nmap_dir/detailed" "$ip"

  # --- Automatic Action ---

  # Web Check
  if [[ ",$ports," =~ ,(80|443|8080|8000|3000|5000), ]]; then
      echo "[+] Web detected!"
      read -p "[?] Run wafw00f to check for firewalls? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          echo "[*] Running wafw00f..."
          wafw00f "http://$ip" || echo "[!] wafw00f failed or not installed"
      fi

      read -p "[?] Run aggressive HTTP scans (Feroxbuster/Nuclei)? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          echo "[+] Spawning Ferox & Nuclei in 'scans' window..."
          tmux split-window -t "$target_win" -c "$proj" \
            "feroxbuster -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -o $proj/logs/ferox.txt; read"
          tmux split-window -t "$target_win" -c "$proj" \
            "nuclei -u http://$ip -o $proj/logs/nuclei.txt; read"
      else
          echo "[-] Skipping HTTP scans."
      fi
  fi

  # SMB Check
  if [[ ",$ports," == *",445,"* ]]; then
      echo "[+] SMB detected!"
      read -p "[?] Run Enum4linux? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          echo "[+] Spawning Enum4linux in 'scans' window..."
          tmux split-window -t "$target_win" -c "$proj" \
            "enum4linux-ng -A $ip | tee $proj/logs/smb_enum.txt; read"
      else
          echo "[-] Skipping SMB scan."
      fi
  fi

  tmux select-layout -t "$target_win" tiled
}

# --- dispatcher -----

cmd="${1:-}";
shift || true
case "$cmd" in
  init) init_project "$@" ;;
  box)  init_box "$@" ;;
  link) link_project "$@" ;;
  list) list_projects ;;
  edit) edit_project ;;
  archive) archive_project ;;
  shot) take_screenshot ;;
  host) host_add "$@" ;;
  ip)   get_ip ;;
  serve) serve_files "$@" ;;
  scope) add_scope "$@" ;;
  note) quick_note "$@" ;;
  tmux) tmux_htb "$@" ;;
  cap)  tmux_cap_screen ;;
  hist) tmux_cap_hist ;;
  scan) scan_target "$@" ;;
  -h|--help|"") usage ;;
  *) echo "[!] Unknown command: $cmd"; usage; exit 1 ;;
esac

#!/usr/bin/env bash
# Personal bash project manager and ctf assistant

set -euo pipefail

BASE="$HOME/Documents/projects"
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
  init [--force] [--no-relink] <name>    Create project and point ~/current to it
  ctf  [--force] [--no-relink] <name>    Create project with ctf files and point ~/current to it
  link <name>                            Point ~/current to existing project
  list                                   List projects (mark current with *)
  edit                                   Open project in GUI editor (Typora/VNote)
  shot                                   Flameshot to ~/current/screens
  host <ip> <hostname>                   Adds and edits /etc/hosts file
  archive                                Archives the current project

Tmux Helpers:
  tmux                                   Launches pre-configured layout for standard engagement
  cap                                    Save current pane visible text to logs (strips color)
  hist                                   Save entire pane scrollback to logs (strips color)

Pentest Helpers:
  ip                                     Print IP of tun0 (useful for payloads)
  rpd <IP> <user> <pass>                 Quick xfreerdp connection with /dynamic-resolution
  serve [port]                           Python HTTP server in current project's /tmp
  scope <ip/range>                       Add target to scope.txt
  note <text>                            Quickly append line to notes.md
  scan [-u] <ip>                         Deep nmap scan will trigger prompts for further scans

Options:
  [init] -f, --force     Reuse existing directory if it already exists
  [init] --no-relink     Create project but do not modify ~/current
  [scan] -u              Performs an additional --top 100 UDP scan
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

_init_generic() {
  local mode="$1"
  shift
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

  # Common files
  mkfile_if_absent "$proj/scope.txt" ""
  mkfile_if_absent "$proj/logs/commands.log" ""

  if [[ "$mode" == "ctf" ]]; then
    mkfile_if_absent "$proj/notes.md"  "# Notes"
    mkfile_if_absent "$proj/Overview.md"  "# Overview"
    mkfile_if_absent "$proj/Enum.md"  "# Enumeration"
    mkfile_if_absent "$proj/Services.md"  "# Service Discovery"
    mkfile_if_absent "$proj/Foothold.md"  "# Foothold"
    mkfile_if_absent "$proj/Privsec.md"  "# Privilege Escalation"
    mkfile_if_absent "$proj/Post.md"  "# Post Exploit and Appendix"
  else
    mkfile_if_absent "$proj/notes.md"  "## Notes - $name"
  fi

  if (( norelink==0 )); then
    safe_link "$proj" "$LINK"
    echo "[+] Project ready: $proj"
    echo "[+] Symlink set:  $LINK -> $proj"
  else
    echo "[+] Project created: $proj (not relinked)"
  fi
}

init_project() {
  _init_generic "standard" "$@"
}

init_ctf() {
  _init_generic "ctf" "$@"
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

tmux_pen() {
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
      echo "Usage: host <IP> <HOSTNAME>"
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

xfree_rdp() {
  # Quick and dirty RDP
  command -v xfreerdp >/dev/null || { echo "[!] xfreerdp not installed"; exit 1; }
  if [ "$#" -ne 3 ]; then
      echo "Usage: <IP> <user> <pass>"
      return 1
  fi
  xfreerdp /v:"$1" /u:"$2" /p:"$3" /dynamic-resolution
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

  local target_url="http://$ip"
  local redirect_url=""
  if [[ -f "$nmap_dir/detailed.nmap" ]]; then
      redirect_url=$(grep -oP 'Did not follow redirect to \Khttps?://[^/\s]+' "$nmap_dir/detailed.nmap" | head -n 1 || true)
  fi

  if [[ -n "$redirect_url" ]]; then
      local clean_host="${redirect_url#*://}"
      local hostname="${clean_host%%:*}"

      echo "[!] Detected redirect to URL: $redirect_url"
      read -p "[?] Add $ip $hostname to /etc/hosts? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          host_add "$ip" "$hostname"
          target_url="$redirect_url"
      fi
  fi

  # --- Prompt Actions ---

  # Web Check
  if [[ ",$ports," =~ ,(80|443|8080|8000|3000|5000), ]]; then
      echo "[+] Web detected!"
      read -p "[?] Run wafw00f to check for firewalls? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          echo "[*] Running wafw00f..."
          wafw00f "$target_url" || echo "[!] wafw00f failed or not installed"
      fi

      read -p "[?] Run aggressive HTTP scans (Feroxbuster/Nuclei)? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          echo "[+] Spawning Ferox & Nuclei in 'scans' window..."
          tmux split-window -t "$target_win" -c "$proj" \
            "feroxbuster -u $target_url -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -o $proj/logs/ferox.txt; read"
          tmux split-window -t "$target_win" -c "$proj" \
            "nuclei -u $target_url -o $proj/logs/nuclei.txt; read"
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
  ctf)  init_ctf "$@" ;;
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
  tmux) tmux_pen "$@" ;;
  cap)  tmux_cap_screen ;;
  hist) tmux_cap_hist ;;
  scan) scan_target "$@" ;;
  rdp) xfree_rdp "$@" ;;
  -h|--help|"") usage ;;
  *) echo "[!] Unknown command: $cmd"; usage; exit 1 ;;
esac

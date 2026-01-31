#!/usr/bin/env bash
# Personal bash project manager + CTF / pentest assistant

set -euo pipefail

# ---- Config ----

BASE_DIR="${HOME}/Documents/projects"
CURRENT_LINK="${HOME}/current"
VPN_INTERFACE="tun0"
ARCHIVE_DIR="${BASE_DIR}/archive"
DEFAULT_HTTP_PORT=8000

SCREENSHOT_TOOL="flameshot"
PREFERRED_EDITOR="typora"           # fallback: vnote, code, etc.
NMAP_BASE_OPTS="-Pn -n -v --reason --stats-every 10s"

mkdir -p "$BASE_DIR" "$ARCHIVE_DIR"

# ---- Output Helpers ----

red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

msg_ok()    { echo "${green}[+]${reset} $*" ; }
msg_info()  { echo "${yellow}[*]${reset} $*" ; }
msg_err()   { echo "${red}[!]${reset} $*" >&2 ; }

# ---- Usage ----

usage() {
  cat <<'EOF'
Personal Project / CTF / Pentest Manager

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
EOF
}

# ---- Helper Functions ----

safe_link() {
  local target="$1" link="$2"
  if [[ -e "$link" && ! -L "$link" ]]; then
    msg_err "$link exists and is not a symlink. Move/rename it first."
    exit 1
  fi
  ln -sfn "$target" "$link"
  msg_ok "Symlink updated: $link → $target"
}

ensure_file() {
  local path="$1" default_content="${2:-}"
  [[ -e "$path" ]] && return
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$default_content" > "$path"
}

require_current_project() {
  if [[ ! -L "$CURRENT_LINK" ]]; then
    msg_err "No active project (~/current not a symlink). Use init or link."
    exit 1
  fi
  CURRENT_PROJECT="$(readlink -f "$CURRENT_LINK")"
}

ensure_in_tmux() {
  if [[ -z "${TMUX:-}" ]]; then
    msg_err "This command must be run inside tmux."
    exit 1
  fi
}

strip_ansi() {
  sed -r 's/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g'
}

get_vpn_ip() {
  local ip
  ip=$(ip -4 addr show "$VPN_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
  if [[ -z "$ip" ]]; then
    ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "127.0.0.1")
    msg_err "$VPN_INTERFACE not found → fallback: $ip"
  fi
  echo "$ip"
}

# ---- Project Management ----

init_generic() {
  local mode="$1" ; shift   # "standard" or "ctf"
  local force=0 norelink=0 name=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f|--force)     force=1    ; shift ;;
      --no-relink)    norelink=1 ; shift ;;
      -h|--help)      usage ; exit 0 ;;
      *)              name="$1"  ; shift ;;
    esac
  done

  [[ -z "$name" ]] && { msg_err "Project name required"; exit 1; }

  local proj="$BASE_DIR/$name"

  if [[ -d "$proj" ]]; then
    (( force )) || { msg_err "$proj already exists. Use --force"; exit 1; }
  else
    mkdir -p "$proj"/{logs,assets,tmp,loot,nmap}
  fi

  # Common structure
  ensure_file "$proj/scope.txt"
  ensure_file "$proj/logs/commands.log"

  if [[ "$mode" == "ctf" ]]; then
    ensure_file "$proj/notes.md"          "# Notes"
    ensure_file "$proj/Overview.md"       "# Overview"
    ensure_file "$proj/Enum.md"           "# Enumeration"
    ensure_file "$proj/Services.md"       "# Service Discovery"
    ensure_file "$proj/Foothold.md"       "# Foothold"
    ensure_file "$proj/Privsec.md"        "# Privilege Escalation"
    ensure_file "$proj/Post.md"           "# Post Exploitation & Appendix"
  else
    ensure_file "$proj/notes.md"          "## Notes - $name"
  fi

  if (( norelink == 0 )); then
    safe_link "$proj" "$CURRENT_LINK"
    msg_ok "Project ready → $proj"
  else
    msg_ok "Project created (no symlink change) → $proj"
  fi
}

init_project()  { init_generic "standard" "$@"; }
init_ctf()      { init_generic "ctf"     "$@"; }

link_project() {
  local name="${1:-}"
  [[ -z "$name" ]] && { msg_err "Project name required"; exit 1; }
  local proj="$BASE_DIR/$name"
  [[ -d "$proj" ]] || { msg_err "$proj does not exist"; exit 1; }
  safe_link "$proj" "$CURRENT_LINK"
}

list_projects() {
  shopt -s nullglob
  for d in "$BASE_DIR"/*; do
    [[ -d "$d" ]] || continue
    local mark=""
    if [[ -L "$CURRENT_LINK" ]] && [[ "$(readlink -f "$CURRENT_LINK")" == "$(readlink -f "$d")" ]]; then
      mark=" *"
    fi
    echo "$(basename "$d")$mark"
  done
}

archive_project() {
  require_current_project
  command -v zip >/dev/null 2>&1 || { msg_err "'zip' not found – install it"; exit 1; }

  local name="$(basename "$CURRENT_PROJECT")"
  local ts=$(date +%Y%m%d)
  local zipfile="$ARCHIVE_DIR/${name}_${ts}.zip"

  msg_info "Creating archive → $zipfile"
  if (cd "$BASE_DIR" && zip -r -q "$zipfile" "$name"); then
    msg_ok "Archive created: $zipfile"
  else
    msg_err "Zip failed – aborting"
    exit 1
  fi
}

# ---- Editors and Screenshots

open_editor() {
  require_current_project
  if command -v "$PREFERRED_EDITOR" &>/dev/null; then
    msg_ok "Opening in $PREFERRED_EDITOR..."
    "$PREFERRED_EDITOR" "$CURRENT_LINK" &>/dev/null &
  elif command -v vnote &>/dev/null; then
    msg_ok "Opening in VNote..."
    vnote "$CURRENT_PROJECT" &>/dev/null &
  else
    msg_err "No supported GUI editor found"
  fi
}

take_screenshot() {
  require_current_project
  command -v "$SCREENSHOT_TOOL" >/dev/null || { msg_err "$SCREENSHOT_TOOL not installed"; exit 1; }

  local dir="$CURRENT_PROJECT/assets"
  mkdir -p "$dir"
  local file="$dir/$(date +%Y%m%d-%H%M%S).png"
  local rel="assets/$(basename "$file")"

  "$SCREENSHOT_TOOL" gui -p "$file" || { msg_info "Flameshot canceled"; return; }

  echo -e "\n![screenshot]($rel)" >> "$CURRENT_PROJECT/notes.md"
  msg_ok "Screenshot saved → $file"
  msg_ok "Linked in notes.md"
}

# ---- Tmux Helpers ----

launch_tmux_session() {
  require_current_project
  local session="pentest"

  if tmux has-session -t "$session" 2>/dev/null; then
    if [[ -n "${TMUX:-}" ]]; then
      tmux switch-client -t "$session"
    else
      tmux attach -t "$session"
    fi
    return
  fi

  tmux new-session -d -s "$session" -n "main" -c "$CURRENT_PROJECT"
  tmux new-window -d -t "$session:" -n "scans" -c "$CURRENT_PROJECT"
  tmux new-window -d -t "$session:" -n "vpn" -c "~/Downloads"
  tmux select-window -t "$session:main"

  if [[ -n "${TMUX:-}" ]]; then
    tmux switch-client -t "$session"
  else
    tmux attach -t "$session"
  fi
}

capture_pane() {
  require_current_project
  ensure_in_tmux
  local ts=$(date +%Y%m%d-%H%M%S)
  local out="$CURRENT_PROJECT/logs/${ts}_pane.log"
  tmux capture-pane -p | strip_ansi > "$out"
  msg_ok "Pane captured → $out"
}

capture_history() {
  require_current_project
  ensure_in_tmux
  local ts=$(date +%Y%m%d-%H%M%S)
  local out="$CURRENT_PROJECT/logs/${ts}_history.log"
  tmux capture-pane -p -S - | strip_ansi > "$out"
  msg_ok "Full history captured → $out"
}

# ---- Quick Commands ----

add_host_entry() {
  if [[ $# -ne 2 ]]; then
    echo "Usage: host <ip> <hostname>"
    return 1
  fi
  local ip="$1" hostname="$2" hosts="/etc/hosts"

  if grep -q "[[:space:]]$hostname" "$hosts"; then
    msg_info "Removing old entry for $hostname"
    sudo sed -i "/[[:space:]]$hostname/d" "$hosts"
  fi

  if grep -q "^$ip[[:space:]]" "$hosts"; then
    msg_info "Appending $hostname to existing $ip line"
    sudo sed -i "/^$ip[[:space:]]/ s/$/ $hostname/" "$hosts"
  else
    msg_info "Adding new entry"
    echo "$ip $hostname" | sudo tee -a "$hosts" >/dev/null
  fi
  grep "^$ip" "$hosts"
}

start_http_server() {
  require_current_project
  local port="${1:-$DEFAULT_HTTP_PORT}"
  local srv_dir="$CURRENT_PROJECT/tmp"
  mkdir -p "$srv_dir"
  msg_ok "Serving $srv_dir on http://$(get_vpn_ip):$port/"
  (cd "$srv_dir" && python3 -m http.server "$port")
}

add_scope_item() {
  require_current_project
  local item="${1:-}"
  [[ -z "$item" ]] && { msg_err "IP/range required"; exit 1; }
  echo "$item" >> "$CURRENT_PROJECT/scope.txt"
  msg_ok "Added to scope.txt → $item"
}

quick_note() {
  require_current_project
  local text="${*:-}"
  [[ -z "$text" ]] && { msg_err "Note text required"; exit 1; }
  local ts=$(date +"%H:%M")
  echo -e "\n- **$ts**: $text" >> "$CURRENT_PROJECT/notes.md"
  msg_ok "Note added"
}

quick_rdp() {
  command -v xfreerdp3 >/dev/null 2>&1 || { msg_err "xfreerdp not found"; exit 1; }
  [[ $# -ne 3 ]] && { echo "Usage: rdp <ip> <user> <pass>"; exit 1; }
  xfreerdp3 /v:"$1" /u:"$2" /p:"$3" /dynamic-resolution +auto-reconnect
}

# --- Recon Functions ---

scan_target() {
  require_current_project
  local udp=0
  local ip=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--udp) udp=1; shift ;;
      *) ip="$1"; shift ;;
    esac
  done

  [[ -z "$ip" ]] && { msg_err "Target IP required"; exit 1; }

  local proj
  proj="$(readlink -f "$CURRENT_LINK")"
  # local log_dir="$proj/anx_scan/$ip"
  local log_dir="$proj/anx_scan/$ip"
  mkdir -p "$log_dir"

  # --- Tmux Setup ---
  local sess
  sess=$(tmux display-message -p '#S')

  if ! tmux list-windows -t "${sess}:" | grep -q "scans"; then
      tmux new-window -t "${sess}:" -n "scans" -c "$proj"
      msg_ok "Created 'scans' window for background tasks."
  fi

  # Target the 'scans' window explicitly
  local target_win="${sess}:scans"

  # --- TCP Fast Scan ---
  msg_info "Starting Fast TCP Scan on $ip..."
  grc nmap -Pn -n -T4 --min-rate 1000 -p- -oG "$log_dir/all_ports.gnmap" "$ip" > /dev/null

  local ports
  ports=$(cat "$log_dir/all_ports.gnmap" | grep "Ports:" | awk -F 'Ports: ' '{print $2}' | tr ',' '\n' | awk '/open/ {print $1}' | awk -F '/' '{print $1}' | tr '\n' ',' | sed 's/,$//')

  if [[ -z "$ports" ]]; then
    msg_err "No open TCP ports found."
    return
  fi

  msg_ok "Open TCP Ports: $ports"

  # --- TCP Deep Scan ---
  msg_info "Starting Version/Script Scan on active ports..."
  grc nmap -Pn -n -sC -sV -T4 -p "$ports" -oA "$log_dir/detailed" "$ip"

  local target_url="http://$ip"
  local redirect_url=""
  if [[ -f "$log_dir/detailed.nmap" ]]; then
      redirect_url=$(grep -oP 'Did not follow redirect to \Khttps?://[^/\s]+' "$log_dir/detailed.nmap" | head -n 1 || true)
  fi

  if [[ -n "$redirect_url" ]]; then
      local clean_host="${redirect_url#*://}"
      local hostname="${clean_host%%:*}"

      msg_info "Detected redirect to URL: $redirect_url"
      read -p "[?] Add $ip $hostname to /etc/hosts? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          add_host_entry "$ip" "$hostname"
          target_url="$redirect_url"
      fi
  fi

  # --- Prompt Actions ---

  # Web Check
  if [[ ",$ports," =~ ,(80|443), ]]; then
      msg_ok "Web detected!"
      read -p "[?] Run wafw00f to check for firewalls? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          msg_info "Running wafw00f..."
          wafw00f "$target_url" || msg_err "wafw00f failed or not installed"
      fi

      read -p "[?] Run aggressive HTTP scans (Feroxbuster/Nuclei)? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          msg_ok "Spawning Ferox & Nuclei in 'scans' window..."
          tmux split-window -t "$target_win" -c "$proj" \
            "feroxbuster -u $target_url -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -o $log_dir/ferox.txt"
          tmux split-window -t "$target_win" -c "$proj" \
            "nuclei -u $target_url -o $log_dir/nuclei.txt"
      else
          msg_info "Skipping HTTP scans."
      fi
  fi

  # ---- SMB Check ----
  if [[ ",$ports," == *",445,"* ]]; then
      msg_ok "SMB detected!"
      read -p "[?] Run Enum4linux? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
          msg_ok "Spawning Enum4linux in 'scans' window..."
          tmux split-window -t "$target_win" -c "$proj" \
            "enum4linux-ng -A $ip | tee $log_dir/smb_enum.txt"
      else
          msg_info "Skipping SMB scan."
      fi
  fi
  
  # --- UDP Scan ---
  if (( udp == 1 )); then
      msg_info "UDP Scan requested. Prompting for sudo..."
      msg_info '[*] Starting UDP Top 1000...'
      sudo grc nmap -Pn -sU --top-ports 1000 -v -oA "$log_dir/udp_top1000" "$ip"
      msg_ok '[+] UDP Done'
  fi

  # tmux select-layout -t "$target_win" tiled
}

# ---- Dispatcher ----

main() {
  local cmd="${1:-}"
  shift || true

  case "$cmd" in
    init)     init_project  "$@" ;;
    ctf)      init_ctf      "$@" ;;
    link)     link_project  "$@" ;;
    list)     list_projects     ;;
    edit)     open_editor       ;;
    shot)     take_screenshot   ;;
    archive)  archive_project   ;;
    ip)       get_vpn_ip        ;;
    host)     add_host_entry "$@" ;;
    serve)    start_http_server "$@" ;;
    scope)    add_scope_item "$@" ;;
    note)     quick_note    "$@" ;;
    tmux)     launch_tmux_session ;;
    cap)      capture_pane      ;;
    hist)     capture_history   ;;
    rdp)      quick_rdp     "$@" ;;
    scan)     scan_target "$@" ;;
    -h|--help|"") usage ;;
    *) msg_err "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
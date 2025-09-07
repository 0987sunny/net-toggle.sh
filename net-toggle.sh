#!/usr/bin/env zsh
# tor-toggle — start/stop/status for system Tor (zsh)
# on     : start/enable tor.service (re-exec with sudo only for this)
# off    : stop tor.service (re-exec with sudo only for this)
# status : read-only overview with Tor exit check + Tor network speed (no sudo)

set -Eeuo pipefail
IFS=$'\n\t'

: ${COLUMNS:=80}
: ${TOR_DL_URL:=https://speed.hetzner.de/100MB.bin}  # large enough; we stop at ~5s
: ${TOR_UL_URL:=https://speed.hetzner.de/upload.php} # accepts POST bodies
: ${TOR_TEST_SECS:=5}                                 # target duration for each leg

# -------- Runtime/state dir (root vs user) --------
if [[ $EUID -eq 0 ]]; then
  STATE_DIR="/run/tor-toggle"
else
  STATE_DIR="${XDG_RUNTIME_DIR:-/run/user/$UID}/tor-toggle"
fi
ensure_state_dir() {
  mkdir -p "$STATE_DIR" 2>/dev/null || true
  [[ $EUID -eq 0 ]] && chmod 700 "$STATE_DIR" || true
}

# -------- UI helpers --------
autoload -Uz colors && colors || true
: ${TERM:="xterm-256color"}

ok()   { print -P "%F{green}[✓]%f $*"; }
warn() { print -P "%F{yellow}[!]%f $*"; }
err()  { print -P "%F{red}[✗]%f $*" >&2; }
info() { print -P "%F{cyan}[*]%f $*"; }

banner(){
  local h="$(hostname -s 2>/dev/null || echo archcrypt)"
  local d="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  local w="${COLUMNS:-80}"
  local msg="tor-toggle — ${h} — ${d}"
  local pad=$(( (w - ${#msg}) / 2 )); (( pad < 0 )) && pad=0
  print -P "%F{magenta}=====================================================%f"
  print -P "%F{yellow}$(printf "%*s%s" "$pad" "" "$msg")%f"
  print -P "%F{magenta}=====================================================%f"
}

step(){ local msg="$1"; shift; if "$@" &>/tmp/.tortoggle.step.log; then ok "$msg"; else warn "$msg (non-fatal)"; return 1; fi }

# -------- Small helpers --------
tor_active(){ systemctl is-active --quiet tor; }
tor_enabled(){ systemctl is-enabled --quiet tor 2>/dev/null; }
socks_listening(){ ss -lnH 'sport = :9050' 2>/dev/null | grep -q .; }
listening(){ ss -lnH "sport = :$1" 2>/dev/null | awk '{print "    "$1,$4}'; }
proxy_env_summary(){
  local p="none"
  [[ -n "${http_proxy:-}${HTTP_PROXY:-}${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}" ]] && p="env-proxy"
  printf "    %-18s %s\n" "Proxy env" "$p"
}
tor_check(){
  if ! command -v curl &>/dev/null; then
    printf "    %-18s %s\n" "Tor check" "curl not installed"
    return
  fi
  local out
  out=$(timeout 8s curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null) || true
  if [[ -z "$out" ]]; then
    printf "    %-18s %s\n" "Tor check" "no response"
    return
  fi
  local is_tor ip
  is_tor=$(printf "%s" "$out" | grep -o '"IsTor":[^,]*' | grep -q true && echo true || echo false)
  ip=$(printf "%s" "$out" | grep -o '"IP":"[^"]*"' | cut -d\" -f4)
  printf "    %-18s %s (IP: %s)\n" "Tor check" "$is_tor" "${ip:-?}"
}

# ---- Tor network speed (5s download + 5s upload via SOCKS) ----
# Returns "dl|ul" in Mb/s (one decimal) or empty on failure.
_tor_speed_5s(){
  command -v curl &>/dev/null || return 1
  socks=(--socks5-hostname 127.0.0.1:9050)

  # Download leg (~5s)
  # We let curl run with --max-time slightly above target to cover TLS; compute actual time_total.
  local w_dl bytes_dl t_dl
  w_dl=$(curl -sS "${socks[@]}" -o /dev/null --max-time $((TOR_TEST_SECS+2)) \
         -w '%{size_download} %{time_total}' "$TOR_DL_URL" 2>/dev/null) || w_dl=""
  bytes_dl=$(cut -d' ' -f1 <<<"$w_dl" 2>/dev/null || echo 0)
  t_dl=$(cut -d' ' -f2 <<<"$w_dl" 2>/dev/null || echo 0)

  # Upload leg (~5s) — POST random bytes, server discards the body.
  # Generate data stream for ~8MB; --max-time clips it to ~5–7s.
  local w_ul bytes_ul t_ul
  w_ul=$(head -c 8388608 /dev/urandom | \
        curl -sS "${socks[@]}" -X POST --data-binary @- --max-time $((TOR_TEST_SECS+2)) \
             -o /dev/null -w '%{size_upload} %{time_total}' "$TOR_UL_URL" 2>/dev/null) || w_ul=""
  bytes_ul=$(cut -d' ' -f1 <<<"$w_ul" 2>/dev/null || echo 0)
  t_ul=$(cut -d' ' -f2 <<<"$w_ul" 2>/dev/null || echo 0)

  # Avoid divide-by-zero; compute Mb/s (bits / 1e6 / seconds)
  local dl ul
  if [[ "$bytes_dl" -gt 0 && "$t_dl" != "0" ]]; then
    dl=$(awk -v b="$bytes_dl" -v t="$t_dl" 'BEGIN{printf "%.1f", (b*8)/(t*1000000)}')
  fi
  if [[ "$bytes_ul" -gt 0 && "$t_ul" != "0" ]]; then
    ul=$(awk -v b="$bytes_ul" -v t="$t_ul" 'BEGIN{printf "%.1f", (b*8)/(t*1000000)}')
  fi
  [[ -n "${dl:-}" || -n "${ul:-}" ]] || return 1
  printf "%s|%s" "${dl:-—}" "${ul:-—}"
}

tor_speed(){
  info "Tor network speed"
  if ! tor_active || ! socks_listening; then
    printf "    %-18s %s\n" "Speed" "Tor inactive — skipping"
    return
  fi
  if ! command -v curl &>/dev/null; then
    printf "    %-18s %s\n" "Speed" "curl not installed"
    return
  fi
  local res dl ul
  res=$(_tor_speed_5s || true)
  if [[ -z "$res" ]]; then
    printf "    %-18s %s\n" "Speed" "test failed"
    return
  fi
  dl="${res%%|*}"; ul="${res##*|}"
  printf "    %-18s ↓ %s Mb/s   ↑ %s Mb/s\n" "Speed" "$dl" "$ul"
}

# -------- Commands --------
cmd_status(){
  clear; banner

  info "Overview"
  printf "    %-18s %s\n" "User"   "${SUDO_USER:-$USER}"
  printf "    %-18s %s\n" "Kernel" "$(uname -r)"
  printf "    %-18s %s\n" "TTY"    "$(tty 2>/dev/null || echo n/a)"

  info "Tor service"
  printf "    %-18s %s\n" "Active"  "$(tor_active && echo active || echo inactive)"
  printf "    %-18s %s\n" "Enabled" "$(tor_enabled && echo enabled || echo disabled)"
  printf "    %-18s %s\n" "SOCKS"   "127.0.0.1:9050"
  printf "    %-18s %s\n" "Control" "127.0.0.1:9051"
  listening 9050 || true
  listening 9051 || true

  info "Environment"
  proxy_env_summary
  tor_check

  tor_speed

  info "State dir"
  if [[ -d "$STATE_DIR" ]]; then
    printf "    %-18s %s\n" "Path" "$STATE_DIR"
    [[ -f "$STATE_DIR/last" ]] && printf "    %-18s %s\n" "Last action" "$(cat "$STATE_DIR/last" 2>/dev/null || true)"
  else
    printf "    %-18s %s\n" "Path" "$STATE_DIR (not created)"
  fi

  ok "Status captured. 📊"
}

cmd_on(){
  if [[ $EUID -ne 0 ]]; then exec sudo -E "$0" on; fi
  clear; banner
  info "Starting Tor"
  ensure_state_dir
  step "Enabling tor.service" systemctl enable tor
  step "Starting tor.service" systemctl start tor
  date -u +'%Y-%m-%d %H:%M:%S UTC on' > "$STATE_DIR/last" 2>/dev/null || true
  ok "Tor started."
  su -s /bin/zsh -c "$0 status" "${SUDO_USER:-root}" 2>/dev/null || "$0" status
}

cmd_off(){
  if [[ $EUID -ne 0 ]]; then exec sudo -E "$0" off; fi
  clear; banner
  info "Stopping Tor"
  ensure_state_dir
  step "Stopping tor.service" systemctl stop tor
  date -u +'%Y-%m-%d %H:%M:%S UTC off' > "$STATE_DIR/last" 2>/dev/null || true
  ok "Tor stopped."
  su -s /bin/zsh -c "$0 status" "${SUDO_USER:-root}" 2>/dev/null || "$0" status
}

case "${1:-}" in
  on)      shift; cmd_on "$@" ;;
  off)     shift; cmd_off "$@" ;;
  status)  shift; cmd_status "$@" ;;
  *)
    print -P "%F{yellow}Usage:%f tor-toggle {on|off|status}"
    print "  on     : enable+start tor.service (sudo only for this step)"
    print "  off    : stop tor.service (sudo only for this step)"
    print "  status : show Tor service + Tor exit check + Tor network speed (5s DL/UL)"
    exit 2
    ;;
esac

#!/usr/bin/env zsh
# v 3.2 yuriy edition
# net-toggle — NM-first network controller + full status (zsh)
# on     : bring networking up via NetworkManager (Ethernet→Wi-Fi). Clears persistent rfkill.
# off    : ultra-secure: NM disconnect, links down, PERSISTENT rfkill (wifi/wwan/bt). Then shows status.
# status : full status; default IF first; 5s DL/UL speed for active IF; Tor status always shown (with Tor speed if active).
SCRIPT_VER="2025-09-11.3"

set -Eeuo pipefail
IFS=$'\n\t'
: ${COLUMNS:=80}
: ${TERM:="xterm-256color"}

# ---------------- CONFIG ----------------
typeset -a PREFERRED_SSIDS=( )
: ${SPEEDTEST_IPERF_SERVER:=iperf.he.net}
: ${SPEEDTEST_TIMEOUT_SEC:=30}

# Tor speed test endpoints (only if tor is active)
: ${TOR_DL_URL:=https://speed.hetzner.de/100MB.bin}
: ${TOR_UL_URL:=https://speed.hetzner.de/upload.php}
: ${TOR_TEST_SECS:=30}

# ---------------- UI ----------------
autoload -Uz colors && colors || true
ok()   { print -P "%F{green}[✓]%f $*"; }
warn() { print -P "%F{yellow}[!]%f $*"; }
err()  { print -P "%F{red}[✗]%f $*" >&2; }
info() { print -P "%F{cyan}[*]%f $*"; }

banner(){
  local h="$(hostname -s 2>/dev/null || echo archcrypt)"
  local d="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  print -P "%F{magenta}===============================================================================================%f"
  print -P "%F{yellow}                        net-toggle — ${h} — ${d}%f"
  print -P "%F{magenta}===============================================================================================%f"
}

step(){ local msg="$1"; shift; if "$@" &>/tmp/.nettoggle.step.log; then ok "$msg"; else warn "$msg (non-fatal)"; return 1; fi }

# ---------------- ROOT ----------------
if [[ $EUID -ne 0 ]]; then exec sudo -E "$0" "$@"; fi

# ---------------- COMMON ----------------
readf(){ [[ -r "$1" ]] && <"$1" tr -d '\n' || echo 0; }
list_ifaces(){ ip -o link show | awk -F': ' '$2!="lo"{print $2}'; }
up_ifaces(){ for i in $(list_ifaces); do [[ "$(</sys/class/net/$i/operstate 2>/dev/null || echo down)" == up ]] && echo "$i"; done; }
iface_ipv4(){ ip -o -4 addr show "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1; }
iface_ipv6_all(){ ip -o -6 addr show "$1" 2>/dev/null | awk '{print $4}' | sed 's,/, ,g' | paste -sd ' '; }
default_dev(){ ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'; }

# ---------------- NM helpers ----------------
nm_make_primary(){
  systemctl is-active --quiet iwd            && step "Stopping iwd (use NM for Wi-Fi)" systemctl stop iwd || true
  systemctl is-active --quiet wpa_supplicant && step "Stopping wpa_supplicant (use NM)" systemctl stop wpa_supplicant || true
  step "Starting NetworkManager" systemctl start NetworkManager
  step "Enabling NM networking"  nmcli networking on
  step "Allowing radios (Wi-Fi/WWAN)"  sh -c 'nmcli radio wifi on; nmcli radio wwan on'
}
nm_fix_unmanaged(){
  local -a u; u=("${(@f)$(nmcli -t -f DEVICE,STATE dev 2>/dev/null | awk -F: '$2=="unmanaged"{print $1}')}") || true
  (( ${#u} )) || return 0
  info "Fixing unmanaged devices: ${u[*]}"
  local d; for d in "${u[@]}"; do nmcli device set "$d" managed yes &>/dev/null || true; done
  sleep 1
}
nm_connect(){
  nm_make_primary; nm_fix_unmanaged
  info "Connecting Ethernet (if present)…"
  nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="ethernet"{print $1}' | while read -r e; do nmcli dev connect "$e" &>/dev/null || true; done
  local -a wl; wl=("${(@f)$(nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="wifi"{print $1}')}") || true
  if (( ${#wl} )); then
    nmcli dev wifi rescan &>/dev/null || true
    if (( ${#PREFERRED_SSIDS} )); then
      local ssid; for ssid in "${PREFERRED_SSIDS[@]}"; do
        info "Trying SSID: $ssid"
        if nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="wifi"{print $1}' | grep -Fxq "$ssid"; then
          nmcli connection up id "$ssid" &>/dev/null && { ok "Connected: $ssid"; break; }
        fi
        nmcli dev wifi connect "$ssid" &>/dev/null && { ok "Connected: $ssid"; break; }
      done
    else
      local d; for d in "${wl[@]}"; do nmcli dev connect "$d" &>/dev/null || true; done
    fi
  fi
}
nm_disconnect_all(){
  local -a c; c=("${(@f)$(nmcli -t -f DEVICE,STATE dev 2>/dev/null | awk -F: '$2=="connected"{print $1}')}") || true
  if (( ${#c} )); then
    info "Disconnecting: ${c[*]}"
    local d; for d in "${c[@]}"; do nmcli dev disconnect "$d" &>/dev/null || true; done
  else
    info "No connected devices."
  fi
  step "Turning NM networking off" nmcli networking off
}

# ---------------- Basics + DNS ----------------
print_dns(){
  info "DNS"
  if command -v resolvectl &>/dev/null; then
    resolvectl dns 2>/dev/null | awk '
      /^Global/ {
        printf "      Global: "
        for(i=3;i<=NF;i++){ printf (i>3?" ":"") $i }
        print ""; next
      }
      match($0,/^Link[[:space:]]+[0-9]+[[:space:]]+\(([^)]+)\):[[:space:]]*(.*)$/,m){
        iface=m[1]; servers=m[2]; gsub(/[[:space:]]+$/,"",servers);
        print "      " iface ": " servers; next
      }
    '
  else
    awk '/^nameserver/{print "      resolv.conf: " $2}' /etc/resolv.conf 2>/dev/null || true
  fi
}
net_basics(){
  local dev gw4 gw6
  dev="$(default_dev || true)"
  gw4="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  gw6="$(ip -6 route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  printf "    %-18s %s\n" "Default dev" "${dev:-—}"
  printf "    %-18s %s\n" "Gateway(v4)" "${gw4:-—}"
  printf "    %-18s %s\n" "Gateway(v6)" "${gw6:-—}"
}

# ---------------- Interface display ----------------
iface_block(){
  local ifc="$1" type="ethernet"
  [[ "$ifc" == wl* || "$ifc" == wlan* ]] && type="wifi"
  local ip4 ip6 state ssid="" rate=""
  ip4="$(iface_ipv4 "$ifc" || true)"
  ip6="$(iface_ipv6_all "$ifc" || true)"
  state="$(</sys/class/net/"$ifc"/operstate 2>/dev/null || echo down)"
  if [[ "$type" == "wifi" ]] && command -v nmcli &>/dev/null; then
    ssid="$(nmcli -t -f GENERAL.CONNECTION dev show "$ifc" 2>/dev/null | awk -F: '{print $2}')"
    rate="$(nmcli -t -f WIFI.BITRATE dev show "$ifc" 2>/dev/null | awk -F: '{print $2}')"
  fi
  [[ -z "$rate" ]] && rate="$(iw dev "$ifc" link 2>/dev/null | awk -F': ' '/tx bitrate/{print $2 " (iw)"}')"
  if [[ "$type" == "ethernet" && -r /sys/class/net/$ifc/speed ]]; then
    local es="$(</sys/class/net/$ifc/speed 2>/dev/null || true)"
    [[ -n "$es" && "$es" != "-1" ]] && rate="${rate:+$rate, }${es} Mb/s"
  fi
  printf "    %-18s %s\n" "Interface" "$ifc (${type})"
  printf "    %-18s %s\n" "State"     "$state"
  [[ -n "$ssid" ]] && printf "    %-18s %s\n" "SSID" "$ssid"
  [[ -n "$rate" ]] && printf "    %-18s %s\n" "Link rate" "$rate"
  printf "    %-18s %s\n" "IPv4" "${ip4:-—}"
  printf "    %-18s %s\n" "IPv6" "${ip6:-—}"
}

# ---------------- Speed test (5s) ----------------
st_iperf3_iface(){
  local ifc="$1" srv="$2" ip dl ul out
  ip="$(iface_ipv4 "$ifc")"; [[ -z "$ip" ]] && return 1
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s iperf3 -J -R -t 5 -f m -B "$ip" -c "$srv" 2>/dev/null || true)
  dl=$(print -r -- "$out" | awk -F'[,: ]+' '/"end"/,0 {if($0 ~ /bits_per_second/){v=$NF}} END{if(v!="") printf "%.1f Mb/s", v/1e6}')
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s iperf3 -J    -t 5 -f m -B "$ip" -c "$srv" 2>/dev/null || true)
  ul=$(print -r -- "$out" | awk -F'[,: ]+' '/"end"/,0 {if($0 ~ /bits_per_second/){v=$NF}} END{if(v!="") printf "%.1f Mb/s", v/1e6}')
  [[ -n "$dl" || -n "$ul" ]] || return 1
  printf "%s|%s\n" "${dl:-—}" "${ul:-—}"
}
st_ookla_iface(){
  local ifc="$1" out dl ul
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s speedtest --accept-license --accept-gdpr --interface "$ifc" 2>/dev/null | sed 's/\r/\n/g' || true)
  dl=$(print -r -- "$out" | awk -F': *' '/^Download/ {print $2; exit}')
  ul=$(print -r -- "$out" | awk -F': *' '/^Upload/   {print $2; exit}')
  [[ -n "$dl" || -n "$ul" ]] || return 1
  printf "%s|%s\n" "${dl:-—}" "${ul:-—}"
}
st_cli_iface(){
  local ifc="$1" ip out dl ul
  ip="$(iface_ipv4 "$ifc")"; [[ -z "$ip" ]] && return 1
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s speedtest-cli --simple --source "$ip" 2>/dev/null || true)
  dl=$(print -r -- "$out" | awk '/^Download/{print $2" " $3; exit}')
  ul=$(print -r -- "$out" | awk '/^Upload/  {print $2" " $3; exit}')
  [[ -n "$dl" || -n "$ul" ]] || return 1
  printf "%s|%s\n" "${dl:-—}" "${ul:-—}"
}
speedtest_iface_best(){
  local ifc="$1" res
  [[ -n "$(iface_ipv4 "$ifc")" ]] || { echo "—|—"; return 0; }
  if command -v iperf3 &>/dev/null && [[ -n "${SPEEDTEST_IPERF_SERVER:-}" ]]; then
    res=$(st_iperf3_iface "$ifc" "$SPEEDTEST_IPERF_SERVER" || true); [[ -n "$res" ]] && { print -r -- "$res"; return 0; }
  fi
  if command -v speedtest &>/dev/null; then
    res=$(st_ookla_iface "$ifc" || true); [[ -n "$res" ]] && { print -r -- "$res"; return 0; }
  fi
  if command -v speedtest-cli &>/dev/null; then
    res=$(st_cli_iface "$ifc" || true); [[ -n "$res" ]] && { print -r -- "$res"; return 0; }
  fi
  echo "No tool|Install iperf3"
}

# ---------------- Tor helpers ----------------
tor_active(){ systemctl is-active --quiet tor; }
tor_enabled(){ systemctl is-enabled --quiet tor 2>/dev/null; }
socks_listening(){ ss -lnH 'sport = :9050' 2>/dev/null | grep -q .; }
listening(){ ss -lnH "sport = :$1" 2>/dev/null | awk '{print "    "$1,$4}'; }
tor_check(){
  if ! command -v curl &>/dev/null; then printf "    %-18s %s\n" "Tor check" "curl not installed"; return; fi
  local out; out=$(timeout 8s curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null) || true
  if [[ -z "$out" ]]; then printf "    %-18s %s\n" "Tor check" "no response"; return; fi
  local is_tor ip; is_tor=$(printf "%s" "$out" | grep -q '"IsTor":[ ]*true' && echo true || echo false)
  ip=$(printf "%s" "$out" | grep -o '"IP":"[^"]*"' | cut -d\" -f4)
  printf "    %-18s %s (IP: %s)\n" "Tor check" "$is_tor" "${ip:-?}"
}
tor_speed_30s(){
  command -v curl &>/dev/null || { echo "—|—"; return 0; }

  local out dl_raw dl_time ul_raw ul_time
  local dl="—" ul="—"

  # Step 1: Download Test
  out=$(curl -sS --socks5-hostname 127.0.0.1:9050 -o /dev/null --connect-timeout 20 --max-time $((TOR_TEST_SECS+5)) -w '%{size_download} %{time_total}' "$TOR_DL_URL" 2>&1 || true)
  dl_raw=$(print -r -- "$out" | awk '{print $1}')
  dl_time=$(print -r -- "$out" | awk '{print $2}')
  
  if [[ "$dl_raw" -gt 0 && "$dl_time" != "0" ]]; then
    dl=$(awk -v b="$dl_raw" -v t="$dl_time" 'BEGIN{printf "%.1f Mb/s", (b*8)/(t*1e6)}')
  else
    dl="Failed (DL)"
  fi

  # Step 2: Upload Test
  out=$(head -c 8388608 /dev/urandom | curl -sS --socks5-hostname 127.0.0.1:9050 -X POST --data-binary @- --connect-timeout 20 --max-time $((TOR_TEST_SECS+5)) -o /dev/null -w '%{size_upload} %{time_total}' "$TOR_UL_URL" 2>&1 || true)
  ul_raw=$(print -r -- "$out" | awk '{print $1}')
  ul_time=$(print -r -- "$out" | awk '{print $2}')

  if [[ "$ul_raw" -gt 0 && "$ul_time" != "0" ]]; then
    ul=$(awk -v b="$ul_raw" -v t="$ul_time" 'BEGIN{printf "%.1f Mb/s", (b*8)/(t*1e6)}')
  else
    ul="Failed (UL)"
  fi
  
  echo "${dl:-—}|${ul:-—}"
}

# ---------------- STATUS VIEW ----------------
print_status(){
  clear; banner
  print -P "%F{green}[i]%f archcrypt Network Details -"
  print

  if command -v nmcli &>/dev/null; then
    info "NetworkManager"
    nmcli general status | sed 's/^/    /' || true
    print
    info "Active NM connections"
    nmcli -t -f NAME,TYPE,DEVICE connection show --active | awk -F: '{printf "    %-18s %-8s %s\n",$1,$2,$3}'
    print
  fi

  info "Basics"
  net_basics

  info "Tor status"
  if tor_active; then
    printf "    %-18s %s\n" "Tor service" "active"
    printf "    %-18s %s\n" "Enabled"     "$(tor_enabled && echo enabled || echo disabled)"
    printf "    %-18s %s\n" "SOCKS"       "127.0.0.1:9050"
    printf "    %-18s %s\n" "Control"     "127.0.0.1:9051"
    listening 9050 || true
    listening 9051 || true
    tor_check
    # inline tor speed
    local tres tdl tul; tres="$(tor_speed_30s)"; tdl="${tres%%|*}"; tul="${tres##*|}"
    printf "    %-18s ↓ %s   ↑ %s\n" "Tor speed" "$tdl" "$tul"
  else
    printf "    %-18s %s\n" "Tor service" "not active"
  fi

  print_dns

  info "Interfaces"
  local def ifc
  def="$(default_dev || true)"
  if [[ -n "$def" ]]; then { iface_block "$def" || warn "could not render $def"; } ; print; fi
  for ifc in $(list_ifaces); do
    [[ "$ifc" == "$def" ]] && continue
    { iface_block "$ifc" || warn "could not render $ifc"; } ; print
  done

  info "Network speed"
  local test_if=""
  if [[ -n "$def" && -n "$(iface_ipv4 "$def")" ]]; then
    test_if="$def"
  else
    for ifc in $(up_ifaces); do
      if [[ -n "$(iface_ipv4 "$ifc")" ]]; then test_if="$ifc"; break; fi
    done
  fi
  if [[ -n "$test_if" ]]; then
    local res dl ul; res="$(speedtest_iface_best "$test_if")"
    dl="${res%%|*}"; ul="${res##*|}"
    printf "      %-16s ↓ %s   ↑ %s\n" "$test_if" "$dl" "$ul"
  else
    printf "      %s\n" "No active interface with IP — skipping."
  fi

  ok "Status captured."
}

# ---------------- COMMANDS ----------------
cmd_on(){
  clear; banner
  print -P "%F{green}[i]%f archcrypt Network Details -"
  print
  command -v rfkill &>/dev/null && step "Clearing persistent rfkill (wifi/wwan/bt)" rfkill unblock all
  if command -v nmcli &>/dev/null; then
    nm_connect
  elif systemctl is-active --quiet iwd || systemctl is-enabled --quiet iwd 2>/dev/null; then
    info "iwd path (no NetworkManager)"
    step "Restarting iwd" systemctl restart iwd
    typeset -a WLANS; WLANS=("${(@f)$(ls /sys/class/net | grep -E '^wl|^wlan' || true)}")
    if (( ${#WLANS} )); then
      local w="${WLANS[1]}"; step "Scanning on ${w}" iwctl station "$w" scan
      if (( ${#PREFERRED_SSIDS} )); then
        local connected=0 ssid
        for ssid in "${PREFERRED_SSIDS[@]}"; do
          info "Trying SSID: $ssid"
          if iwctl station "$w" connect "$ssid" &>/dev/null; then ok "Connected: $ssid"; connected=1; break; fi
          warn "Could not connect: $ssid"
        done
        (( connected )) || warn "No preferred SSID connected; run:  iwctl station $w connect <SSID>"
      else
        warn "No SSIDs provided; run:  iwctl station $w connect <SSID>"
      fi
    else
      warn "No wlan* interface found."
    fi
  else
    info "Minimal wired fallback"
    info "Bringing non-loopback links up…"
    local dev; for dev in $(list_ifaces); do ip link set "$dev" up &>/dev/null || true; done
    info "Attempting DHCP on common wired names…"
    for dev in eth0 eno1 enp0s25 enp3s0 enp2s0; do
      command -v dhcpcd &>/dev/null && dhcpcd -n "$dev" &>/dev/null || true
      command -v dhclient &>/dev/null && dhclient -1 "$dev" &>/dev/null || true
    done
  fi
  info "Connectivity check"
  local gw dev; dev="$(default_dev || true)"; gw="$(ip route show default | awk '/default/{print $3; exit}')"
  [[ -n "$gw" ]] && (ping -W1 -c1 "$gw" &>/dev/null && ok "Ping gateway $gw (dev $dev)") || warn "Gateway ping skipped/failed"
  (ping -W1 -c1 1.1.1.1 &>/dev/null && ok "Ping 1.1.1.1 OK") || warn "No ICMP to 1.1.1.1"
  (getent hosts archlinux.org &>/dev/null && ok "DNS OK (archlinux.org)") || warn "DNS lookup failed (archlinux.org)"
  print_status
}

cmd_off(){
  clear; banner
  print -P "%F{green}[i]%f archcrypt Network Details -"
  print
  command -v nmcli &>/dev/null && nm_disconnect_all
  info "Bringing non-loopback links down…"
  local dev; for dev in $(list_ifaces); do ip link set "$dev" down &>/dev/null || true; done
  if command -v rfkill &>/dev/null; then
    step "Applying persistent rfkill (wifi/wwan/bt)" sh -c 'rfkill block wifi; rfkill block wwan; rfkill block bluetooth'
    warn "Radios hard-blocked across reboots. Use 'net-toggle on' to restore."
  else
    warn "rfkill not installed; cannot persistently block radios."
  fi
  print_status
}

case "${1:-}" in
  on)      shift; cmd_on "$@" ;;
  off)     shift; cmd_off "$@" ;;
  status)  shift; print_status "$@" ;;
  *)
    print -P "%F{yellow}Usage:%f net-toggle {on|off|status}"
    print "  on     : NM-first bring-up (unblock radios, NM up, Ethernet→Wi-Fi)"
    print "  off    : ultra-secure: NM disconnect, links down, PERSISTENT rfkill (wifi/wwan/bt)"
    print "  status : full network details; default IF first; 5s speed test; Tor inline section"
    exit 2
    ;;
esac

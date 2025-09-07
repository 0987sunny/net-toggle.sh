#!/usr/bin/env zsh
# net-toggle — unified network controller (zsh)
# on     : bring networking up via NetworkManager (Ethernet→Wi-Fi). Reverses persistent rfkill.
# off    : ultra-secure cut: disconnect + links down + PERSISTENT rfkill (wifi/wwan/bt). Prints status.
# status : pretty status incl. link rate + 5s speed test avg (default iface); Tor + rfkill; per-iface DNS.
#
# Policy:
#   - Always use NetworkManager if present. Start it; prefer it for Ethernet + Wi-Fi.
#   - Fall back to iwd/minimal wired only if NM is missing.
#   - Non-destructive; best-effort to mark devices managed and stop conflicting daemons.

set -Eeuo pipefail
IFS=$'\n\t'

# -------- CONFIG --------
typeset -a PREFERRED_SSIDS=(
  # "HomeSSID"
  # "PhoneHotspot"
)
: ${SPEEDTEST_IFACE:=}                  # force which iface to test (default: current default route dev)
: ${SPEEDTEST_IPERF_SERVER:=iperf.he.net}  # public iperf3 server (can change)
: ${SPEEDTEST_TIMEOUT_SEC:=30}          # cap for external tests (Ookla/cli/iperf3)

# -------- UI HELPERS --------
autoload -Uz colors && colors || true
: ${TERM:="xterm-256color"}

ok()   { print -P "%F{green}[✓]%f $*"; }
warn() { print -P "%F{yellow}[!]%f $*"; }
err()  { print -P "%F{red}[✗]%f $*" >&2; }
info() { print -P "%F{cyan}[*]%f $*"; }

rule()   { print -P "%F{magenta}─────────────────────────────────────────────────────%f"; }
center_orange(){
  local msg="$*"; local w=${COLUMNS:-80}; local pad=$(( (w - ${#msg}) / 2 ))
  (( pad < 0 )) && pad=0
  print -P "%F{yellow}$(printf "%*s%s" "$pad" "" "$msg")%f"
}
banner(){
  local h="$(hostname -s 2>/dev/null || echo archcrypt)"
  local d="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  print -P "%F{magenta}=====================================================%f"
  center_orange "net-toggle — ${h} — ${d}"
  print -P "%F{magenta}=====================================================%f"
}
box(){ rule; print -P "%F{yellow} $*%f"; rule; }  # left-aligned section header

# swallow noisy output; one clean line
step(){ local msg="$1"; shift; if "$@" &>/tmp/.nettoggle.step.log; then ok "$msg"; else warn "$msg (non-fatal)"; return 1; fi }

# -------- ROOT RE-EXEC --------
if [[ $EUID -ne 0 ]]; then exec sudo -E "$0" "$@"; fi

# -------- COMMON UTILS --------
readf(){ [[ -r "$1" ]] && <"$1" tr -d '\n' || echo 0; }
list_ifaces(){ ip -o link show | awk -F': ' '$2!="lo"{print $2}'; }
default_dev(){ ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'; }

# 5s local sample from /sys counters (Mb/s, 1 dec); only if iface is up
sample_iface_avg_5s(){
  local ifc="$1" dt=5 op rx1 tx1 rx2 tx2
  op=$(</sys/class/net/"$ifc"/operstate 2>/dev/null || echo down)
  [[ "$op" != "up" ]] && { printf "0.0 0.0\n"; return 0; }
  rx1=$(readf "/sys/class/net/$ifc/statistics/rx_bytes")
  tx1=$(readf "/sys/class/net/$ifc/statistics/tx_bytes")
  sleep "$dt"
  rx2=$(readf "/sys/class/net/$ifc/statistics/rx_bytes")
  tx2=$(readf "/sys/class/net/$ifc/statistics/tx_bytes")
  local drx=$(( rx2 - rx1 )); (( drx < 0 )) && drx=0
  local dtx=$(( tx2 - tx1 )); (( dtx < 0 )) && dtx=0
  local down=$(( (drx * 8.0) / (1000.0*1000.0*dt) ))
  local up=$((   (dtx * 8.0) / (1000.0*1000.0*dt) ))
  printf "%.1f %.1f\n" "$down" "$up"
}

net_basics(){
  local gw4 gw6 dev
  dev="$(default_dev || true)"
  gw4="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  gw6="$(ip -6 route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  printf "    %-18s %s\n" "Default dev" "${dev:-—}"
  printf "    %-18s %s\n" "Gateway(v4)" "${gw4:-—}"
  printf "    %-18s %s\n" "Gateway(v6)" "${gw6:-—}"

  # Per-interface DNS (clean, one line per link)
  print "    DNS"
  if command -v resolvectl &>/dev/null; then
    resolvectl dns 2>/dev/null | awk '
      /^Global/ { print "      Global: " $3; next }
      /^Link/   { iface=$3; sub(/\(|\)/,"",iface); ns=""; for(i=4;i<=NF;i++) ns=ns ? ns " " $i : $i; print "      " iface ": " ns }
    '
  else
    awk '/^nameserver/{print "      resolv.conf: " $2}' /etc/resolv.conf 2>/dev/null || true
  fi
}

iface_info(){
  local ifc="$1"
  local type="ethernet"; [[ "$ifc" == wl* || "$ifc" == wlan* ]] && type="wifi"
  local ip4 ip6 state ssid="" rate=""
  ip4="$(ip -o -4 addr show "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd ' ')"
  ip6="$(ip -o -6 addr show "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd ' ')"
  state="$(</sys/class/net/"$ifc"/operstate 2>/dev/null || echo down)"
  if [[ "$type" == "wifi" ]] && command -v nmcli &>/dev/null; then
    ssid="$(nmcli -t -f GENERAL.CONNECTION dev show "$ifc" 2>/dev/null | awk -F: '{print $2}')"
    rate="$(nmcli -t -f WIFI.BITRATE dev show "$ifc" 2>/dev/null | awk -F: '{print $2}')"
  fi
  [[ -z "$rate" ]] && rate="$(iw dev "$ifc" link 2>/dev/null | awk -F': ' '/tx bitrate/ {print $2 " (iw)"}')"
  if [[ "$type" == "ethernet" && -r /sys/class/net/$ifc/speed ]]; then
    local es="$(</sys/class/net/$ifc/speed 2>/dev/null || true)"
    [[ -n "$es" && "$es" != "-1" ]] && rate="${rate:+$rate, }${es} Mb/s"
  fi
  printf "    %-18s %s\n" "Interface" "$ifc (${type})"
  printf "    %-18s %s\n" "State"     "$state"
  [[ -n "$ssid" ]] && printf "    %-18s %s\n" "SSID" "$ssid"
  [[ -n "$rate" ]] && printf "    %-18s %s\n" "Link rate" "$rate"
  printf "    %-18s %s\n" "IPv4"      "${ip4:-—}"
  printf "    %-18s %s\n" "IPv6"      "${ip6:-—}"
}

tor_status(){
  local svc="inactive"; systemctl is-active --quiet tor && svc="active"
  local proxy="none"
  [[ -n "${http_proxy:-}${HTTP_PROXY:-}${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}" ]] && proxy="env-proxy"
  printf "    %-18s %s\n" "Tor service" "$svc"
  printf "    %-18s %s\n" "Proxy env"   "$proxy"
}

rfkill_summary(){
  if ! command -v rfkill &>/dev/null; then printf "    %-18s %s\n" "RFKill" "rfkill not installed"; return; fi
  printf "    %-18s %s\n" "RFKill state" "(soft/hard)"
  rfkill list 2>/dev/null | awk '
    /^([0-9]+):/ {gsub(":",""); cls=$2}
    /Soft blocked/ {soft=$3}
    /Hard blocked/ {hard=$3; printf "      %-16s %s/%s\n", cls, soft, hard }
  '
}

# ---------- NetworkManager helpers ----------
nm_make_primary(){
  systemctl is-active --quiet iwd            && step "Stopping iwd (use NM for Wi-Fi)" systemctl stop iwd || true
  systemctl is-active --quiet wpa_supplicant && step "Stopping wpa_supplicant (use NM)" systemctl stop wpa_supplicant || true
  step "Starting NetworkManager" systemctl start NetworkManager
  step "Enabling NM networking"  nmcli networking on
  step "Allowing radios (Wi-Fi/WWAN)"  sh -c 'nmcli radio wifi on; nmcli radio wwan on'
}

nm_fix_unmanaged(){
  local -a unmanaged
  unmanaged=("${(@f)$(nmcli -t -f DEVICE,STATE dev 2>/dev/null | awk -F: '$2=="unmanaged"{print $1}')}") || true
  (( ${#unmanaged} )) || return 0
  info "Fixing unmanaged devices: ${unmanaged[*]}"
  local d; for d in "${unmanaged[@]}"; do nmcli device set "$d" managed yes &>/dev/null || true; done
  sleep 1
}

nm_connect(){
  nm_make_primary
  nm_fix_unmanaged
  info "Connecting Ethernet (if present)…"
  nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="ethernet"{print $1}' |
    while read -r e; do nmcli dev connect "$e" &>/dev/null || true; done

  local -a wifi_devs; wifi_devs=("${(@f)$(nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="wifi"{print $1}')}") || true
  if (( ${#wifi_devs} )); then
    nmcli dev wifi rescan &>/dev/null || true
    if (( ${#PREFERRED_SSIDS} )); then
      local ssid
      for ssid in "${PREFERRED_SSIDS[@]}"; do
        info "Trying SSID: $ssid"
        if nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="wifi"{print $1}' | grep -Fxq "$ssid"; then
          nmcli connection up id "$ssid" &>/dev/null && { ok "Connected: $ssid"; break; }
        fi
        nmcli dev wifi connect "$ssid" &>/dev/null && { ok "Connected: $ssid"; break; }
      done
    else
      local d; for d in "${wifi_devs[@]}"; do nmcli dev connect "$d" &>/dev/null || true; done
    fi
  fi
}

nm_disconnect_all(){
  local -a connd; connd=("${(@f)$(nmcli -t -f DEVICE,STATE dev 2>/dev/null | awk -F: '$2=="connected"{print $1}')}") || true
  if (( ${#connd} )); then
    info "Disconnecting: ${connd[*]}"
    local d; for d in "${connd[@]}"; do nmcli dev disconnect "$d" &>/dev/null || true; done
  else
    info "No connected devices."
  fi
  step "Turning NM networking off" nmcli networking off
}

# ---------- 5s SPEED TEST (avg) ----------
st_iperf3_5s(){
  local face="$1" srv="$2" dl ul out
  [[ -z "$srv" ]] && return 1
  # Download (reverse), 5s
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s iperf3 -J -R -t 5 -f m -c "$srv" 2>/dev/null || true)
  dl=$(print -r -- "$out" | awk -F'[,: ]+' '/end.*sum_sent/ && /bits_per_second/ {printf "%.1f Mb/s", $NF/1e6; exit}')
  # Upload, 5s
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s iperf3 -J -t 5 -f m -c "$srv" 2>/dev/null || true)
  ul=$(print -r -- "$out" | awk -F'[,: ]+' '/end.*sum_sent/ && /bits_per_second/ {printf "%.1f Mb/s", $NF/1e6; exit}')
  [[ -n "$dl" || -n "$ul" ]] || return 1
  printf "%s|%s\n" "${dl:-—}" "${ul:-—}"
}

st_ookla(){
  local out dl ul
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s speedtest --accept-license --accept-gdpr 2>/dev/null | sed 's/\r/\n/g' || true)
  dl=$(print -r -- "$out" | awk -F': *' '/^Download/ {print $2; exit}')
  ul=$(print -r -- "$out" | awk -F': *' '/^Upload/   {print $2; exit}')
  [[ -n "$dl" || -n "$ul" ]] || return 1
  printf "%s|%s\n" "${dl:-—}" "${ul:-—}"
}

st_cli(){
  local out dl ul
  out=$(timeout ${SPEEDTEST_TIMEOUT_SEC}s speedtest-cli --simple 2>/dev/null || true)
  dl=$(print -r -- "$out" | awk '/^Download/{print $2" " $3; exit}')
  ul=$(print -r -- "$out" | awk '/^Upload/  {print $2" " $3; exit}')
  [[ -n "$dl" || -n "$ul" ]] || return 1
  printf "%s|%s\n" "${dl:-—}" "${ul:-—}"
}

# ---------- Commands ----------
cmd_status(){
  [[ "${1:-}" == "no-clear" ]] || { clear; banner; }

  box "Overview"
  printf "    %-18s %s\n" "User"   "${SUDO_USER:-$USER}"
  printf "    %-18s %s\n" "Kernel" "$(uname -r)"
  printf "    %-18s %s\n" "TTY"    "$(tty 2>/dev/null || echo n/a)"

  if command -v nmcli &>/dev/null; then
    box "NetworkManager"
    nmcli general status | sed 's/^/    /' || true
    print
    box "Active NM connections"
    nmcli -t -f NAME,TYPE,DEVICE connection show --active | awk -F: '{printf "    %-18s %-8s %s\n",$1,$2,$3}'
    print
  fi

  box "Basics"
  net_basics

  box "Interfaces (5s speed avg on default iface)"
  local def ifc rx tx st_dl="—" st_ul="—" tested=""
  def="${SPEEDTEST_IFACE:-$(default_dev || true)}"

  # If we can, run a 5s external speed test for the default iface (max-ish avg)
  if [[ -n "$def" ]]; then
    if command -v iperf3 &>/dev/null && [[ -n "${SPEEDTEST_IPERF_SERVER:-}" ]]; then
      local r; r=$(st_iperf3_5s "$def" "$SPEEDTEST_IPERF_SERVER" || true)
      [[ -n "$r" ]] && { st_dl="${r%%|*}"; st_ul="${r##*|}"; tested="iperf3 (5s)"; }
    elif command -v speedtest &>/dev/null; then
      local r; r=$(st_ookla || true)
      [[ -n "$r" ]] && { st_dl="${r%%|*}"; st_ul="${r##*|}"; tested="Ookla"; }
    elif command -v speedtest-cli &>/dev/null; then
      local r; r=$(st_cli || true)
      [[ -n "$r" ]] && { st_dl="${r%%|*}"; st_ul="${r##*|}"; tested="speedtest-cli"; }
    fi
  fi

  for ifc in ${(f)"$(list_ifaces)"}; do
    iface_info "$ifc"

    if [[ "$ifc" == "$def" ]]; then
      if [[ "$tested" != "" ]]; then
        printf "    %-18s %s   %s\n" "Speed test avg" "↓ ${st_dl}   ↑ ${st_ul}" "[$tested]"
      else
        read rx tx < <(sample_iface_avg_5s "$ifc" || echo "0.0 0.0")
        printf "    %-18s ↓ %s Mb/s   ↑ %s Mb/s   %s\n" "5s sample" "$rx" "$tx" "[local counters, not max]"
      fi
    fi
    rule
  done

  box "Tor"
  tor_status

  box "RFKill"
  rfkill_summary

  ok "Status captured. 📊"
}

cmd_on(){
  clear; banner
  box "Overview"
  printf "    %-18s %s\n" "User"   "${SUDO_USER:-$USER}"
  printf "    %-18s %s\n" "Kernel" "$(uname -r)"
  printf "    %-18s %s\n" "TTY"    "$(tty 2>/dev/null || echo n/a)"

  command -v rfkill &>/dev/null && step "Clearing persistent rfkill (wifi/wwan/bt)" rfkill unblock all

  if command -v nmcli &>/dev/null; then
    nm_connect
  elif systemctl is-active --quiet iwd || systemctl is-enabled --quiet iwd 2>/dev/null; then
    box "iwd path (no NetworkManager)"
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
    box "Minimal wired fallback"
    info "Bringing non-loopback links up…"
    local dev; for dev in ${(f)"$(list_ifaces)"}; do ip link set "$dev" up &>/dev/null || true; done
    info "Attempting DHCP on common wired names…"
    for dev in eth0 eno1 enp0s25 enp3s0 enp2s0; do
      command -v dhcpcd &>/dev/null && dhcpcd -n "$dev" &>/dev/null || true
      command -v dhclient &>/dev/null && dhclient -1 "$dev" &>/dev/null || true
    done
  fi

  box "Connectivity check"
  local gw dev; dev="$(default_dev || true)"; gw="$(ip route show default | awk '/default/{print $3; exit}')"
  [[ -n "$gw" ]] && (ping -W1 -c1 "$gw" &>/dev/null && ok "Ping gateway $gw (dev $dev)") || warn "Gateway ping skipped/failed"
  (ping -W1 -c1 1.1.1.1 &>/dev/null && ok "Ping 1.1.1.1 OK") || warn "No ICMP to 1.1.1.1"
  (getent hosts archlinux.org &>/dev/null && ok "DNS OK (archlinux.org)") || warn "DNS lookup failed (archlinux.org)"

  cmd_status "no-clear"
}

cmd_off(){
  clear; banner
  box "Ultra-secure teardown"

  if command -v nmcli &>/dev/null; then
    nm_disconnect_all
  fi

  info "Bringing non-loopback links down…"
  local dev; for dev in ${(f)"$(list_ifaces)"}; do ip link set "$dev" down &>/dev/null || true; done

  if command -v rfkill &>/dev/null; then
    step "Applying persistent rfkill (wifi/wwan/bt)" sh -c 'rfkill block wifi; rfkill block wwan; rfkill block bluetooth'
    warn "Radios hard-blocked across reboots. Use 'net-toggle on' to restore."
  else
    warn "rfkill not installed; cannot persistently block radios."
  fi

  cmd_status "no-clear"
}

# -------- Dispatch --------
case "${1:-}" in
  on)      shift; cmd_on "$@" ;;
  off)     shift; cmd_off "$@" ;;
  status)  shift; cmd_status "$@" ;;
  *)
    print -P "%F{yellow}Usage:%f net-toggle {on|off|status}"
    print "  on     : NM-first bring-up (unblock radios, NM up, Ethernet→Wi-Fi)"
    print "  off    : ultra-secure: NM disconnect, links down, PERSISTENT rfkill (wifi/wwan/bt)"
    print "  status : show NM/Tor/RFKill + per-iface DNS + 5s speed avg (default iface)"
    exit 2
    ;;
esac

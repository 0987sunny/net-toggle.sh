#!/usr/bin/env zsh
# net-toggle — unified network controller (zsh)
# on     : bring networking up via NetworkManager (Ethernet→Wi-Fi). Reverses persistent rfkill.
# off    : ultra-secure cut: disconnect + links down + PERSISTENT rfkill (wifi/wwan/bt). Prints status.
# status : pretty status incl. link rate + 2s throughput; Tor + rfkill summary.
#
# Policy:
#   - Always use NetworkManager if present. Start it; prefer it for both Ethernet and Wi-Fi.
#   - If NM is absent only, fall back to iwd/minimal wired.
#   - Avoid destructive changes; best-effort to set devices managed and stop conflicting daemons.

set -Eeuo pipefail
IFS=$'\n\t'

# -------- CONFIG --------
typeset -a PREFERRED_SSIDS=(
  # "HomeSSID"
  # "PhoneHotspot"
)

# -------- UI HELPERS --------
autoload -Uz colors && colors || true
: ${TERM:="xterm-256color"}

ok()   { print -P "%F{green}[✓]%f $*"; }
warn() { print -P "%F{yellow}[!]%f $*"; }
err()  { print -P "%F{red}[✗]%f $*" >&2; }
info() { print -P "%F{cyan}[*]%f $*"; }

rule()   { print -P "%F{magenta}─────────────────────────────────────────────────────%f"; }
_center(){ local w=${COLUMNS:-80}; printf "%*s\n" $(((${#1}+$w)/2)) "$1"; }
banner(){
  local h="$(hostname -s 2>/dev/null || echo archcrypt)"
  local d="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  print -P "%F{magenta}=====================================================%f"
  _center "net-toggle • ${h} • ${d}"
  print -P "%F{magenta}=====================================================%f"
}
kv(){ printf "    %-18s %s\n" "$1" "$2"; }

# swallow noisy output; show one clean line
step(){ local msg="$1"; shift; if "$@" &>/tmp/.nettoggle.step.log; then ok "$msg"; else warn "$msg (non-fatal)"; return 1; fi }

# -------- ROOT RE-EXEC --------
if [[ $EUID -ne 0 ]]; then exec sudo -E "$0" "$@"; fi

# -------- COMMON UTILS --------
readf(){ [[ -r "$1" ]] && <"$1" tr -d '\n' || echo 0; }
list_ifaces(){ ip -o link show | awk -F': ' '$2!="lo"{print $2}'; }
default_dev(){ ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'; }

# 2s throughput sample (Mb/s, 1 dec); only if operstate=up
sample_iface_mbps(){
  local ifc="$1" dt="${2:-2}" op
  op=$(</sys/class/net/"$ifc"/operstate 2>/dev/null || echo down)
  [[ "$op" != "up" ]] && { printf "0.0 0.0\n"; return 0; }
  local rx1 tx1 rx2 tx2
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
  local gw4 gw6 dns dev
  gw4="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  gw6="$(ip -6 route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  dev="$(default_dev || true)"
  if command -v resolvectl &>/dev/null; then
    dns="$(resolvectl dns 2>/dev/null | awk '{for(i=3;i<=NF;i++)printf (i>3?" ":"") $i} END{print ""}')"
  else
    dns="$(awk '/^nameserver/{printf (NR>1?", ":"") $2} END{print ""}' /etc/resolv.conf 2>/dev/null || true)"
  fi
  kv "Default dev" "${dev:-—}"
  kv "Gateway(v4)" "${gw4:-—}"
  kv "Gateway(v6)" "${gw6:-—}"
  kv "DNS"         "${dns:-—}"
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
  kv "Interface" "$ifc (${type})"
  kv "State"     "$state"
  [[ -n "$ssid" ]] && kv "SSID" "$ssid"
  [[ -n "$rate" ]] && kv "Link rate" "$rate"
  kv "IPv4"      "${ip4:-—}"
  kv "IPv6"      "${ip6:-—}"
}

tor_status(){
  local svc="inactive"; systemctl is-active --quiet tor && svc="active"
  local proxy="none"
  [[ -n "${http_proxy:-}${HTTP_PROXY:-}${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}" ]] && proxy="env-proxy"
  kv "Tor service" "$svc"; kv "Proxy env" "$proxy"
}

rfkill_summary(){
  if ! command -v rfkill &>/dev/null; then kv "RFKill" "rfkill not installed"; return; fi
  kv "RFKill state" "(soft/hard)"
  rfkill list 2>/dev/null | awk '
    /^([0-9]+):/ {gsub(":",""); cls=$2}
    /Soft blocked/ {soft=$3}
    /Hard blocked/ {hard=$3; printf "    %-18s %s/%s\n", cls, soft, hard }
  '
}

# ---------- NetworkManager helpers ----------
nm_make_primary(){
  # Stop conflicting daemons (best-effort, session only)
  systemctl is-active --quiet iwd && step "Stopping iwd (use NM for Wi-Fi)" systemctl stop iwd || true
  systemctl is-active --quiet wpa_supplicant && step "Stopping wpa_supplicant (use NM)" systemctl stop wpa_supplicant || true

  # Ensure NM is running
  step "Starting NetworkManager" systemctl start NetworkManager
  step "Enabling NM networking"  nmcli networking on
  step "Allowing radios (Wi-Fi/WWAN)"  sh -c 'nmcli radio wifi on; nmcli radio wwan on'
}

nm_fix_unmanaged(){
  # If NM reports devices as unmanaged, try to flip to managed for this session
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

  # Ethernet first
  info "Connecting Ethernet (if present)…"
  nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="ethernet"{print $1}' |
    while read -r e; do nmcli dev connect "$e" &>/dev/null || true; done

  # Wi-Fi next
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

# ---------- Commands ----------
cmd_status(){
  [[ "${1:-}" == "no-clear" ]] || { clear; banner; }

  rule; _center " Overview "; rule
  kv "User"   "${SUDO_USER:-$USER}"
  kv "Kernel" "$(uname -r)"
  kv "TTY"    "$(tty 2>/dev/null || echo n/a)"
  rule; print

  if command -v nmcli &>/dev/null; then
    rule; _center " NetworkManager "; rule
    nmcli general status | sed 's/^/    /' || true
    print
    rule; _center " Active NM connections "; rule
    nmcli -t -f NAME,TYPE,DEVICE connection show --active | awk -F: '{printf "    %-18s %-8s %s\n",$1,$2,$3}'
    print
  fi

  rule; _center " Basics "; rule
  net_basics

  rule; _center " Interfaces (with 2s throughput sample) "; rule
  local ifc rx tx
  for ifc in ${(f)"$(list_ifaces)"}; do
    iface_info "$ifc"
    read rx tx < <(sample_iface_mbps "$ifc" 2 || echo "0.0 0.0")
    if [[ "$rx" == "0.0" && "$tx" == "0.0" ]]; then
      kv "Throughput" "— (interface down/idle)"
    else
      kv "Throughput" "↓ ${rx} Mb/s   ↑ ${tx} Mb/s"
    fi
    rule
  done

  rule; _center " Tor "; rule
  tor_status

  rule; _center " RFKill "; rule
  rfkill_summary

  ok "Status captured. 📊"
}

cmd_on(){
  clear; banner

  rule; _center " Overview "; rule
  kv "User"   "${SUDO_USER:-$USER}"
  kv "Kernel" "$(uname -r)"
  kv "TTY"    "$(tty 2>/dev/null || echo n/a)"
  rule; print

  # Reverse persistent air-gap
  command -v rfkill &>/dev/null && step "Clearing persistent rfkill (wifi/wwan/bt)" rfkill unblock all

  if command -v nmcli &>/dev/null; then
    nm_connect
  elif systemctl is-active --quiet iwd || systemctl is-enabled --quiet iwd 2>/dev/null; then
    # Only used if NM is missing
    rule; _center " iwd path (no NetworkManager) "; rule
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
    # Minimal wired if neither NM nor iwd present
    rule; _center " Minimal wired fallback "; rule
    info "Bringing non-loopback links up…"
    local dev; for dev in ${(f)"$(list_ifaces)"}; do ip link set "$dev" up &>/dev/null || true; done
    info "Attempting DHCP on common wired names…"
    for dev in eth0 eno1 enp0s25 enp3s0 enp2s0; do
      command -v dhcpcd &>/dev/null && dhcpcd -n "$dev" &>/dev/null || true
      command -v dhclient &>/dev/null && dhclient -1 "$dev" &>/dev/null || true
    done
  fi

  rule; _center " Connectivity check "; rule
  local gw dev; dev="$(default_dev || true)"; gw="$(ip route show default | awk '/default/{print $3; exit}')"
  [[ -n "$gw" ]] && (ping -W1 -c1 "$gw" &>/dev/null && ok "Ping gateway $gw (dev $dev)") || warn "Gateway ping skipped/failed"
  (ping -W1 -c1 1.1.1.1 &>/dev/null && ok "Ping 1.1.1.1 OK") || warn "No ICMP to 1.1.1.1"
  (getent hosts archlinux.org &>/dev/null && ok "DNS OK (archlinux.org)") || warn "DNS lookup failed (archlinux.org)"

  cmd_status "no-clear"
}

cmd_off(){
  clear; banner
  rule; _center " Ultra-secure teardown "; rule

  if command -v nmcli &>/dev/null; then
    nm_disconnect_all
  fi

  info "Bringing non-loopback links down…"
  local dev; for dev in ${(f)"$(list_ifaces)"}; do ip link set "$dev" down &>/dev/null || true; done

  # ALWAYS persistently block radios
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
    print "  status : show NM/links/Tor/DNS + 2s throughput + rfkill"
    exit 2
    ;;
esac

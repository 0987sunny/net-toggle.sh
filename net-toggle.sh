#!/usr/bin/env zsh
# net-toggle — unified network controller (zsh)
# Commands:
#   on       : bring networking up (Wi-Fi/Ethernet auto). Clears persistent rfkill from secure-shutdown.
#   off      : bring networking fully down (non-persistent by default; add --airgap for persistent Wi-Fi rfkill)
#   status   : pretty status incl. link rate + 1s throughput sample; Tor service/proxy state
#
# Design:
#   - Pure zsh (no bashisms), CLI-first, no GUI deps.
#   - Prefers NetworkManager (nmcli); falls back to iwd or plain ip/dhcp.
#   - Tailored to pair with a persistent-rfkill shutdown: `on` reverses it cleanly.
#   - Aesthetic: banners, magenta rules, tidy tables, spinner, subtle emoji.

set -Eeuo pipefail
IFS=$'\n\t'

### ---------------- CONFIG ----------------
# Optional: priority SSIDs (first match wins). Leave empty to let NM autoconnect.
typeset -a PREFERRED_SSIDS=(
  # "HomeSSID"
  # "PhoneHotspot"
  # "WorkGuest"
)

### --------------- UI HELPERS --------------
autoload -Uz colors && colors || true
: ${TERM:="xterm-256color"}

ok()    { print -P "%F{green}[✓]%f $*"; }
warn()  { print -P "%F{yellow}[!]%f $*"; }
err()   { print -P "%F{red}[✗]%f $*" >&2; }
info()  { print -P "%F{cyan}[*]%f $*"; }

rule()  { print -P "%F{magenta}─────────────────────────────────────────────────────%f"; }
box()   { local t="$1"; rule; print -P "%F{magenta}■%f $t"; rule; }
banner(){
  local h="$(hostname -s 2>/dev/null || echo archcrypt)"
  local d="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  print -P "%F{magenta}=====================================================%f"
  print -P "%F{magenta} net-toggle — ${h} — ${d}%f"
  print -P "%F{magenta}=====================================================%f"
}
kv()    { printf "    %-18s %s\n" "$1" "$2"; }

# spinner wrapper for a command (zsh-native)
spin() {  # spin "Message…" command args...
  local msg="$1"; shift
  local -a frames=('|' '/' '-' '\'); local i=1 n=${#frames}
  print -n -- " $msg "
  { "$@" &>/tmp/.nettoggle.step.log; } &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    print -nr -- "\r $msg ${frames[i]}"
    (( i = (i % n) + 1 ))
    sleep 0.1
  done
  local rc=0; wait $pid || rc=$?
  print -r -- "\r $msg   "
  return $rc
}

### ------------- ROOT RE-EXEC -------------
if [[ $EUID -ne 0 ]]; then
  exec sudo -E "$0" "$@"
fi

### ------------- COMMON UTILS -------------
readf(){ [[ -r "$1" ]] && <"$1" tr -d '\n' || true; }

# 1s throughput sample (Mb/s, 1 decimal) from /sys counters
sample_iface_mbps(){
  local ifc="$1" rx1 tx1 rx2 tx2 dt=1
  rx1=$(readf "/sys/class/net/$ifc/statistics/rx_bytes"); tx1=$(readf "/sys/class/net/$ifc/statistics/tx_bytes")
  sleep "$dt"
  rx2=$(readf "/sys/class/net/$ifc/statistics/rx_bytes"); tx2=$(readf "/sys/class/net/$ifc/statistics/tx_bytes")
  local drx=$(( rx2 > rx1 ? rx2 - rx1 : 0 ))
  local dtx=$(( tx2 > tx1 ? tx2 - tx1 : 0 ))
  printf "%.1f %.1f\n" "$(( drx * 8 ))e-6" "$(( dtx * 8 ))e-6" 2>/dev/null
}

tor_status(){
  local svc="inactive"; systemctl is-active --quiet tor && svc="active"
  local proxy="none"
  [[ -n "${http_proxy:-}${HTTP_PROXY:-}${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}" ]] && proxy="env-proxy"
  kv "Tor service" "$svc"
  kv "Proxy env"   "$proxy"
}

list_ifaces(){ ip -o link show | awk -F': ' '$2!="lo"{print $2}'; }

default_dev(){
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
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
  local type=""
  [[ "$ifc" == wl* || "$ifc" == wlan* ]] && type="wifi"
  [[ -z "$type" ]] && type="ethernet"
  local ip4="$(ip -o -4 addr show "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd ' ')"
  local ip6="$(ip -o -6 addr show "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd ' ')"
  local state="$(ip -o link show "$ifc" | awk '{print $9}')"
  local ssid="" rate=""
  if [[ "$type" == "wifi" ]] && command -v nmcli &>/dev/null; then
    ssid="$(nmcli -t -f GENERAL.CONNECTION dev show "$ifc" 2>/dev/null | awk -F: '{print $2}')"
    rate="$(nmcli -t -f WIFI.BITRATE dev show "$ifc" 2>/dev/null | awk -F: '{print $2}')"
  fi
  [[ -z "$rate" ]] && rate="$(iw dev "$ifc" link 2>/dev/null | awk -F': ' '/tx bitrate/ {print $2 " (iw)"}')"
  kv "Interface" "$ifc (${type})"
  kv "State"     "$state"
  [[ -n "$ssid" ]] && kv "SSID" "$ssid"
  [[ -n "$rate" ]] && kv "Link rate" "$rate"
  kv "IPv4"      "${ip4:-—}"
  kv "IPv6"      "${ip6:-—}"
}

# NM Wi-Fi connect helper
nm_connect_wifi_preferred(){
  local -a wifi_devs; wifi_devs=("${(@f)$(nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="wifi"{print $1}')}") || true
  (( ${#wifi_devs} )) || return 1
  nmcli dev wifi rescan 2>/dev/null || true
  if (( ${#PREFERRED_SSIDS} )); then
    local ssid
    for ssid in "${PREFERRED_SSIDS[@]}"; do
      info "Trying SSID: $ssid"
      if nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="wifi"{print $1}' | grep -Fxq "$ssid"; then
        nmcli connection up id "$ssid" && { ok "Connected: $ssid"; return 0; }
      fi
      nmcli dev wifi connect "$ssid" && { ok "Connected: $ssid"; return 0; }
      warn "No joy on $ssid"
    done
    return 1
  else
    local d; for d in "${wifi_devs[@]}"; do nmcli dev connect "$d" 2>/dev/null || true; done
    sleep 1
    nmcli -t -f DEVICE,STATE dev | awk -F: '$2=="connected"{exit 1}'; local rc=$?
    return $((rc==1?0:1))
  fi
}

nm_up(){
  box "NetworkManager up"
  spin "Enabling NM networking…"  nmcli networking on || true
  spin "Restarting NetworkManager…" systemctl restart NetworkManager || true
  spin "Ensuring radios allowed (Wi-Fi/WWAN) …" sh -c 'nmcli radio wifi on; nmcli radio wwan on' || true

  # Ethernet first
  info "Connecting Ethernet (if present)…"
  nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="ethernet"{print $1}' | while read -r e; do nmcli dev connect "$e" 2>/dev/null || true; done

  # Wi-Fi next
  nm_connect_wifi_preferred || info "Letting NM autoconnect…"
}

nm_down(){
  box "NetworkManager down"
  local -a connd; connd=("${(@f)$(nmcli -t -f DEVICE,STATE dev | awk -F: '$2=="connected"{print $1}')}") || true
  if (( ${#connd} )); then
    info "Disconnecting: ${connd[*]}"
    local d; for d in "${connd[@]}"; do nmcli dev disconnect "$d" 2>/dev/null || true; done
  else
    info "No connected devices."
  fi
  spin "Turning NM networking off…" nmcli networking off || true
}

### --------------- COMMANDS ---------------
cmd_on(){
  clear; banner
  box "Overview"
  kv "User"   "${SUDO_USER:-$USER}"
  kv "Kernel" "$(uname -r)"
  kv "TTY"    "$(tty 2>/dev/null || echo n/a)"
  rule; print

  # Reverse persistent air-gap from secure-shutdown
  if command -v rfkill &>/dev/null; then
    spin "Clearing persistent rfkill (wifi/wwan/bt)…" rfkill unblock all || true
  fi

  if command -v nmcli &>/dev/null; then
    # Ensure NM radios are allowed in-session
    sh -c 'nmcli radio all on' 2>/dev/null || true
    nm_up
  elif systemctl is-active --quiet iwd || systemctl is-enabled --quiet iwd 2>/dev/null; then
    box "iwd path (no NetworkManager)"
    spin "Restarting iwd…" systemctl restart iwd || true
    typeset -a WLANS; WLANS=("${(@f)$(ls /sys/class/net | grep -E '^wl|^wlan' || true)}")
    if (( ${#WLANS} )); then
      local w="${WLANS[1]}"; spin "Scanning on ${w}…" iwctl station "$w" scan || true
      if (( ${#PREFERRED_SSIDS} )); then
        local connected=0 ssid
        for ssid in "${PREFERRED_SSIDS[@]}"; do
          info "Trying SSID: $ssid"
          if iwctl station "$w" connect "$ssid" &>/tmp/.nettoggle.iwd.log; then
            ok "Connected: $ssid"; connected=1; break
          fi
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
    box "Minimal wired fallback (no NM/iwd)"
    info "Bringing non-loopback links up…"
    local dev; for dev in ${(f)"$(list_ifaces)"}; do ip link set "$dev" up 2>/dev/null || true; done
    info "Attempting DHCP on common wired names…"
    for dev in eth0 eno1 enp0s25 enp3s0 enp2s0; do
      command -v dhcpcd &>/dev/null && dhcpcd -n "$dev" 2>/dev/null || true
      command -v dhclient &>/dev/null && dhclient -1 "$dev" 2>/dev/null || true
    done
  fi

  # Quick connectivity sanity (noisy but useful)
  box "Connectivity check"
  local gw dev; dev="$(default_dev || true)"; gw="$(ip route show default | awk '/default/{print $3; exit}')"
  [[ -n "$gw" ]] && (ping -W1 -c1 "$gw" &>/dev/null && ok "Ping gateway $gw (dev $dev)") || warn "Gateway ping skipped/failed"
  (ping -W1 -c1 1.1.1.1 &>/dev/null && ok "Ping 1.1.1.1 OK") || warn "No ICMP to 1.1.1.1"
  (getent hosts archlinux.org &>/dev/null && ok "DNS OK (archlinux.org)") || warn "DNS lookup failed (archlinux.org)"

  print; box "Basics"
  net_basics
  print; box "Interfaces"
  local ifc; for ifc in ${(f)"$(list_ifaces)"}; do iface_info "$ifc"; rule; done

  if command -v nmcli &>/dev/null; then
    box "Active NM connections"
    nmcli -t -f NAME,TYPE,DEVICE connection show --active | awk -F: '{printf "    %-18s %-8s %s\n",$1,$2,$3}'
  fi
  ok "Networking is up. 🚀"
}

cmd_off(){
  local airgap=0
  [[ "${1:-}" == "--airgap" ]] && airgap=1

  clear; banner
  box "Tear down networking"
  if command -v nmcli &>/dev/null; then
    nm_down
  fi

  # Bring all non-loopback links down (belt+suspenders)
  info "Bringing non-loopback links down…"
  local dev; for dev in ${(f)"$(list_ifaces)"}; do ip link set "$dev" down 2>/dev/null || true; done

  # Optionally enforce persistent Wi-Fi rfkill (air-gap)
  if (( airgap )); then
    if command -v rfkill &>/dev/null; then
      spin "Applying persistent Wi-Fi rfkill (air-gap) …" rfkill block wifi || true
      warn "Wi-Fi is now hard-blocked across reboots. Use 'rfkill unblock wifi' or 'net-toggle on' later."
    else
      warn "rfkill not installed; cannot air-gap persistently."
    fi
  else
    info "Non-persistent shutdown (radios will work on next boot)."
  fi

  print; box "Post-teardown check"
  net_basics
  print; box "Interfaces"
  local ifc; for ifc in ${(f)"$(list_ifaces)"}; do iface_info "$ifc"; rule; done
  ok "Networking is off. 🔒"
}

cmd_status(){
  clear; banner

  box "Overview"
  kv "User"   "${SUDO_USER:-$USER}"
  kv "Kernel" "$(uname -r)"
  kv "TTY"    "$(tty 2>/dev/null || echo n/a)"
  rule; print

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

  box "Interfaces (with 1s throughput sample)"
  local ifc rx tx
  for ifc in ${(f)"$(list_ifaces)"}; do
    iface_info "$ifc"
    read rx tx < <(sample_iface_mbps "$ifc" || echo "0.0 0.0")
    kv "Throughput" "↓ ${rx} Mb/s   ↑ ${tx} Mb/s"
    rule
  done

  box "Tor"
  tor_status

  ok "Status captured. 📊"
}

### ---------------- DISPATCH ---------------
case "${1:-}" in
  on)      shift; cmd_on "$@" ;;
  off)     shift; cmd_off "$@" ;;
  status)  shift; cmd_status "$@" ;;
  *)
    print -P "%F{yellow}Usage:%f net-toggle {on|off|status} [--airgap]"
    print "  on       : bring networking up (prefers NM; falls back to iwd/manual)"
    print "  off      : bring networking down (add --airgap for persistent Wi-Fi rfkill)"
    print "  status   : show connection/Tor/DNS/gateway + 1s throughput sample"
    exit 2
    ;;
esac

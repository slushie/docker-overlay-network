#!/usr/bin/env bash

set -eu
[[ -n ${DEBUG:-} ]] && set -x

## only used with docker for mac
if [[ $(uname -s) != "Darwin" ]]; then
  err "This script is only used with Docker for Mac"
  exit 2
fi

# public vars, may be overridden
: ${CONFIG_DIR:=$HOME/Library/Application Support/docker-overlay-network}
: ${TOOLS_REF:=slushie/docker-overlay-network/tools:release}
: ${OVERWRITE:=}

# private vars, set statically in this script
declare -r wg_listen_port=5060
declare -r wg_host=198.18.1.1
declare -r wg_peer=198.18.1.2
declare -r wg_network=198.18.1.0/24
declare -r dkr_network=198.18.0.0/24
declare -r dkr_vpnkit=192.168.65.2
declare -r host_dns_name=host.kimmy

function err () { echo >&2 -e "\033[1;91mERROR\033[39m: $@\033[0m"; }
function log () { echo >&2 -e "\033[1m$@\033[0m"; }
function value () { echo -en "\033[34m$@\033[39m"; }
function success () { echo >&2 -e "\033[1;92mOK\033[39m: $@\033[0m"; }

function dry_run () { [[ -n "${DRY_RUN:=}" ]]; }

function run () {
  log "$([[ -f /.dockerenv ]] && echo '>>' || echo ' >') \033[0m$@"
  dry_run || "$@"
}

function add_routes_for_net () {
  set -eu

  declare iface=$1
  declare network=$2
  declare peer=$3

  if [[ $iface != $(route get $network | awk '/interface:/{print $2}') ]]; then
    log Adding routes for network $(value $network)
    run route -q -n delete -inet $network || true
    run route -q -n add -inet -interface $network $peer
  fi
}

function add_routes_for_p2p () {
  set -eu

  declare iface=$1
  declare host=$2
  declare peer=$3

  if [[ $iface != $(route get $peer | awk '/interface:/{print $2}') ]]; then
    log Adding P2P route for $(value $host) '<->' $(value $peer)
    run route -q -n delete -inet $peer || true
    run route -q -n add -inet -interface $peer $host
  fi
}

if [[ -z "$(which wireguard-go)" ]]; then
    log WireGuard binary missing, installing $(value wireguard-tools)
    run brew install wireguard-tools
    if [[ -z "$(which wireguard-go)" ]]; then
        err "Failed :("
        exit 1
    fi
fi

log Configuring your Mac to run WireGuard. '(requires sudo)'
sudo true

if [[ -n "${OVERWRITE}" ]]; then
  log "Overwriting all existing configuration."
  run sudo rm -rf "$CONFIG_DIR" /var/run/wireguard /tmp/kimmy.lock
  route get default >/dev/null || true
fi

umask 057
mkdir -p "$CONFIG_DIR"

log Creating WireGuard keys
if [[ -e "$CONFIG_DIR"/host.key ]]; then
  success Keys already exist
else
  run wg genkey > "$CONFIG_DIR"/host.key
  run wg genkey > "$CONFIG_DIR"/peer.key
  run wg pubkey < "$CONFIG_DIR"/host.key > "$CONFIG_DIR"/host.pub
  run wg pubkey < "$CONFIG_DIR"/peer.key > "$CONFIG_DIR"/peer.pub
fi


log Creating a WireGuard host config
if [[ -e "$CONFIG_DIR"/wg-host.conf ]]; then
  success WireGuard host config already exists.
else
  cat > "$CONFIG_DIR"/wg-host.conf <<EOF
[Interface]
PrivateKey = $(cat "$CONFIG_DIR"/host.key)
ListenPort = $wg_listen_port

[Peer]
PublicKey = $(cat "$CONFIG_DIR"/peer.pub)
AllowedIPs = $wg_network, $dkr_network
PersistentKeepalive = 25
EOF
fi

declare iface=
declare iface_file=/var/run/wireguard/kimmy.name
if sudo test -e $iface_file; then
  iface=$(sudo cat $iface_file)
fi

if [[ -z "$iface" ]] || ! ifconfig $iface >/dev/null 2>&1; then
  # no interface
  log Creating WireGuard interface
  sudo mkdir -p /var/run/wireguard
  run sudo env WG_TUN_NAME_FILE=$iface_file wireguard-go utun
  iface=$(sudo cat $iface_file)
else
  success WireGuard interface $(value $iface) already exists.
fi

log Starting WireGuard interface
if [[ $(ifconfig $iface | grep -c -F -e UP -e "inet $wg_host") == "2" ]]; then
  success WireGuard host interface $(value $iface) is already configured.
else
  log Configuring $(value $iface) interface
  run sudo wg setconf $iface "$CONFIG_DIR"/wg-host.conf
  run sudo ifconfig $iface $wg_host $wg_peer up
fi

cat <(set | awk '!/^[A-Z0-9_]+=/{print}') - <<'EOF' | sudo bash -
add_routes_for_p2p $iface $wg_host $wg_peer
add_routes_for_net $iface $wg_network $wg_peer
add_routes_for_net $iface $dkr_network $wg_peer
EOF

log Trying to resolve $(value $host_dns_name)
if [[ -n "$(dscacheutil -q host -a name "$host_dns_name")" ]] ; then
  success Resolved OK
else
  log Adding /etc/hosts entry for $(value $host_dns_name)
  cat <<EOF | run sudo sh -c 'cat >> /etc/hosts'

# This entry added by Kimmy at $(date)
$wg_host $host_dns_name
EOF
  success Added hosts entry
fi

log Creating a WireGuard peer config
if [[ -e "$CONFIG_DIR"/wg-peer.conf ]]; then
  success WireGuard peer config already exists.
else
  cat > "$CONFIG_DIR"/wg-peer.conf <<EOF
[Interface]
Address = $wg_peer
PrivateKey = $(cat "$CONFIG_DIR"/peer.key)
ListenPort = $wg_listen_port

[Peer]
PublicKey = $(cat "$CONFIG_DIR"/host.pub)
AllowedIPs = $wg_network
Endpoint = $dkr_vpnkit:$wg_listen_port
PersistentKeepalive = 25
EOF
fi

log Configuring Docker for Mac to run WireGuard via "[$TOOLS_REF]"
declare -r peer_config="$(cat "$CONFIG_DIR"/wg-peer.conf)"
cat <(set | awk '!/^[A-Z0-9_]+=/{print}') - <<EOF | \
docker run --privileged -i --rm --net host --pid host \
    -v /dev/net/tun:/dev/net/tun \
    -v "$CONFIG_DIR/wg-peer.conf:/etc/wireguard/kimmy.conf" \
    $TOOLS_REF bash -
set -e

try_ping_host () { run ping -W1 -c1 $wg_host >/dev/null; }

if try_ping_host; then
  success Peer network is available.
  exit 0
fi

if run ip -o link | grep -q kimmy; then
  log Removing existing WireGuard interface.
  run ip link del kimmy
fi

log Checking Docker Desktop for WireGuard support
if ! grep -q wireguard /proc/modules; then
  declare kernel_version="\$(uname -r)"
  err WireGuard kernel module is not shipped by your version of Docker
  if [[ ! -f /lib/kimmy-modules/\$kernel_version/wireguard.ko ]]; then
    err Cannot find WireGuard module for \$kernel_version
    exit 1
  fi
  insmod /lib/kimmy-modules/\$kernel_version/wireguard.ko
  success WireGuard kernel module loaded from internal distribution
else
  success WireGuard kernel module is available
fi

log Bringing up WireGuard peer interface
run wg-quick up kimmy

log Trying to reach host $(value $wg_host) from Docker for Mac $(value $wg_peer)
try_ping_host
success Peer network is available.
EOF

log Trying to reach Docker for Mac $(value $wg_peer) from host $(value $wg_host)
run ping -W100 -c1 $wg_peer >/dev/null
success Host network is available.

log Trying to reach Docker network $(value $dkr_network) from host $(value $wg_host)
run ping -W100 -c1 $(perl -pe 's,\d+/\d+$,1,' <<<"$dkr_network") >/dev/null
success Docker network is available.

if ! ( set -C ; 2>/dev/null >/tmp/kimmy.lock ); then
  log Already monitoring route changes as PID $(</tmp/kimmy.lock)
  exit 0
fi

cat <(set | awk '!/^[A-Z0-9_]+=/{print}') - <<'EOF' \
  | sudo bash -c "exec -a 'route-monitor $iface' bash -" &
set -eu
declare pgid=$(ps -o pgid= $$ | tr -cd 0-9)

log Monitoring route changes in the background as $$

out () { echo "[$(date)]" "$@"; }

exec >/dev/null 2>&1
trap "out goodbye; rm -f /tmp/kimmy.lock" EXIT
trap "trap - TERM INT; kill -- -$pgid; exit" TERM INT

out started as PID $$ from PPID $PPID in PGID $pgid
echo $$ >/tmp/kimmy.lock

while read -r event; do
  [[ -e /tmp/kimmy.lock ]]        || exit
  ifconfig $iface >/dev/null 2>&1 || exit

  out "$event"
  if [[ "$event" == RTM_DELETE:* ]]; then
    add_routes_for_p2p $iface $wg_host $wg_peer
    add_routes_for_net $iface $wg_network $wg_peer
    add_routes_for_net $iface $dkr_network $wg_peer
  fi
done < <(route -n monitor)
EOF

disown
sleep 1

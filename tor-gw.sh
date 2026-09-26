#!/usr/bin/env bash

set -euo pipefail

VERSION="2.0"

SSH_PORT=22
TOR_PORT=9040
DNS_PORT=5353

STATE_DIR="/etc/tor-gw"
STATE_FILE="$STATE_DIR/gw.conf"
RULE_FILE="$STATE_DIR/firewall.rules"
BACKUP_FILE="$STATE_DIR/firewall.backup"

#######################################
# Logging
#######################################

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

info(){
    echo -e "${CYAN}[INFO]${NC} $1"
}

ok(){
    echo -e "${GREEN}[ OK ]${NC} $1"
}

fail(){
    echo -e "${RED}[FAIL]${NC} $1" >&2
    exit 1
}

#######################################
# Root check
#######################################

require_root(){
    [[ $EUID -eq 0 ]] || fail "Run as root"
}

#######################################
# Dependency check
#######################################

check_dependencies(){

    info "Checking dependencies"

    for cmd in ip iptables iptables-save iptables-restore awk grep tor; do
        command -v "$cmd" >/dev/null ||
        fail "$cmd not installed"
    done

    [[ -f /etc/tor/torrc ]] ||
    fail "/etc/tor/torrc not found"

    ok "Dependencies OK"
}

#######################################
# Network detection
#######################################

detect_network(){

    info "Detecting network"

    WAN_IFACE=$(ip route |
        awk '/default/ {print $5; exit}')

    WAN_GATEWAY=$(ip route |
        awk '/default/ {print $3; exit}')

    WAN_IP=$(ip -4 addr show "$WAN_IFACE" |
        awk '/inet / {print $2}' |
        cut -d/ -f1)

    [[ -n "$WAN_IFACE" ]] ||
    fail "WAN interface not found"

    LAN_IFACE=$(ip link |
        awk -F': ' '{print $2}' |
        grep -v lo |
        grep -v "$WAN_IFACE" |
        sed '/^$/d' |
        head -1)

    [[ -n "$LAN_IFACE" ]] ||
    fail "LAN interface not found"

    LAN_IP=$(ip -4 addr show "$LAN_IFACE" |
        awk '/inet / {print $2}' |
        cut -d/ -f1)

    LAN_NETWORK=$(ip route |
        grep "$LAN_IFACE" |
        awk '{print $1}' |
        head -1)

    ok "WAN detected: $WAN_IFACE"
    ok "LAN detected: $LAN_IFACE"
}

#######################################
# Show configuration
#######################################

show_config(){

    echo

    echo "=============================="
    echo " TOR-GW CONFIGURATION"
    echo "=============================="

    echo

    echo "WAN"
    echo " Interface : $WAN_IFACE"
    echo " IP        : $WAN_IP"
    echo " Gateway   : $WAN_GATEWAY"

    echo

    echo "LAN"
    echo " Interface : $LAN_IFACE"
    echo " IP        : $LAN_IP"
    echo " Network   : $LAN_NETWORK"

    echo
}

#######################################
# Save state
#######################################

save_state(){

    mkdir -p "$STATE_DIR"

    cat > "$STATE_FILE" <<EOF

WAN_IFACE=$WAN_IFACE
WAN_IP=$WAN_IP
WAN_GATEWAY=$WAN_GATEWAY

LAN_IFACE=$LAN_IFACE
LAN_IP=$LAN_IP
LAN_NETWORK=$LAN_NETWORK

EOF

    ok "Configuration saved"
}

#######################################
# Tor configuration
#######################################

configure_tor(){

    local TORRC="/etc/tor/torrc"

    info "Configuring Tor"

    [[ -f "$TORRC" ]] ||
    fail "$TORRC not found"

    # Backup torrc before modifying it
    cp "$TORRC" "${TORRC}.backup"

    # Remove existing managed settings
    sed -i \
        -e '/^RunAsDaemon[[:space:]]/d' \
        -e '/^ClientOnly[[:space:]]/d' \
        -e '/^VirtualAddrNetworkIPv4[[:space:]]/d' \
        -e '/^AutomapHostsOnResolve[[:space:]]/d' \
        -e '/^TransPort[[:space:]]/d' \
        -e '/^DNSPort[[:space:]]/d' \
        -e '/^SocksPort[[:space:]]/d' \
        -e '/^SocksPolicy[[:space:]]/d' \
        -e '/^ControlPort[[:space:]]/d' \
        -e '/^CookieAuthentication[[:space:]]/d' \
        -e '/^AvoidDiskWrites[[:space:]]/d' \
        -e '/^Log notice file[[:space:]]/d' \
        "$TORRC"

    cat >> "$TORRC" <<'EOF'

# ==========================================
# tor-gw configuration
# ==========================================

RunAsDaemon 1

ClientOnly 1

VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1

TransPort 0.0.0.0:9040
DNSPort 0.0.0.0:5353

SocksPort 127.0.0.1:9050
SocksPolicy accept 127.0.0.1
SocksPolicy reject *
ControlPort 127.0.0.1:9051
CookieAuthentication 1

AvoidDiskWrites 1
Log notice file /var/log/tor/notices.log

EOF

    ok "Tor configuration updated"
}

#######################################
# Firewall generation
#######################################

generate_firewall(){

    mkdir -p "$STATE_DIR"

    cat > "$RULE_FILE" <<EOF

*mangle

:PREROUTING ACCEPT
:INPUT ACCEPT
:FORWARD ACCEPT
:OUTPUT ACCEPT
:POSTROUTING ACCEPT

-A FORWARD \
-p tcp \
-m tcp \
--tcp-flags SYN,RST SYN \
-j TCPMSS \
--clamp-mss-to-pmtu

COMMIT


*filter

:INPUT DROP
:FORWARD DROP
:OUTPUT ACCEPT

# Local traffic
-A INPUT \
-i lo \
-j ACCEPT

# Existing connections to the gateway
-A INPUT \
-m conntrack \
--ctstate ESTABLISHED,RELATED \
-j ACCEPT

# SSH management access
-A INPUT \
-p tcp \
--dport $SSH_PORT \
-j ACCEPT

# LAN -> WAN
-A FORWARD \
-i $LAN_IFACE \
-o $WAN_IFACE \
-m conntrack \
--ctstate NEW,RELATED,ESTABLISHED \
-j ACCEPT

# WAN -> LAN: return traffic only
-A FORWARD \
-i $WAN_IFACE \
-o $LAN_IFACE \
-m conntrack \
--ctstate RELATED,ESTABLISHED \
-j ACCEPT

COMMIT


*nat

:PREROUTING ACCEPT
:INPUT ACCEPT
:OUTPUT ACCEPT
:POSTROUTING ACCEPT

# Do not redirect SSH to Tor
-A PREROUTING \
-i $LAN_IFACE \
-p tcp \
--dport $SSH_PORT \
-j RETURN

# Do not redirect traffic destined for the gateway itself
-A PREROUTING \
-d $LAN_IP \
-i $LAN_IFACE \
-j RETURN

# Force LAN DNS through local DNS resolver
-A PREROUTING \
-i $LAN_IFACE \
-p udp \
--dport 53 \
-j REDIRECT \
--to-ports $DNS_PORT

-A PREROUTING \
-i $LAN_IFACE \
-p tcp \
--dport 53 \
-j REDIRECT \
--to-ports $DNS_PORT

# Redirect new TCP connections to Tor
-A PREROUTING \
-i $LAN_IFACE \
-p tcp \
-m conntrack \
--ctstate NEW \
-j REDIRECT \
--to-ports $TOR_PORT

# NAT LAN traffic to WAN
-A POSTROUTING \
-o $WAN_IFACE \
-j MASQUERADE

COMMIT

EOF

    ok "Firewall generated"
}

#######################################
# Validate
#######################################

validate_firewall(){

    info "Testing firewall"

    iptables-restore --test < "$RULE_FILE" ||
    fail "Firewall syntax error"

    ok "Firewall valid"
}

enable_ip_forwarding() {
    info Enabling IPv4 forwarding

    cat > /etc/sysctl.d/99-tor-gw.conf <<EOF
net.ipv4.ip_forward = 1
EOF

    sysctl --system >/dev/null

    if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]; then
        ok IPv4 forwarding enabled
    else
        fail Could not enable IPv4 forwarding

    fi
}

#######################################
# Apply
#######################################

apply_firewall(){

    info "Backing up current firewall"

    {
        iptables-save -t filter
        iptables-save -t nat
        iptables-save -t mangle
        iptables-save -t raw
        iptables-save -t security
    } > "$BACKUP_FILE"

    info "Applying firewall"

    iptables-restore < "$RULE_FILE"

    ok "Firewall applied"
}

#######################################
# Rollback
#######################################

rollback(){

    [[ -f "$BACKUP_FILE" ]] ||
    fail "No backup found"

    iptables-restore < "$BACKUP_FILE"

    ok "Firewall restored"
}

#######################################
# Status
#######################################

status(){

    echo

    echo "TOR-GW STATUS"

    echo

    [[ -f "$STATE_FILE" ]] &&
    cat "$STATE_FILE" ||
    echo "Not configured"
}

#######################################
# Client-side help
#######################################

client_help(){

    echo
    echo "=============================="
    echo " TOR-GW CLIENT SETUP"
    echo "=============================="
    echo

    echo "Example:"
    echo

    echo "1. Show interfaces:"
    echo "   ip -br a"
    echo
    echo "   lo    UP  127.0.0.1/8 ..."
    echo "   eth0  UP  10.0.2.15/24 ..."
    echo "   eth1  UP  ${LAN_IP%.*}.<1-254> ..."
    echo

    echo "2. Set TOR-GW as default route:"
    echo "   ip route replace default via $LAN_IP dev eth1"
    echo

    echo "3. Verify:"
    echo "   ip route"
    echo
    echo "   default via $LAN_IP dev eth1"
    echo

    echo "4. Test:"
    echo "   ping -c 3 $LAN_IP"
    echo "   curl https://check.torproject.org/api/ip"
    echo
}

#######################################
# Setup
#######################################

setup(){

    require_root

    check_dependencies

    detect_network

    show_config

    read -rp "Apply configuration? [Y/n] " answer

    if [[ ! "$answer" =~ ^[Nn]$ ]]; then

        save_state

        configure_tor

        generate_firewall

        validate_firewall

        enable_ip_forwarding

        apply_firewall

        client_help

    else

        echo "Cancelled"

    fi

    echo
    echo -e "\033[1;92m==============================\033[0m"
    echo -e "\033[1;92m This machine is now a TOR-GW \033[0m"
    echo -e "\033[1;92m \033[0m"
    echo -e "\033[1;92m To restore the previous firewall:\033[0m"
    echo -e "\033[1;92m ./tor-gw.sh rollback:\033[0m"
    echo -e "\033[1;92m==============================\033[0m"
    echo
}

#######################################
# Main
#######################################

case "${1:-}" in

    setup)
        setup
        ;;

    status)
        status
        ;;

    rollback)
        require_root
        rollback
        ;;

    detect)
        require_root
        detect_network
        show_config
        ;;

    *)
        cat <<EOF

tor-gw v$VERSION

Usage:

 ./tor-gw.sh setup

 ./tor-gw.sh detect

 ./tor-gw.sh status

 ./tor-gw.sh rollback

EOF
        ;;

esac

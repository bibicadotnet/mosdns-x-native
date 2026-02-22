#!/bin/bash
# setup-geo-firewall.sh
# GeoIP-based firewall with Docker support
# TCP: filter table hashlimit DROP (after allowlist, before ESTABLISHED — counts all packets)
# UDP: raw table hashlimit DROP + NOTRACK → bypass conntrack → lower CPU for DoQ/DoH3

PUBLIC_IP=$(curl -s https://api.ipify.org)

# ==============================
# USER CONFIGURATION
# ==============================
ALLOW_COUNTRIES=("VN" "SG" "JP" "HK")
ALLOW_TCP_PORTS=("22" "2224" "53" "443" "853")
ALLOW_UDP_PORTS=("53" "443" "853")

# PING Configuration
ENABLE_PING=false

# RATE LIMITING
# TCP: filter table (before ESTABLISHED) → hashlimit DROP → counts all packets incl. persistent DoT/DoH
# UDP: raw table (before conntrack) → hashlimit DROP + NOTRACK
ENABLE_RATE_LIMIT=true
RATE_LIMIT_PER_SECOND=200   # The "Warning" threshold. If exceed this, the IP is flagged for penalty.
THROTTLE_RATE=5             # The "Penalty" rate. Flagged IPs are throttled to this PPS & determines Burst size.
PENALTY_TIME=5              # Duration (seconds) an IP remains in the penalty state after triggering.

# ALLOWLIST CONFIGURATION
ALLOWLIST_URLS=(
    "https://hetrixtools.com/resources/uptime-monitor-only-ips.txt"
    "https://www.cloudflare.com/ips-v4/"
)
ALLOWLIST_IPS=("217.15.166.168" "$PUBLIC_IP")

# ==============================
# SYSTEM CONFIGURATION
# ==============================
SCRIPT_DIR="/home/geo-firewall"
DATA_DIR="$SCRIPT_DIR/data"
HASH_DIR="$SCRIPT_DIR/hash"
FIREWALL_SCRIPT="$SCRIPT_DIR/geo-firewall.sh"
SERVICE_FILE="/etc/systemd/system/geo-firewall.service"
RESET_SCRIPT="$SCRIPT_DIR/emergency-reset.sh"

CHAIN_INPUT="GEO_INPUT"
CHAIN_DOCKER="GEO_DOCKER"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# ==============================
# KERNEL HARDENING
# ==============================
apply_kernel_tuning() {
    log "Applying kernel hardening..."
    # Reload xt_recent with correct parameter
    modprobe -r xt_recent 2>/dev/null || true
    modprobe xt_recent ip_pkt_list_tot=1 2>/dev/null || true
    echo "options xt_recent ip_pkt_list_tot=1" > /etc/modprobe.d/xt_recent.conf
    cat > /etc/sysctl.d/99-geo-firewall.conf << 'EOF'
# High-Performance Kernel Tuning (16384 limits)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 16384
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
# MosDNS-X UDP Buffer for DNS-over-QUIC
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
EOF
    sysctl --system >/dev/null
    log "✓ Kernel hardening applied"
}

# ==============================
# CLEANUP FUNCTION
# ==============================
cleanup_all() {
    log "Cleaning up existing configurations..."

    if systemctl is-active --quiet geo-firewall.service 2>/dev/null; then
        systemctl stop geo-firewall.service 2>/dev/null || true
    fi
    systemctl disable geo-firewall.service 2>/dev/null || true

    iptables -D INPUT -j "$CHAIN_INPUT" 2>/dev/null || true
    iptables -D DOCKER-USER -j "$CHAIN_DOCKER" 2>/dev/null || true

    for chain in "$CHAIN_INPUT" "$CHAIN_DOCKER"; do
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
    done

    iptables -t raw -F PREROUTING 2>/dev/null || true
    iptables -t raw -F OUTPUT 2>/dev/null || true

    for ipset_name in "$IPSET_COUNTRY" "$IPSET_ALLOWLIST" "${IPSET_COUNTRY}_tmp" "${IPSET_ALLOWLIST}_tmp"; do
        ipset destroy "$ipset_name" 2>/dev/null || true
    done

    crontab -l 2>/dev/null | grep -v "$FIREWALL_SCRIPT" | crontab - 2>/dev/null || true

    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$SCRIPT_DIR"

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi

    log "✓ Cleanup complete"
}

# ==============================
# INSTALL DEPENDENCIES
# ==============================
log "Installing required packages..."
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ipset iptables-persistent curl
elif command -v yum >/dev/null; then
    yum install -y -q ipset iptables-services curl
else
    log "ERROR: Unsupported package manager"
    exit 1
fi

apply_kernel_tuning
cleanup_all
mkdir -p "$SCRIPT_DIR" "$DATA_DIR" "$HASH_DIR"

# ==============================
# GENERATE EMERGENCY RESET SCRIPT
# ==============================
log "Creating emergency reset script..."

cat > "$RESET_SCRIPT" << 'EOF_RESET'
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="/home/geo-firewall"
FIREWALL_SCRIPT="$SCRIPT_DIR/geo-firewall.sh"
SERVICE_FILE="/etc/systemd/system/geo-firewall.service"
CHAIN_INPUT="GEO_INPUT"
CHAIN_DOCKER="GEO_DOCKER"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"

echo "=========================================="
echo "⚠️  EMERGENCY FIREWALL RESET"
echo "=========================================="

if systemctl is-active --quiet geo-firewall.service 2>/dev/null; then
    systemctl stop geo-firewall.service 2>/dev/null || true
    echo "✓ Service stopped"
fi
systemctl disable geo-firewall.service 2>/dev/null || true

iptables -D INPUT -j "$CHAIN_INPUT" 2>/dev/null || true
iptables -D DOCKER-USER -j "$CHAIN_DOCKER" 2>/dev/null || true

for chain in "$CHAIN_INPUT" "$CHAIN_DOCKER"; do
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
done
echo "✓ Firewall chains removed"

iptables -t raw -F PREROUTING 2>/dev/null || true
iptables -t raw -F OUTPUT 2>/dev/null || true
echo "✓ Raw table cleared"

for ipset_name in "$IPSET_COUNTRY" "$IPSET_ALLOWLIST" "${IPSET_COUNTRY}_tmp" "${IPSET_ALLOWLIST}_tmp"; do
    ipset destroy "$ipset_name" 2>/dev/null || true
done
echo "✓ IPsets destroyed"

crontab -l 2>/dev/null | grep -v "$FIREWALL_SCRIPT" | crontab - 2>/dev/null || true
echo "✓ Cron job removed"

rm -f "$SERVICE_FILE"
systemctl daemon-reload 2>/dev/null || true
echo "✓ Systemd service removed"

rm -rf "$SCRIPT_DIR"
echo "✓ Scripts removed"

rm -f /etc/sysctl.d/99-geo-firewall.conf
sysctl --system >/dev/null 2>&1 || true
echo "✓ Kernel tuning reverted"

mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save 2>/dev/null || true
fi
echo "✓ Configuration saved"

echo "=========================================="
echo "✓ All geo-firewall components removed"
echo "=========================================="
EOF_RESET

chmod +x "$RESET_SCRIPT"

# ==============================
# GENERATE FIREWALL SCRIPT
# ==============================
log "Generating firewall script..."

cat > "$FIREWALL_SCRIPT" << 'EOF_MAIN'
#!/bin/bash
set -euo pipefail

# Configuration (injected by sed)
ALLOW_COUNTRIES=()
ALLOW_TCP_PORTS=()
ALLOW_UDP_PORTS=()
ALLOWLIST_URLS=()
ALLOWLIST_IPS=()
ENABLE_PING=false
ENABLE_RATE_LIMIT=false
RATE_LIMIT_PER_SECOND=100
THROTTLE_RATE=10
PENALTY_TIME=5

# Paths
SCRIPT_DIR="/home/geo-firewall"
DATA_DIR="$SCRIPT_DIR/data"
HASH_DIR="$SCRIPT_DIR/hash"

# Chain/IPSet names
CHAIN_INPUT="GEO_INPUT"
CHAIN_DOCKER="GEO_DOCKER"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"

# Valid IPv4 CIDR: octets 0-255, prefix 1-32 (reject /0)
CIDR_REGEX='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/(3[0-2]|[12][0-9]|[1-9]))?$'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# ==============================
# DOWNLOAD
# Fixed order per source → stable content → stable hash → skip on cron if unchanged
# ==============================
download_raw_allowlist() {
    local raw="$DATA_DIR/allowlist.raw"
    local tmp="$DATA_DIR/tmp_allowlist"
    rm -rf "$tmp" && mkdir -p "$tmp"

    local i=0
    for ip in "${ALLOWLIST_IPS[@]}"; do
        [[ -z "$ip" ]] && continue
        echo "$ip" > "$tmp/$(printf '%03d' $i)_local.txt"
        (( i++ )) || true
    done
    for url in "${ALLOWLIST_URLS[@]}"; do
        [[ -z "$url" ]] && continue
        local file="$tmp/$(printf '%03d' $i)_url.txt"
        curl -sf --connect-timeout 10 --max-time 30 "$url" > "$file" 2>/dev/null &
        (( i++ )) || true
    done
    wait

    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" | sort -u > "$raw" || true
    rm -rf "$tmp"

    if [[ ! -s "$raw" ]]; then
        log "ERROR: allowlist download failed or empty"
        return 1
    fi
}

download_raw_country() {
    local raw="$DATA_DIR/country.raw"
    local tmp="$DATA_DIR/tmp_country"
    rm -rf "$tmp" && mkdir -p "$tmp"

    local sources=(
        "https://raw.githubusercontent.com/ipverse/rir-ip/refs/heads/master/country/__CC__/ipv4-aggregated.txt"
        "https://www.ipdeny.com/ipblocks/data/countries/__CC__.zone"
        "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/__CC__-ipv4-Hackers.Zone.txt"
    )

    local i=0
    for cc in "${ALLOW_COUNTRIES[@]}"; do
        local cc_lower="${cc,,}"
        local cc_upper="${cc^^}"
        for source_template in "${sources[@]}"; do
            local url=""
            if [[ "$source_template" == *"ebrasha"* ]]; then
                url="${source_template//__CC__/$cc_upper}"
            else
                url="${source_template//__CC__/$cc_lower}"
            fi
            local file="$tmp/$(printf '%03d' $i)_${cc}_src.txt"
            curl -sf --connect-timeout 10 --max-time 30 "$url" > "$file" 2>/dev/null &
            (( i++ )) || true
        done
        if [[ "$cc_upper" == "VN" ]]; then
            local file="$tmp/$(printf '%03d' $i)_VN_special.txt"
            curl -sf --connect-timeout 10 --max-time 30 \
                "https://raw.githubusercontent.com/bibicadotnet/IPinfo-VietNam/main/vietnam.txt" > "$file" 2>/dev/null &
            (( i++ )) || true
        fi
    done
    wait

    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" | sort -u > "$raw" || true
    rm -rf "$tmp"

    if [[ ! -s "$raw" ]]; then
        log "ERROR: country download failed or empty"
        return 1
    fi
}

# ==============================
# UPDATE IPSET
# ==============================
update_ipset() {
    local name="$1"
    local ipset_name="$2"
    local ipset_type="$3"
    local maxelem="$4"

    local raw="$DATA_DIR/${name}.raw"
    local hash_file="$HASH_DIR/${name}.raw.hash"
    local tmp_name="${ipset_name}_tmp"

    log "Downloading $name..."
    if [[ "$name" == "allowlist" ]]; then
        download_raw_allowlist || return 1
    else
        download_raw_country || return 1
    fi

    local new_hash
    new_hash=$(sha256sum "$raw" | cut -d' ' -f1)
    local old_hash
    old_hash=$(cat "$hash_file" 2>/dev/null || echo "")

    if [[ "$new_hash" == "$old_hash" ]] && ipset list "$ipset_name" >/dev/null 2>&1; then
        log "✓ $name unchanged — skip"
        return 0
    fi

    if [[ "$new_hash" == "$old_hash" ]]; then
        log "⚠ $name hash match but ipset missing — forcing rebuild"
    else
        log "$name changed — updating..."
    fi

    if ! ipset list "$ipset_name" >/dev/null 2>&1; then
        ipset create "$ipset_name" "$ipset_type" maxelem "$maxelem"
    fi

    ipset destroy "$tmp_name" 2>/dev/null || true
    ipset create "$tmp_name" "$ipset_type" maxelem "$maxelem"
    awk '{print "add '"$tmp_name"' " $0}' "$raw" | ipset restore -!
    ipset swap "$ipset_name" "$tmp_name"
    ipset destroy "$tmp_name"

    echo "$new_hash" > "$hash_file"

    local count
    count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    log "✓ $name updated: $count entries"
    return 2
}

update_ipsets() {
    local allowlist_rc=0 country_rc=0

    update_ipset "allowlist" "$IPSET_ALLOWLIST" "hash:net" "65536"  || allowlist_rc=$?
    update_ipset "country"   "$IPSET_COUNTRY"   "hash:net" "131072" || country_rc=$?

    if [[ $allowlist_rc -eq 0 && $country_rc -eq 0 ]]; then
        log "✓ All data unchanged — nothing to do"
    fi
}

# ==============================
# RATE LIMIT HELPER (xt_recent + hashlimit)
# "If rate > 100/sec, then limit to 10/sec"
# ==============================
add_rate_limit() {
    local table="$1"; local chain="$2"; local proto="$3"; local port="$4"; local prefix="$5"
    local t_flag=""; [[ "$table" == "raw" ]] && t_flag="-t raw"
    local sub="RL_${prefix}"
    iptables $t_flag -N "$sub" 2>/dev/null || iptables $t_flag -F "$sub"

    # 1. PENALTY CHECK: If flagged, enforce 10/sec cap
    iptables $t_flag -A "$sub" -m recent --rcheck --seconds "${PENALTY_TIME}" --name "FLOOD_${prefix}" \
        -m hashlimit --hashlimit-upto "${THROTTLE_RATE}/sec" --hashlimit-burst "${THROTTLE_RATE}" --hashlimit-name "${prefix}_pen" -j RETURN
    
    # 2. PENALTY DROP: If flagged and exceeds 10/sec quota
    iptables $t_flag -A "$sub" -m recent --rcheck --seconds "${PENALTY_TIME}" --name "FLOOD_${prefix}" -j DROP
    
    # 3. DETECTION: sustained rate > RATE_LIMIT_PER_SECOND/sec → flag + DROP
    # burst=RATE_LIMIT_PER_SECOND: allows natural microbursts up to the PPS threshold.
    iptables $t_flag -A "$sub" \
        -m hashlimit --hashlimit-above "${RATE_LIMIT_PER_SECOND}/sec" --hashlimit-burst "${RATE_LIMIT_PER_SECOND}" \
        --hashlimit-name "${prefix}_det" \
        -m recent --set --name "FLOOD_${prefix}" -j DROP

    iptables $t_flag -A "$sub" -j RETURN
    iptables $t_flag -A "$chain" $proto --dport "$port" -j "$sub"
}

# ==============================
# BUILD RAW TABLE
# UDP only: allowlist bypass → hashlimit DROP → NOTRACK valid packets
# OUTPUT: NOTRACK UDP reply packets
# ==============================
build_raw_table() {
    iptables -t raw -F PREROUTING
    iptables -t raw -F OUTPUT

    for port in "${ALLOW_UDP_PORTS[@]}"; do
        # 1. Allowlist bypass
        iptables -t raw -A PREROUTING -p udp --dport "$port" \
            -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN

        if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
            # 2. Rate limit — DROP flood before conntrack
            add_rate_limit "raw" "PREROUTING" "-p udp" "$port" "udp_${port}"
        fi

        # 3. NOTRACK valid UDP — no conntrack entries → lower CPU for DoQ/DoH3
        iptables -t raw -A PREROUTING -p udp --dport "$port" -j CT --notrack

        # 4. NOTRACK reply — reply packets also bypass conntrack
        iptables -t raw -A OUTPUT -p udp --sport "$port" -j CT --notrack
    done

    log "✓ RAW table built (UDP: hashlimit DROP + NOTRACK)"
}

# ==============================
# BUILD CHAIN_INPUT
#
# Rule order:
#  1. lo → ACCEPT
#  2. DROP INVALID
#  3. Docker 172.16.0.0/12 → ACCEPT
#  4. UNTRACKED + GeoIP → ACCEPT    (UDP NOTRACKed from raw table)
#  5. ALLOWLIST → ACCEPT            (bypass rate limit)
#  6. TCP rate limit → DROP         (before ESTABLISHED — counts ALL packets incl. persistent DoT/DoH)
#  7. ESTABLISHED,RELATED → ACCEPT  (TCP — after rate limit)
#  8. GEOIP TCP → ACCEPT            (new TCP connections)
#  9. DROP
# ==============================
build_chain_input() {
    local allowlist_count=$1

    iptables -N "$CHAIN_INPUT" 2>/dev/null || true
    iptables -F "$CHAIN_INPUT"

    # 1. Loopback
    iptables -A "$CHAIN_INPUT" -i lo -j ACCEPT

    # 2. Drop INVALID
    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate INVALID -j DROP

    # 3. Docker internal
    iptables -A "$CHAIN_INPUT" -s 172.16.0.0/12 -j ACCEPT

    # 4. UNTRACKED UDP + GeoIP — handle NOTRACKed UDP from raw table
    if [[ "$ENABLE_PING" == "true" ]]; then
        iptables -A "$CHAIN_INPUT" -p icmp --icmp-type echo-request \
            -m conntrack --ctstate UNTRACKED \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    fi
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p udp --dport "$port" \
            -m conntrack --ctstate UNTRACKED \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done

    # 5. ALLOWLIST — bypass rate limit entirely
    if [[ $allowlist_count -gt 0 ]]; then
        if [[ "$ENABLE_PING" == "true" ]]; then
            iptables -A "$CHAIN_INPUT" -p icmp --icmp-type echo-request \
                -m set --match-set "$IPSET_ALLOWLIST" src -j ACCEPT
        fi
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            iptables -A "$CHAIN_INPUT" -p tcp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j ACCEPT
        done
        for port in "${ALLOW_UDP_PORTS[@]}"; do
            iptables -A "$CHAIN_INPUT" -p udp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j ACCEPT
        done
        log "✓ INPUT: allowlist rules added"
    fi

    # 6. TCP rate limit — BEFORE ESTABLISHED to count all packets incl. persistent connections
    # No --ctstate NEW: DoT/DoH reuse connections, must count all packets not just new
    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            add_rate_limit "filter" "$CHAIN_INPUT" "-p tcp" "$port" "tcp_${port}"
        done
        log "✓ INPUT: TCP rate limit added (${RATE_LIMIT_PER_SECOND}/sec -> ${THROTTLE_RATE}/sec)"
    fi

    # 7. ESTABLISHED/RELATED — after rate limit (TCP only meaningful here)
    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 8. GEOIP TCP — new connections
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done

    # 9. DROP
    iptables -A "$CHAIN_INPUT" -j DROP

    log "✓ INPUT chain built"
}

# ==============================
# BUILD CHAIN_DOCKER
# Same order as INPUT
# ==============================
build_chain_docker() {
    local allowlist_count=$1

    iptables -N DOCKER-USER 2>/dev/null || true
    iptables -N "$CHAIN_DOCKER" 2>/dev/null || true
    iptables -F "$CHAIN_DOCKER"

    # 1. Docker internal
    iptables -A "$CHAIN_DOCKER" -s 172.16.0.0/12 -j RETURN

    # 2. Drop INVALID
    iptables -A "$CHAIN_DOCKER" -m conntrack --ctstate INVALID -j DROP

    # 3. UNTRACKED UDP + GeoIP
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -A "$CHAIN_DOCKER" -p udp --dport "$port" \
            -m conntrack --ctstate UNTRACKED \
            -m set --match-set "$IPSET_COUNTRY" src -j RETURN
    done

    # 4. ALLOWLIST
    if [[ $allowlist_count -gt 0 ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            iptables -A "$CHAIN_DOCKER" -p tcp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        done
        for port in "${ALLOW_UDP_PORTS[@]}"; do
            iptables -A "$CHAIN_DOCKER" -p udp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        done
    fi

    # 5. TCP rate limit — before ESTABLISHED
    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            add_rate_limit "filter" "$CHAIN_DOCKER" "-p tcp" "$port" "docker_tcp_${port}"
        done
    fi

    # 6. ESTABLISHED/RELATED — after rate limit
    iptables -A "$CHAIN_DOCKER" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    # 7. GEOIP TCP
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_DOCKER" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j RETURN
    done

    # 8. DROP
    iptables -A "$CHAIN_DOCKER" -j DROP

    log "✓ Docker chain built"
}

activate_firewall() {
    if ! iptables -C INPUT -j "$CHAIN_INPUT" 2>/dev/null; then
        iptables -I INPUT 1 -j "$CHAIN_INPUT"
    fi

    if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
        if ! iptables -C DOCKER-USER -j "$CHAIN_DOCKER" 2>/dev/null; then
            iptables -I DOCKER-USER 1 -j "$CHAIN_DOCKER" 2>/dev/null || true
        fi
        log "✓ Docker protection enabled"
    fi

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi
    log "✓ Rules saved"
}

# ==============================
# MAIN
# ==============================
main() {
    log "=========================================="
    log "GeoIP Firewall"
    log "=========================================="

    local first_run=false

    if ! iptables -L "$CHAIN_INPUT" -n >/dev/null 2>&1; then
        first_run=true
        log "First run — initializing"

        # Delete hashes to force rebuild after reboot
        rm -f "$HASH_DIR"/*.hash

        ipset create "$IPSET_ALLOWLIST" hash:net maxelem 65536 2>/dev/null || true
        ipset create "$IPSET_COUNTRY" hash:net maxelem 131072 2>/dev/null || true
    fi

    update_ipsets

    if [[ "$first_run" == true ]]; then
        local allowlist_count country_count
        allowlist_count=$(ipset list -t "$IPSET_ALLOWLIST" | awk '/Number of entries:/{print $NF}')
        country_count=$(ipset list -t "$IPSET_COUNTRY" | awk '/Number of entries:/{print $NF}')

        if [[ "$country_count" -eq 0 ]]; then
            log "ERROR: country ipset is empty — aborting to prevent lockout"
            log "       Check network connectivity and try again"
            exit 1
        fi

        build_raw_table
        build_chain_input "$allowlist_count"

        if command -v docker >/dev/null 2>&1; then
            build_chain_docker "$allowlist_count"
        fi

        activate_firewall

        log "=========================================="
        log "✓ FIREWALL ACTIVE"
        log "  Countries:   ${ALLOW_COUNTRIES[*]}"
        log "  TCP Ports:   ${ALLOW_TCP_PORTS[*]}"
        log "  UDP Ports:   ${ALLOW_UDP_PORTS[*]}"
        log "  Allowlist:   $allowlist_count entries"
        log "  Country IPs: $country_count CIDRs"
        [[ "$ENABLE_RATE_LIMIT" == "true" ]] && log "  Rate Limit:  ${RATE_LIMIT_PER_SECOND}/sec -> ${THROTTLE_RATE}/sec (UDP: raw, TCP: filter)"
        log "=========================================="
    else
        log "✓ Done"
    fi
}

main
EOF_MAIN

# ==============================
# INJECT CONFIGURATION
# ==============================
sed -i "/^ALLOW_COUNTRIES=()/ c\ALLOW_COUNTRIES=($(printf '"%s" ' "${ALLOW_COUNTRIES[@]}") )" "$FIREWALL_SCRIPT"
sed -i "/^ALLOW_TCP_PORTS=()/ c\ALLOW_TCP_PORTS=($(printf '"%s" ' "${ALLOW_TCP_PORTS[@]}") )" "$FIREWALL_SCRIPT"
sed -i "/^ALLOW_UDP_PORTS=()/ c\ALLOW_UDP_PORTS=($(printf '"%s" ' "${ALLOW_UDP_PORTS[@]}") )" "$FIREWALL_SCRIPT"
sed -i "/^ALLOWLIST_URLS=()/ c\ALLOWLIST_URLS=($(printf '"%s" ' "${ALLOWLIST_URLS[@]}") )" "$FIREWALL_SCRIPT"
sed -i "/^ALLOWLIST_IPS=()/ c\ALLOWLIST_IPS=($(printf '"%s" ' "${ALLOWLIST_IPS[@]}") )" "$FIREWALL_SCRIPT"
sed -i "/^ENABLE_PING=/ c\ENABLE_PING=\"$ENABLE_PING\"" "$FIREWALL_SCRIPT"
sed -i "/^ENABLE_RATE_LIMIT=/ c\ENABLE_RATE_LIMIT=\"$ENABLE_RATE_LIMIT\"" "$FIREWALL_SCRIPT"
sed -i "/^RATE_LIMIT_PER_SECOND=/ c\RATE_LIMIT_PER_SECOND=\"$RATE_LIMIT_PER_SECOND\"" "$FIREWALL_SCRIPT"
sed -i "/^THROTTLE_RATE=/ c\THROTTLE_RATE=\"$THROTTLE_RATE\"" "$FIREWALL_SCRIPT"
sed -i "/^PENALTY_TIME=/ c\PENALTY_TIME=\"$PENALTY_TIME\"" "$FIREWALL_SCRIPT"

chmod +x "$FIREWALL_SCRIPT"

# ==============================
# SETUP SYSTEMD SERVICE
# ==============================
log "Creating systemd service..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=GeoIP Firewall
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$FIREWALL_SCRIPT
RemainAfterExit=yes
StandardOutput=null
StandardError=null
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable geo-firewall.service

# ==============================
# SETUP CRON JOB
# ==============================
log "Setting up cron job..."

(crontab -l 2>/dev/null || true; echo "30 2 * * * /bin/bash $FIREWALL_SCRIPT >/dev/null 2>&1") | crontab -

# ==============================
# FIRST RUN
# ==============================
log "Applying firewall..."

if "$FIREWALL_SCRIPT"; then
    log "✓ Setup complete"
else
    log "✗ Firewall failed — running emergency reset"
    "$RESET_SCRIPT"
    exit 1
fi

# ==============================
# FINAL SUMMARY
# ==============================
echo ""
echo "╔════════════════════════════════════════╗"
echo "║      GEO FIREWALL INSTALLED            ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "Configuration:"
echo "  • Countries: ${ALLOW_COUNTRIES[*]}"
echo "  • TCP ports: ${ALLOW_TCP_PORTS[*]}"
echo "  • UDP ports: ${ALLOW_UDP_PORTS[*]}"
echo "  • Allowlist: ${#ALLOWLIST_URLS[@]} URLs, ${#ALLOWLIST_IPS[@]} IPs"
echo ""
echo "Rule Order:"
echo "  [raw/PREROUTING — UDP only]"
echo "  1. Allowlist → RETURN"
[[ "$ENABLE_RATE_LIMIT" == "true" ]] && echo "  2. hashlimit UDP ${RATE_LIMIT_PER_SECOND}/sec → DROP"
echo "  3. CT --notrack UDP"
echo ""
echo "  [raw/OUTPUT — UDP only]"
echo "  1. CT --notrack UDP sport"
echo ""
echo "  [filter/INPUT]"
echo "  1. lo → ACCEPT"
echo "  2. DROP INVALID"
echo "  3. Docker 172.16.0.0/12 → ACCEPT"
echo "  4. UNTRACKED + GeoIP → ACCEPT (UDP)"
echo "  5. Allowlist → ACCEPT"
[[ "$ENABLE_RATE_LIMIT" == "true" ]] && echo "  6. hashlimit TCP ${RATE_LIMIT_PER_SECOND}/sec → DROP  (before ESTABLISHED)"
echo "  7. ESTABLISHED/RELATED → ACCEPT"
echo "  8. GeoIP → ACCEPT (TCP)"
echo "  9. DROP"
echo ""
echo "Kernel Hardening: /etc/sysctl.d/99-geo-firewall.conf"
echo ""
echo "Management:"
echo "  • Status:  systemctl status geo-firewall"
echo "  • Update:  $FIREWALL_SCRIPT"
echo "  • Reset:   $RESET_SCRIPT"
echo ""
echo "Rate Limit Stats:"
if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        echo "  • UDP $port: cat /proc/net/ipt_hashlimit/raw_udp_${port}_limit"
    done
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        echo "  • TCP $port: cat /proc/net/ipt_hashlimit/tcp_${port}_limit"
    done
fi
echo ""

exit 0

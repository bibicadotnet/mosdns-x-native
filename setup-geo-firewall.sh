#!/bin/bash
# setup-geo-firewall.sh
# GeoIP-based firewall with Docker support
# DNS protection: RATE_LIMIT only (packets/sec per IP, before ESTABLISHED)
# UDP rate limit in raw table (before conntrack) for lower CPU

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
# TCP: filter table (after conntrack)
# UDP: raw table (before conntrack) → lower CPU for DoH3/DoQ flood
ENABLE_RATE_LIMIT=true
RATE_LIMIT_PER_SECOND=100

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
    cat > /etc/sysctl.d/99-geo-firewall.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
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

    # Clean raw table UDP rules
    iptables -t raw -F PREROUTING 2>/dev/null || true

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

# Paths
SCRIPT_DIR="/home/geo-firewall"
DATA_DIR="$SCRIPT_DIR/data"
HASH_DIR="$SCRIPT_DIR/hash"

# Chain/IPSet names
CHAIN_INPUT="GEO_INPUT"
CHAIN_DOCKER="GEO_DOCKER"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"

CIDR_REGEX='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/(3[0-2]|[12][0-9]|[1-9]))?$'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# ==============================
# DOWNLOAD: each source → separate file, cat in fixed order → grep CIDR → raw
# Fixed order → stable hash → 99% cron runs exit after hash check
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

    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" > "$raw" || true
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

    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" > "$raw" || true
    rm -rf "$tmp"

    if [[ ! -s "$raw" ]]; then
        log "ERROR: country download failed or empty"
        return 1
    fi
}

# ==============================
# UPDATE IPSET PIPELINE:
#   download_raw (fixed order → stable content)
#   → hash(raw) → compare saved hash
#       ├── same + ipset intact → skip (no sort, no swap)
#       └── diff → sort -u → atomic_swap → save hash
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

    local sorted
    sorted=$(sort -u "$raw")
    if [[ -z "$sorted" ]]; then
        log "ERROR: sort produced empty output for $name"
        return 1
    fi

    if ! ipset list "$ipset_name" >/dev/null 2>&1; then
        ipset create "$ipset_name" "$ipset_type" maxelem "$maxelem"
    fi
    ipset destroy "$tmp_name" 2>/dev/null || true
    ipset create "$tmp_name" "$ipset_type" maxelem "$maxelem"
    echo "$sorted" | awk '{print "add '"$tmp_name"' " $0}' | ipset restore -!
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
# BUILD RAW TABLE (UDP only)
# Drop UDP before conntrack → lower CPU for DoH3/DoQ flood
# Allowlist bypass via ipset check
# ==============================
build_raw_udp() {
    iptables -t raw -F PREROUTING

    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_UDP_PORTS[@]}"; do
            # Allowlist bypass
            iptables -t raw -A PREROUTING -p udp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN

            # Rate limit — drop before conntrack
            iptables -t raw -A PREROUTING -p udp --dport "$port" \
                -m hashlimit \
                --hashlimit-mode srcip \
                --hashlimit-above "${RATE_LIMIT_PER_SECOND}/sec" \
                --hashlimit-burst "${RATE_LIMIT_PER_SECOND}" \
                --hashlimit-name "raw_udp_${port}_limit" \
                --hashlimit-htable-expire 10000 \
                -j DROP
        done
        log "✓ RAW: UDP rate limit added (${RATE_LIMIT_PER_SECOND}/sec)"
    fi
}

# ==============================
# BUILD CHAIN_INPUT (TCP only for rate limit)
#
# Rule order:
#  1. lo → ACCEPT
#  2. DROP INVALID
#  3. Docker 172.16.0.0/12 → ACCEPT
#  4. ALLOWLIST → ACCEPT  (bypass rate limit)
#  5. RATE_LIMIT TCP → DROP  (before ESTABLISHED)
#  6. ESTABLISHED,RELATED → ACCEPT
#  7. GEOIP → ACCEPT
#  8. DROP
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

    # 4. ALLOWLIST
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

    # 5. RATE LIMIT TCP — before ESTABLISHED
    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            iptables -A "$CHAIN_INPUT" -p tcp --dport "$port" \
                -m hashlimit \
                --hashlimit-mode srcip \
                --hashlimit-above "${RATE_LIMIT_PER_SECOND}/sec" \
                --hashlimit-burst "${RATE_LIMIT_PER_SECOND}" \
                --hashlimit-name "tcp_${port}_limit" \
                --hashlimit-htable-expire 10000 \
                -j DROP
        done
        log "✓ INPUT: TCP rate limit added (${RATE_LIMIT_PER_SECOND}/sec)"
    fi

    # 6. ESTABLISHED/RELATED — after rate limit
    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 7. GEOIP
    if [[ "$ENABLE_PING" == "true" ]]; then
        iptables -A "$CHAIN_INPUT" -p icmp --icmp-type echo-request \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    fi
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p udp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done

    # 8. DROP
    iptables -A "$CHAIN_INPUT" -j DROP

    log "✓ INPUT chain built"
}

# ==============================
# BUILD CHAIN_DOCKER
# Same order as INPUT, ACCEPT → RETURN
# UDP rate limit handled in raw table
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

    # 3. ALLOWLIST
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

    # 4. RATE LIMIT TCP — before ESTABLISHED
    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            iptables -A "$CHAIN_DOCKER" -p tcp --dport "$port" \
                -m hashlimit \
                --hashlimit-mode srcip \
                --hashlimit-above "${RATE_LIMIT_PER_SECOND}/sec" \
                --hashlimit-burst "${RATE_LIMIT_PER_SECOND}" \
                --hashlimit-name "docker_tcp_${port}_limit" \
                --hashlimit-htable-expire 10000 \
                -j DROP
        done
    fi

    # 5. ESTABLISHED/RELATED — after rate limit
    iptables -A "$CHAIN_DOCKER" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    # 6. GEOIP
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_DOCKER" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j RETURN
    done
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -A "$CHAIN_DOCKER" -p udp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j RETURN
    done

    # 7. DROP
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

        build_raw_udp
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
        [[ "$ENABLE_RATE_LIMIT" == "true" ]] && log "  Rate Limit:  ${RATE_LIMIT_PER_SECOND}/sec (TCP: filter, UDP: raw)"
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
echo "  [raw/PREROUTING - UDP only, before conntrack]"
echo "  1. Allowlist → RETURN"
[[ "$ENABLE_RATE_LIMIT" == "true" ]] && echo "  2. Rate Limit UDP: ${RATE_LIMIT_PER_SECOND}/sec → DROP"
echo ""
echo "  [filter/INPUT - TCP]"
echo "  1. lo → ACCEPT"
echo "  2. DROP INVALID"
echo "  3. Docker 172.16.0.0/12 → ACCEPT"
echo "  4. Allowlist → ACCEPT"
[[ "$ENABLE_RATE_LIMIT" == "true" ]] && echo "  5. Rate Limit TCP: ${RATE_LIMIT_PER_SECOND}/sec → DROP"
echo "  6. ESTABLISHED/RELATED → ACCEPT"
echo "  7. GeoIP → ACCEPT"
echo "  8. DROP"
echo ""
echo "Kernel Hardening: /etc/sysctl.d/99-geo-firewall.conf"
echo ""
echo "Management:"
echo "  • Status:  systemctl status geo-firewall"
echo "  • Update:  $FIREWALL_SCRIPT"
echo "  • Reset:   $RESET_SCRIPT"
echo ""
echo "Rate Limit Stats:"
for port in "${ALLOW_TCP_PORTS[@]}"; do
    [[ "$ENABLE_RATE_LIMIT" == "true" ]] && echo "  • TCP $port: cat /proc/net/ipt_hashlimit/tcp_${port}_limit"
done
for port in "${ALLOW_UDP_PORTS[@]}"; do
    [[ "$ENABLE_RATE_LIMIT" == "true" ]] && echo "  • UDP $port: cat /proc/net/ipt_hashlimit/raw_udp_${port}_limit"
done
echo ""

exit 0

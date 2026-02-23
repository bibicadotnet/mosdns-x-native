#!/bin/bash
# setup-geo-firewall.sh
# GeoIP and Rate Limit protection with Docker support

PUBLIC_IP=$(curl -s https://api.ipify.org)

# ==============================
# USER CONFIGURATION
# ==============================

# Allowed countries (ISO 3166-1 alpha-2 codes)
ALLOW_COUNTRIES=("VN" "SG" "JP" "HK")

# TCP/UDP ports open to allowed countries
ALLOW_TCP_PORTS=("22" "2224" "53" "443" "853")
ALLOW_UDP_PORTS=("53" "443" "853")

# Allow ICMP ping from allowed countries
ENABLE_PING=false

# RATE LIMIT CONFIGURATION
# Rule: If traffic exceeds thresholds, IP is penalized for PENALTY_TIME.
# UDP is limited to 200 PPS, TCP to 5000 PPS.
ENABLE_RATE_LIMIT=true
RATE_LIMIT_UDP=200   # PPS threshold for UDP
RATE_LIMIT_TCP=200  # PPS threshold for TCP
THROTTLE_RATE=5             # PPS limit during penalty phase
PENALTY_TIME=5              # Penalty duration in seconds

# URLs containing IPs that always bypass all rules
ALLOWLIST_URLS=(
    "https://hetrixtools.com/resources/uptime-monitor-only-ips.txt"
    "https://www.cloudflare.com/ips-v4/"
)
# Static IPs that always bypass all rules
ALLOWLIST_IPS=("217.15.166.168" "$PUBLIC_IP")

# ==============================
# PATHS
# ==============================
INSTALL_DIR="/home/geo-firewall"
DATA_DIR="$INSTALL_DIR/data"
HASH_DIR="$INSTALL_DIR/hash"
FIREWALL_SCRIPT="$INSTALL_DIR/geo-firewall.sh"
RESET_SCRIPT="$INSTALL_DIR/emergency-reset.sh"
SERVICE_FILE="/etc/systemd/system/geo-firewall.service"

CHAIN_INPUT="GEO_INPUT"
CHAIN_DOCKER="GEO_DOCKER"
CHAIN_RAW_IN="GEO_RAW_IN"
CHAIN_RAW_OUT="GEO_RAW_OUT"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"
CIDR_REGEX='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/(3[0-2]|[12][0-9]|[1-9]))?$'

# ==============================
# BOOTSTRAP
# ==============================
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "ERROR: Run as root"; exit 1; }
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
trap 'log "ERROR at line $LINENO: $BASH_COMMAND (exit $?)"' ERR

# ==============================
# DEPENDENCIES
# ==============================
install_deps() {
    log "Installing dependencies..."
    if command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ipset iptables-persistent curl
    elif command -v yum >/dev/null; then
        yum install -y -q ipset iptables-services curl
    else
        log "ERROR: Unsupported package manager"; exit 1
    fi
}

# ==============================
# KERNEL HARDENING
# ==============================
apply_kernel_tuning() {
    log "Applying kernel hardening..."
    echo "options xt_recent ip_pkt_list_tot=1" > /etc/modprobe.d/xt_recent.conf
    modprobe -r xt_recent 2>/dev/null || true
    modprobe xt_recent ip_pkt_list_tot=1 2>/dev/null || true

    local val; val=$(cat /sys/module/xt_recent/parameters/ip_pkt_list_tot 2>/dev/null || echo "?")
    [[ "$val" == "1" ]] \
        && log "xt_recent: ip_pkt_list_tot=1 OK" \
        || log "WARNING: xt_recent update failed (val=$val) — reboot may be required"

    cat > /etc/sysctl.d/99-geo-firewall.conf << 'EOF'
# Kernel Tuning
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 16384
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_tw_buckets = 32768
net.ipv4.tcp_slow_start_after_idle = 0
net.core.netdev_max_backlog = 16384
net.core.netdev_budget = 300
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_local_port_range = 32768 60999
EOF
    sysctl --system >/dev/null
    log "Kernel hardening applied"
}

# ==============================
# CLEANUP ALL
# Wipes everything created by this script — runs at start of every setup
# ==============================
cleanup_all() {
    log "Clearing previous installation..."

    systemctl stop    geo-firewall.service 2>/dev/null || true
    systemctl disable geo-firewall.service 2>/dev/null || true

    iptables    -D INPUT       -j "$CHAIN_INPUT"   2>/dev/null || true
    iptables    -D DOCKER-USER -j "$CHAIN_DOCKER"  2>/dev/null || true
    iptables -t raw -D PREROUTING -j "$CHAIN_RAW_IN"  2>/dev/null || true
    iptables -t raw -D OUTPUT     -j "$CHAIN_RAW_OUT" 2>/dev/null || true

    while IFS= read -r chain; do
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
    done < <(iptables-save 2>/dev/null | awk -F'[ :]' '/^:(GEO_|RL_)/{print $2}')

    while IFS= read -r chain; do
        iptables -t raw -F "$chain" 2>/dev/null || true
        iptables -t raw -X "$chain" 2>/dev/null || true
    done < <(iptables -t raw -S 2>/dev/null | awk '/^-N (GEO_|RL_)/{print $2}')

    if [[ -d /proc/net/xt_recent ]]; then
        for f in /proc/net/xt_recent/FLOOD_*; do
            [[ -f "$f" ]] && echo "/" > "$f" 2>/dev/null || true
        done
    fi

    for s in "$IPSET_COUNTRY" "$IPSET_ALLOWLIST" "${IPSET_COUNTRY}_tmp" "${IPSET_ALLOWLIST}_tmp"; do
        ipset destroy "$s" 2>/dev/null || true
    done

    crontab -l 2>/dev/null | grep -v "$FIREWALL_SCRIPT" | crontab - 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -f /etc/sysctl.d/99-geo-firewall.conf
    rm -f /etc/modprobe.d/xt_recent.conf
    rm -rf "$INSTALL_DIR"

    systemctl daemon-reload 2>/dev/null || true
    log "Cleared"
}

# ==============================
# DOWNLOAD
# ==============================
download_allowlist() {
    local tmp; tmp=$(mktemp -d)
    local i=0
    for ip in "${ALLOWLIST_IPS[@]}"; do
        if [[ -n "$ip" ]]; then
            echo "$ip" > "$tmp/$(printf '%04d' $i)_local.txt"
            i=$(( i + 1 ))
        fi
    done
    for url in "${ALLOWLIST_URLS[@]}"; do
        if [[ -n "$url" ]]; then
            curl -sf --connect-timeout 10 --max-time 30 "$url" \
                > "$tmp/$(printf '%04d' $i)_url.txt" 2>/dev/null &
            i=$(( i + 1 ))
        fi
    done
    wait
    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" | sort -u > "$DATA_DIR/allowlist.raw" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/allowlist.raw" ]]; then
        log "ERROR: allowlist download failed"; return 1
    fi
}

download_country() {
    local tmp; tmp=$(mktemp -d)
    local i=0
    local sources=(
        "https://raw.githubusercontent.com/ipverse/rir-ip/refs/heads/master/country/__CC__/ipv4-aggregated.txt"
        "https://www.ipdeny.com/ipblocks/data/countries/__CC__.zone"
        "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/__CC__-ipv4-Hackers.Zone.txt"
    )
    for cc in "${ALLOW_COUNTRIES[@]}"; do
        local cc_lower="${cc,,}"
        local cc_upper="${cc^^}"
        for src in "${sources[@]}"; do
            local url="${src//__CC__/$cc_lower}"
            if [[ "$src" == *"ebrasha"* ]]; then url="${src//__CC__/$cc_upper}"; fi
            curl -sf --connect-timeout 10 --max-time 30 "$url" \
                > "$tmp/$(printf '%04d' $i)_${cc}.txt" 2>/dev/null &
            i=$(( i + 1 ))
        done
        if [[ "$cc_upper" == "VN" ]]; then
            curl -sf --connect-timeout 10 --max-time 30 \
                "https://raw.githubusercontent.com/bibicadotnet/IPinfo-VietNam/main/vietnam.txt" \
                > "$tmp/$(printf '%04d' $i)_VN_extra.txt" 2>/dev/null &
            i=$(( i + 1 ))
        fi
    done
    wait
    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" | sort -u > "$DATA_DIR/country.raw" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/country.raw" ]]; then
        log "ERROR: country download failed"; return 1
    fi
}

# ==============================
# IPSET UPDATE
# Skip rebuild when hash unchanged AND ipset has entries
# ==============================
update_ipset() {
    local name="$1" ipset_name="$2" ipset_type="$3" maxelem="$4"
    local raw="$DATA_DIR/${name}.raw"
    local hash_file="$HASH_DIR/${name}.sha256"
    local tmp_name="${ipset_name}_tmp"

    log "Downloading $name..."
    if [[ "$name" == "allowlist" ]]; then
        download_allowlist || return 1
    else
        download_country || return 1
    fi

    local new_hash old_hash current_count
    new_hash=$(sha256sum "$raw" | cut -d' ' -f1)
    old_hash=$(cat "$hash_file" 2>/dev/null || echo "")

    current_count=0
    if ipset list "$ipset_name" >/dev/null 2>&1; then
        current_count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    fi

    if [[ "$new_hash" == "$old_hash" && "$current_count" -gt 0 ]]; then
        log "$name: unchanged ($current_count entries), skipping"
        return 0
    fi

    log "$name: rebuilding ipset..."
    ipset create "$ipset_name" "$ipset_type" maxelem "$maxelem" 2>/dev/null || true
    ipset destroy "$tmp_name" 2>/dev/null || true
    ipset create  "$tmp_name" "$ipset_type" maxelem "$maxelem"
    awk -v s="$tmp_name" '{print "add " s " " $0}' "$raw" | ipset restore -!
    ipset swap "$ipset_name" "$tmp_name"
    ipset destroy "$tmp_name"
    echo "$new_hash" > "$hash_file"

    local count; count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    log "$name: $count entries loaded"
}

update_ipsets() {
    mkdir -p "$DATA_DIR" "$HASH_DIR"
    update_ipset "allowlist" "$IPSET_ALLOWLIST" "hash:net" "65536"  || true
    update_ipset "country"   "$IPSET_COUNTRY"   "hash:net" "131072" || true

    local count; count=$(ipset list -t "$IPSET_COUNTRY" | awk '/Number of entries:/{print $NF}')
    if [[ "$count" -eq 0 && "${#ALLOW_COUNTRIES[@]}" -gt 0 ]]; then
        log "ERROR: country ipset empty — check connectivity"; exit 1
    fi
}

# ==============================
# RATE LIMIT SUB-CHAIN
#
# Two-phase logic per IP:
#   Phase 1 — PENALTY:  if flagged, allow up to THROTTLE_RATE PPS, drop rest
#   Phase 2 — DETECT:   if traffic > rate PPS, flag IP and drop
#
# Placed BEFORE ESTABLISHED: DoT/DoH reuse connections → must count all packets
# ==============================
add_rate_limit() {
    local table="$1" chain="$2" proto="$3" port="$4" prefix="$5" rate="$6"
    local t_flag=""
    if [[ "$table" == "raw" ]]; then t_flag="-t raw"; fi
    local sub="RL_${prefix}"

    iptables $t_flag -N "$sub" 2>/dev/null || iptables $t_flag -F "$sub"

    iptables $t_flag -A "$sub" -m recent --rcheck --seconds "$PENALTY_TIME" --name "FLOOD_${prefix}" \
        -m hashlimit --hashlimit-upto "${THROTTLE_RATE}/sec" --hashlimit-burst "$THROTTLE_RATE" \
        --hashlimit-name "${prefix}_pen" -j RETURN
    iptables $t_flag -A "$sub" -m recent --rcheck --seconds "$PENALTY_TIME" --name "FLOOD_${prefix}" \
        -j DROP

    iptables $t_flag -A "$sub" \
        -m hashlimit --hashlimit-above "${rate}/sec" --hashlimit-burst "$rate" \
        --hashlimit-name "${prefix}_det" \
        -m recent --set --name "FLOOD_${prefix}" -j DROP

    iptables $t_flag -A "$sub" -j RETURN
    iptables $t_flag -A "$chain" $proto --dport "$port" -j "$sub"
}

# ==============================
# RAW TABLE (UDP only)
#
# Allowlist bypass → rate limit DROP → NOTRACK
# NOTRACK skips conntrack entirely → lower CPU for DoQ/DoH3
# OUTPUT: NOTRACK reply packets too
# ==============================
build_raw_table() {
    iptables -t raw -N "$CHAIN_RAW_IN"  2>/dev/null || iptables -t raw -F "$CHAIN_RAW_IN"
    iptables -t raw -N "$CHAIN_RAW_OUT" 2>/dev/null || iptables -t raw -F "$CHAIN_RAW_OUT"
    iptables -t raw -C PREROUTING -j "$CHAIN_RAW_IN"  2>/dev/null \
        || iptables -t raw -I PREROUTING 1 -j "$CHAIN_RAW_IN"
    iptables -t raw -C OUTPUT     -j "$CHAIN_RAW_OUT" 2>/dev/null \
        || iptables -t raw -I OUTPUT     1 -j "$CHAIN_RAW_OUT"

    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -t raw -A "$CHAIN_RAW_IN" -p udp --dport "$port" \
            -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
            add_rate_limit raw "$CHAIN_RAW_IN" "-p udp" "$port" "udp_${port}" "$RATE_LIMIT_UDP"
        fi
        iptables -t raw -A "$CHAIN_RAW_IN"  -p udp --dport "$port" -j CT --notrack
        iptables -t raw -A "$CHAIN_RAW_OUT" -p udp --sport "$port" -j CT --notrack
    done
    log "RAW table built (UDP NOTRACK)"
}

# ==============================
# INPUT CHAIN
#
#   1. lo               → ACCEPT
#   2. INVALID          → DROP
#   3. Docker 172/12    → ACCEPT
#   4. UNTRACKED + GeoIP→ ACCEPT  (UDP NOTRACKed in raw table)
#   5. Allowlist        → ACCEPT  (bypass rate limit)
#   6. TCP rate limit   → DROP    (before ESTABLISHED — counts all packets)
#   7. ESTABLISHED      → ACCEPT
#   8. GeoIP TCP        → ACCEPT
#   9. Default          → DROP
# ==============================
build_input_chain() {
    local allowlist_count="$1"
    iptables -N "$CHAIN_INPUT" 2>/dev/null || iptables -F "$CHAIN_INPUT"
    iptables -C INPUT -j "$CHAIN_INPUT" 2>/dev/null \
        || iptables -I INPUT 1 -j "$CHAIN_INPUT"

    iptables -A "$CHAIN_INPUT" -i lo -j ACCEPT
    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate INVALID -j DROP
    iptables -A "$CHAIN_INPUT" -s 172.16.0.0/12 -j ACCEPT

    if [[ "$ENABLE_PING" == "true" ]]; then
        iptables -A "$CHAIN_INPUT" -p icmp --icmp-type echo-request \
            -m conntrack --ctstate UNTRACKED -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    fi
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p udp --dport "$port" \
            -m conntrack --ctstate UNTRACKED -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done

    if [[ "$allowlist_count" -gt 0 ]]; then
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
        log "INPUT: allowlist rules added ($allowlist_count entries)"
    fi

    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            add_rate_limit filter "$CHAIN_INPUT" "-p tcp" "$port" "tcp_${port}" "$RATE_LIMIT_TCP"
        done
        log "INPUT: rate limit TCP=${RATE_LIMIT_TCP}/s → throttle=${THROTTLE_RATE}/s"
    fi

    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done

    iptables -A "$CHAIN_INPUT" -j DROP
    log "INPUT chain built"
}

# ==============================
# DOCKER CHAIN (mirrors INPUT, uses RETURN instead of ACCEPT)
# ==============================
build_docker_chain() {
    local allowlist_count="$1"
    iptables -N DOCKER-USER    2>/dev/null || true
    iptables -N "$CHAIN_DOCKER" 2>/dev/null || iptables -F "$CHAIN_DOCKER"
    iptables -C DOCKER-USER -j "$CHAIN_DOCKER" 2>/dev/null \
        || iptables -I DOCKER-USER 1 -j "$CHAIN_DOCKER"

    iptables -A "$CHAIN_DOCKER" -s 172.16.0.0/12 -j RETURN
    iptables -A "$CHAIN_DOCKER" -m conntrack --ctstate INVALID -j DROP

    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -A "$CHAIN_DOCKER" -p udp --dport "$port" \
            -m conntrack --ctstate UNTRACKED -m set --match-set "$IPSET_COUNTRY" src -j RETURN
    done

    if [[ "$allowlist_count" -gt 0 ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            iptables -A "$CHAIN_DOCKER" -p tcp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        done
        for port in "${ALLOW_UDP_PORTS[@]}"; do
            iptables -A "$CHAIN_DOCKER" -p udp --dport "$port" \
                -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        done
    fi

    if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
        for port in "${ALLOW_TCP_PORTS[@]}"; do
            add_rate_limit filter "$CHAIN_DOCKER" "-p tcp" "$port" "docker_tcp_${port}" "$RATE_LIMIT_TCP"
        done
    fi

    iptables -A "$CHAIN_DOCKER" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_DOCKER" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j RETURN
    done

    iptables -A "$CHAIN_DOCKER" -j DROP
    log "Docker chain built"
}

save_rules() {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    command -v netfilter-persistent >/dev/null && netfilter-persistent save 2>/dev/null || true
    log "Rules saved"
}

# ==============================
# WRITE GEO-FIREWALL.SH
# This script ONLY updates ipsets — no rule building
# Called by: cron (daily refresh) + systemd (load ipsets on boot)
# ==============================
write_firewall_script() {
    # Unquoted heredoc: setup variables expand into the script
    cat > "$FIREWALL_SCRIPT" << EOF
#!/bin/bash
# geo-firewall.sh — re-run setup-geo-firewall.sh to reconfigure.
# Only updates IP lists. Rules are built by setup and restored on boot by netfilter-persistent.
set -euo pipefail

# --- CONFIG (baked in by setup-geo-firewall.sh) ---
ALLOW_COUNTRIES=($(printf '"%s" ' "${ALLOW_COUNTRIES[@]}"))
ALLOW_TCP_PORTS=($(printf '"%s" ' "${ALLOW_TCP_PORTS[@]}"))
ALLOW_UDP_PORTS=($(printf '"%s" ' "${ALLOW_UDP_PORTS[@]}"))
ALLOWLIST_URLS=($(printf '"%s" ' "${ALLOWLIST_URLS[@]}"))
ALLOWLIST_IPS=($(printf '"%s" ' "${ALLOWLIST_IPS[@]}"))

# --- PATHS ---
INSTALL_DIR="/home/geo-firewall"
DATA_DIR="\$INSTALL_DIR/data"
HASH_DIR="\$INSTALL_DIR/hash"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"
CIDR_REGEX='$CIDR_REGEX'

log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
trap 'log "ERROR at line \$LINENO: \$BASH_COMMAND (exit \$?)"' ERR
EOF

    # Quoted heredoc: functions, no expansion needed
    cat >> "$FIREWALL_SCRIPT" << 'SCRIPT_EOF'

download_allowlist() {
    local tmp; tmp=$(mktemp -d)
    local i=0
    for ip in "${ALLOWLIST_IPS[@]}"; do
        if [[ -n "$ip" ]]; then
            echo "$ip" > "$tmp/$(printf '%04d' $i)_local.txt"
            i=$(( i + 1 ))
        fi
    done
    for url in "${ALLOWLIST_URLS[@]}"; do
        if [[ -n "$url" ]]; then
            curl -sf --connect-timeout 10 --max-time 30 "$url" \
                > "$tmp/$(printf '%04d' $i)_url.txt" 2>/dev/null &
            i=$(( i + 1 ))
        fi
    done
    wait
    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" | sort -u > "$DATA_DIR/allowlist.raw" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/allowlist.raw" ]]; then
        log "ERROR: allowlist download failed"; return 1
    fi
}

download_country() {
    local tmp; tmp=$(mktemp -d)
    local i=0
    local sources=(
        "https://raw.githubusercontent.com/ipverse/rir-ip/refs/heads/master/country/__CC__/ipv4-aggregated.txt"
        "https://www.ipdeny.com/ipblocks/data/countries/__CC__.zone"
        "https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/__CC__-ipv4-Hackers.Zone.txt"
    )
    for cc in "${ALLOW_COUNTRIES[@]}"; do
        local cc_lower="${cc,,}"
        local cc_upper="${cc^^}"
        for src in "${sources[@]}"; do
            local url="${src//__CC__/$cc_lower}"
            if [[ "$src" == *"ebrasha"* ]]; then url="${src//__CC__/$cc_upper}"; fi
            curl -sf --connect-timeout 10 --max-time 30 "$url" \
                > "$tmp/$(printf '%04d' $i)_${cc}.txt" 2>/dev/null &
            i=$(( i + 1 ))
        done
        if [[ "$cc_upper" == "VN" ]]; then
            curl -sf --connect-timeout 10 --max-time 30 \
                "https://raw.githubusercontent.com/bibicadotnet/IPinfo-VietNam/main/vietnam.txt" \
                > "$tmp/$(printf '%04d' $i)_VN_extra.txt" 2>/dev/null &
            i=$(( i + 1 ))
        fi
    done
    wait
    cat "$tmp"/*.txt 2>/dev/null | grep -Eo "$CIDR_REGEX" | sort -u > "$DATA_DIR/country.raw" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/country.raw" ]]; then
        log "ERROR: country download failed"; return 1
    fi
}

update_ipset() {
    local name="$1" ipset_name="$2" ipset_type="$3" maxelem="$4"
    local raw="$DATA_DIR/${name}.raw"
    local hash_file="$HASH_DIR/${name}.sha256"
    local tmp_name="${ipset_name}_tmp"

    log "Downloading $name..."
    if [[ "$name" == "allowlist" ]]; then
        download_allowlist || return 1
    else
        download_country || return 1
    fi

    local new_hash old_hash current_count
    new_hash=$(sha256sum "$raw" | cut -d' ' -f1)
    old_hash=$(cat "$hash_file" 2>/dev/null || echo "")

    current_count=0
    if ipset list "$ipset_name" >/dev/null 2>&1; then
        current_count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    fi

    if [[ "$new_hash" == "$old_hash" && "$current_count" -gt 0 ]]; then
        log "$name: unchanged ($current_count entries), skipping"
        return 0
    fi

    log "$name: rebuilding ipset..."
    ipset create "$ipset_name" "$ipset_type" maxelem "$maxelem" 2>/dev/null || true
    ipset destroy "$tmp_name" 2>/dev/null || true
    ipset create  "$tmp_name" "$ipset_type" maxelem "$maxelem"
    awk -v s="$tmp_name" '{print "add " s " " $0}' "$raw" | ipset restore -!
    ipset swap "$ipset_name" "$tmp_name"
    ipset destroy "$tmp_name"
    echo "$new_hash" > "$hash_file"

    local count; count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    log "$name: $count entries loaded"
}

update_ipsets() {
    mkdir -p "$DATA_DIR" "$HASH_DIR"
    update_ipset "allowlist" "$IPSET_ALLOWLIST" "hash:net" "65536"  || true
    update_ipset "country"   "$IPSET_COUNTRY"   "hash:net" "131072" || true

    local count; count=$(ipset list -t "$IPSET_COUNTRY" | awk '/Number of entries:/{print $NF}')
    if [[ "$count" -eq 0 && "${#ALLOW_COUNTRIES[@]}" -gt 0 ]]; then
        log "ERROR: country ipset empty — check connectivity"; exit 1
    fi
}

log "=== GeoIP Firewall: Updating IPs ==="
update_ipsets
log "=== Done ==="
SCRIPT_EOF

    chmod +x "$FIREWALL_SCRIPT"
    log "Firewall script written → $FIREWALL_SCRIPT"
}

# ==============================
# WRITE EMERGENCY RESET SCRIPT
# ==============================
write_reset_script() {
    cat > "$RESET_SCRIPT" << 'RESET_EOF'
#!/bin/bash
# emergency-reset.sh — wipes all iptables rules and ipsets created by this firewall
set -euo pipefail
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log "=== Emergency Reset ==="

iptables    -D INPUT       -j GEO_INPUT   2>/dev/null || true
iptables    -D DOCKER-USER -j GEO_DOCKER  2>/dev/null || true
iptables -t raw -D PREROUTING -j GEO_RAW_IN  2>/dev/null || true
iptables -t raw -D OUTPUT     -j GEO_RAW_OUT 2>/dev/null || true

while IFS= read -r chain; do
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
done < <(iptables-save 2>/dev/null | awk -F'[ :]' '/^:(GEO_|RL_)/{print $2}')

while IFS= read -r chain; do
    iptables -t raw -F "$chain" 2>/dev/null || true
    iptables -t raw -X "$chain" 2>/dev/null || true
done < <(iptables -t raw -S 2>/dev/null | awk '/^-N (GEO_|RL_)/{print $2}')

if [[ -d /proc/net/xt_recent ]]; then
    for f in /proc/net/xt_recent/FLOOD_*; do
        [[ -f "$f" ]] && echo "/" > "$f" 2>/dev/null || true
    done
fi

for s in geo_country geo_allowlist geo_country_tmp geo_allowlist_tmp; do
    ipset destroy "$s" 2>/dev/null || true
done

rm -f /etc/sysctl.d/99-geo-firewall.conf
rm -f /etc/modprobe.d/xt_recent.conf
rm -rf /home/geo-firewall

log "=== Reset complete — everything cleared ==="
RESET_EOF
    chmod +x "$RESET_SCRIPT"
    log "Reset script written → $RESET_SCRIPT"
}

# ==============================
# SYSTEMD + CRON
# ==============================
setup_service() {
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=GeoIP Firewall — update IP lists after boot
After=network-online.target netfilter-persistent.service docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$FIREWALL_SCRIPT
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable geo-firewall.service
    log "Systemd service installed (enabled on boot)"

    (crontab -l 2>/dev/null | grep -v "$FIREWALL_SCRIPT" || true
     echo "30 2 * * * /bin/bash $FIREWALL_SCRIPT >/dev/null 2>&1") | crontab -
    log "Cron job installed (daily 02:30)"
}

# ==============================
# MAIN
# ==============================
install_deps
cleanup_all
apply_kernel_tuning
mkdir -p "$INSTALL_DIR"

write_firewall_script
write_reset_script

log "Loading IP lists..."
update_ipsets

log "Building firewall rules..."
allowlist_count=$(ipset list -t "$IPSET_ALLOWLIST" | awk '/Number of entries:/{print $NF}')
build_raw_table
build_input_chain "$allowlist_count"
if command -v docker >/dev/null 2>&1; then
    build_docker_chain "$allowlist_count"
fi
save_rules

setup_service

echo ""
echo "================================================"
echo "  GEO FIREWALL INSTALLED"
echo "================================================"
echo "  Countries  : ${ALLOW_COUNTRIES[*]}"
echo "  TCP ports  : ${ALLOW_TCP_PORTS[*]}"
echo "  UDP ports  : ${ALLOW_UDP_PORTS[*]}"
echo "  Rate limit : UDP=${RATE_LIMIT_UDP}/s  TCP=${RATE_LIMIT_TCP}/s"
echo "               throttle=${THROTTLE_RATE}/s for ${PENALTY_TIME}s"
echo ""
echo "  Status : systemctl status geo-firewall"
echo "  Update : $FIREWALL_SCRIPT"
echo "  Reset  : $RESET_SCRIPT"
echo ""
if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
    echo "  Rate limit stats:"
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        echo "    UDP $port : cat /proc/net/ipt_hashlimit/udp_${port}_det"
    done
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        echo "    TCP $port : cat /proc/net/ipt_hashlimit/tcp_${port}_det"
    done
    echo ""
fi
echo "================================================"

#!/bin/bash
# setup-geo-firewall.sh — V3 Optimized
# GeoIP and Rate Limit protection with Docker support
#
# Optimizations vs V2:
#   1. xt_recent replaced by ipset SET target (O(1) hash vs O(n) linked list)
#   2. TCP rate-limiting moved to raw table (flood dropped BEFORE conntrack)
#   3. INPUT chain simplified (no rate-limit logic, just GeoIP + ESTABLISHED)
#   4. Docker chain simplified (rate-limiting handled globally in raw table)

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
# Per-IP token bucket: allows sustained traffic up to RATE, with BURST headroom
# for short spikes (e.g. power restore, browser restart with 100 tabs).
# If sustained traffic > RATE drains all BURST tokens → IP penalized (THROTTLE_RATE PPS).
# Formula: time_to_penalty = BURST / (actual_PPS - RATE)
ENABLE_RATE_LIMIT=true
RATE_LIMIT_UDP=250          # Sustained PPS limit per IP (single device peak ~150)
RATE_LIMIT_TCP=500          # Sustained PPS limit per IP (single device peak ~150)
BURST_UDP=5000              # Token bucket size — absorbs multi-device NAT spikes without penalty
BURST_TCP=5000              # Token bucket size — absorbs multi-device NAT spikes without penalty
THROTTLE_RATE=5             # PPS allowed during penalty (just enough for basic DNS resolution)
PENALTY_TIME=5              # Penalty duration in seconds (auto-refreshed while flood continues)

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
CIDR_REGEX='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[12][0-9]|3[0-2]))?$'

# ==============================
# BOOTSTRAP
# ==============================
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "ERROR: Run as root"; exit 1; }
renice -n 19 $$ >/dev/null 2>&1 || true
ionice -c 3 -p $$ 2>/dev/null || true
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
# (xt_recent removed — no longer used)
# ==============================
apply_kernel_tuning() {
    log "Applying kernel hardening..."
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

    # Clean up penalty ipsets (v3) + xt_recent leftovers (v2)
    while IFS= read -r s; do
        ipset destroy "$s" 2>/dev/null || true
    done < <(ipset list -n 2>/dev/null | grep -E '^(geo_|rl_pen_)')
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
# Downloads save raw concatenated data (no grep/sort)
# Expensive regex parsing only runs when data changes
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
    cat "$tmp"/*.txt 2>/dev/null > "$DATA_DIR/allowlist.concat" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/allowlist.concat" ]]; then
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
    cat "$tmp"/*.txt 2>/dev/null > "$DATA_DIR/country.concat" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/country.concat" ]]; then
        log "ERROR: country download failed"; return 1
    fi
}

# ==============================
# IPSET UPDATE
# Hash raw download BEFORE expensive grep → zero CPU when unchanged
# ==============================
update_ipset() {
    local name="$1" ipset_name="$2" ipset_type="$3" maxelem="$4"
    local raw="$DATA_DIR/${name}.raw"
    local concat="$DATA_DIR/${name}.concat"
    local hash_file="$HASH_DIR/${name}.sha256"
    local tmp_name="${ipset_name}_tmp"

    log "Downloading $name..."
    if [[ "$name" == "allowlist" ]]; then
        download_allowlist || return 1
    else
        download_country || return 1
    fi

    # Hash raw downloaded data (fast — no regex)
    local new_hash old_hash current_count
    new_hash=$(sha256sum "$concat" | cut -d' ' -f1)
    old_hash=$(cat "$hash_file" 2>/dev/null || echo "")

    current_count=0
    if ipset list "$ipset_name" >/dev/null 2>&1; then
        current_count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    fi

    if [[ "$new_hash" == "$old_hash" && "$current_count" -gt 0 ]]; then
        log "$name: unchanged ($current_count entries), skipping"
        rm -f "$concat"
        return 0
    fi

    # Data changed or ipset empty → run expensive grep + sort
    log "$name: processing new data..."
    grep -Eo "$CIDR_REGEX" "$concat" | sort -u > "$raw" || true
    rm -f "$concat"

    if [[ ! -s "$raw" ]]; then
        log "ERROR: $name processing failed"; return 1
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
# PENALTY IPSETS (replaces xt_recent)
#
# One ipset per port per protocol with auto-expiring timeout.
# ipset hash:ip lookup is O(1) vs xt_recent O(n) linked list.
# ==============================
create_penalty_ipsets() {
    log "Creating penalty ipsets..."
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        ipset create "rl_pen_udp_${port}" hash:ip timeout "$PENALTY_TIME" maxelem 65536 2>/dev/null || \
            ipset flush "rl_pen_udp_${port}"
    done
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        ipset create "rl_pen_tcp_${port}" hash:ip timeout "$PENALTY_TIME" maxelem 65536 2>/dev/null || \
            ipset flush "rl_pen_tcp_${port}"
    done
}

# ==============================
# RATE LIMIT SUB-CHAIN (V3 — ipset penalty)
#
# Same two-phase logic as V2:
#   Phase 1 — PENALTY:  if flagged in ipset, throttle to THROTTLE_RATE PPS
#   Phase 2 — DETECT:   if traffic > rate PPS, flag IP via SET target, DROP
#
# Differences from V2:
#   - ipset SET target replaces xt_recent (O(1) hash vs O(n) list)
#   - All rate limiting in raw table (TCP flood dropped before conntrack)
# ==============================
add_rate_limit() {
    local chain="$1" proto="$2" port="$3" rate="$4" burst="$5"
    local prefix="${proto}_${port}"
    local pen_set="rl_pen_${prefix}"
    local sub="RL_${prefix}"

    iptables -t raw -N "$sub" 2>/dev/null || iptables -t raw -F "$sub"

    # Phase 1 — PENALTY: penalized IP, allow up to THROTTLE_RATE PPS
    iptables -t raw -A "$sub" -m set --match-set "$pen_set" src \
        -m hashlimit --hashlimit-upto "${THROTTLE_RATE}/sec" --hashlimit-burst "$THROTTLE_RATE" \
        --hashlimit-name "${prefix}_pen" --hashlimit-mode srcip -j RETURN
    # Over throttle → refresh penalty if traffic still significant
    # THROTTLE_RATE*2 (=10): low enough to catch QUIC/TCP congestion backoff (~30 PPS),
    # high enough that normal post-flood traffic (~5 PPS) won't keep penalty alive.
    # Scaled down from *10 because BURST is 5-10x larger than original (burst=rate).
    local refresh_threshold=$(( THROTTLE_RATE * 10 ))
    iptables -t raw -A "$sub" -m set --match-set "$pen_set" src \
        -m hashlimit --hashlimit-above "${refresh_threshold}/sec" --hashlimit-burst "$refresh_threshold" \
        --hashlimit-name "${prefix}_ref" --hashlimit-mode srcip \
        -j SET --add-set "$pen_set" src --exist
    iptables -t raw -A "$sub" -m set --match-set "$pen_set" src -j DROP

    # Phase 2 — DETECT: over rate limit → add to penalty ipset, then DROP
    # burst = token bucket size: allows short-term spikes (power restore)
    # while catching sustained overload (benchmark/DDoS)
    iptables -t raw -A "$sub" \
        -m hashlimit --hashlimit-above "${rate}/sec" --hashlimit-burst "$burst" \
        --hashlimit-name "${prefix}_det" --hashlimit-mode srcip \
        -j SET --add-set "$pen_set" src --exist
    iptables -t raw -A "$sub" -m set --match-set "$pen_set" src -j DROP

    # Under limit → RETURN (continue processing)
    iptables -t raw -A "$sub" -j RETURN

    # Hook sub-chain into parent
    iptables -t raw -A "$chain" -p "$proto" --dport "$port" -j "$sub"
}

# ==============================
# RAW TABLE (UDP + TCP)
#
# V3: Both UDP and TCP rate-limited here.
# TCP flood dropped BEFORE conntrack allocation → major CPU savings.
# UDP: NOTRACK as before.
# TCP: kept tracked (conntrack) for Docker DNAT compatibility.
#
# Flow per protocol:
#   Allowlist → RETURN/NOTRACK (bypass rate limit)
#   Rate limit sub-chain → DROP floods
#   UDP only: CT --notrack
# ==============================
build_raw_table() {
    iptables -t raw -N "$CHAIN_RAW_IN"  2>/dev/null || iptables -t raw -F "$CHAIN_RAW_IN"
    iptables -t raw -N "$CHAIN_RAW_OUT" 2>/dev/null || iptables -t raw -F "$CHAIN_RAW_OUT"
    iptables -t raw -C PREROUTING -j "$CHAIN_RAW_IN"  2>/dev/null \
        || iptables -t raw -I PREROUTING 1 -j "$CHAIN_RAW_IN"
    iptables -t raw -C OUTPUT     -j "$CHAIN_RAW_OUT" 2>/dev/null \
        || iptables -t raw -I OUTPUT     1 -j "$CHAIN_RAW_OUT"

    # --- UDP ---
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        iptables -t raw -A "$CHAIN_RAW_IN" -p udp --dport "$port" \
            -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
            add_rate_limit "$CHAIN_RAW_IN" "udp" "$port" "$RATE_LIMIT_UDP" "$BURST_UDP"
        fi
        iptables -t raw -A "$CHAIN_RAW_IN"  -p udp --dport "$port" -j CT --notrack
        iptables -t raw -A "$CHAIN_RAW_OUT" -p udp --sport "$port" -j CT --notrack
    done

    # --- TCP (NEW in V3) ---
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -t raw -A "$CHAIN_RAW_IN" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_ALLOWLIST" src -j RETURN
        if [[ "$ENABLE_RATE_LIMIT" == "true" ]]; then
            add_rate_limit "$CHAIN_RAW_IN" "tcp" "$port" "$RATE_LIMIT_TCP" "$BURST_TCP"
        fi
        # TCP: NO notrack — keep conntrack for Docker DNAT + ESTABLISHED fast-path
    done

    log "RAW table built (UDP NOTRACK + TCP rate-limit in raw)"
}

# ==============================
# INPUT CHAIN (V3 — simplified)
#
# Rate limiting is now in raw table, so INPUT is clean:
#   1. lo               → ACCEPT
#   2. INVALID          → DROP
#   3. Docker 172/12    → ACCEPT
#   4. UNTRACKED + GeoIP→ ACCEPT  (UDP NOTRACKed in raw)
#   5. Allowlist        → ACCEPT
#   6. ESTABLISHED      → ACCEPT  (TCP, already rate-limited in raw)
#   7. GeoIP TCP NEW    → ACCEPT
#   8. Default          → DROP
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

    # ESTABLISHED moved up — no rate-limit needed here (already done in raw table)
    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    for port in "${ALLOW_TCP_PORTS[@]}"; do
        iptables -A "$CHAIN_INPUT" -p tcp --dport "$port" \
            -m set --match-set "$IPSET_COUNTRY" src -j ACCEPT
    done

    iptables -A "$CHAIN_INPUT" -j DROP
    log "INPUT chain built"
}

# ==============================
# DOCKER CHAIN (V3 — simplified, no rate limiting)
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

    # No rate-limit here — handled in raw table for all traffic
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
# Updates ipsets + ensures penalty ipsets exist
# Called by: cron (daily refresh) + systemd (boot)
# ==============================
write_firewall_script() {
    cat > "$FIREWALL_SCRIPT" << EOF
#!/bin/bash
# geo-firewall.sh — V3. Re-run setup script to reconfigure.
# Updates IP lists + ensures penalty ipsets exist.
set -euo pipefail

# --- CONFIG (baked in by setup) ---
ALLOW_COUNTRIES=($(printf '"%s" ' "${ALLOW_COUNTRIES[@]}"))
ALLOW_TCP_PORTS=($(printf '"%s" ' "${ALLOW_TCP_PORTS[@]}"))
ALLOW_UDP_PORTS=($(printf '"%s" ' "${ALLOW_UDP_PORTS[@]}"))
ALLOWLIST_URLS=($(printf '"%s" ' "${ALLOWLIST_URLS[@]}"))
ALLOWLIST_IPS=($(printf '"%s" ' "${ALLOWLIST_IPS[@]}"))
BURST_UDP=$BURST_UDP
BURST_TCP=$BURST_TCP
PENALTY_TIME=$PENALTY_TIME

# --- PATHS ---
INSTALL_DIR="/home/geo-firewall"
DATA_DIR="\$INSTALL_DIR/data"
HASH_DIR="\$INSTALL_DIR/hash"
IPSET_COUNTRY="geo_country"
IPSET_ALLOWLIST="geo_allowlist"
CIDR_REGEX='$CIDR_REGEX'

log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
trap 'log "ERROR at line \$LINENO: \$BASH_COMMAND (exit \$?)"' ERR
renice -n 19 \$\$ >/dev/null 2>&1 || true
ionice -c 3 -p \$\$ 2>/dev/null || true
EOF

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
    cat "$tmp"/*.txt 2>/dev/null > "$DATA_DIR/allowlist.concat" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/allowlist.concat" ]]; then
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
    cat "$tmp"/*.txt 2>/dev/null > "$DATA_DIR/country.concat" || true
    rm -rf "$tmp"
    if [[ ! -s "$DATA_DIR/country.concat" ]]; then
        log "ERROR: country download failed"; return 1
    fi
}

update_ipset() {
    local name="$1" ipset_name="$2" ipset_type="$3" maxelem="$4"
    local raw="$DATA_DIR/${name}.raw"
    local concat="$DATA_DIR/${name}.concat"
    local hash_file="$HASH_DIR/${name}.sha256"
    local tmp_name="${ipset_name}_tmp"

    log "Downloading $name..."
    if [[ "$name" == "allowlist" ]]; then
        download_allowlist || return 1
    else
        download_country || return 1
    fi

    # Hash raw downloaded data (fast — no regex)
    local new_hash old_hash current_count
    new_hash=$(sha256sum "$concat" | cut -d' ' -f1)
    old_hash=$(cat "$hash_file" 2>/dev/null || echo "")

    current_count=0
    if ipset list "$ipset_name" >/dev/null 2>&1; then
        current_count=$(ipset list -t "$ipset_name" | awk '/Number of entries:/{print $NF}')
    fi

    if [[ "$new_hash" == "$old_hash" && "$current_count" -gt 0 ]]; then
        log "$name: unchanged ($current_count entries), skipping"
        rm -f "$concat"
        return 0
    fi

    # Data changed or ipset empty → run expensive grep + sort
    log "$name: processing new data..."
    grep -Eo "$CIDR_REGEX" "$concat" | sort -u > "$raw" || true
    rm -f "$concat"

    if [[ ! -s "$raw" ]]; then
        log "ERROR: $name processing failed"; return 1
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

# Ensure penalty ipsets exist (referenced by iptables rules)
ensure_penalty_ipsets() {
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        ipset create "rl_pen_udp_${port}" hash:ip timeout "$PENALTY_TIME" maxelem 65536 2>/dev/null || true
    done
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        ipset create "rl_pen_tcp_${port}" hash:ip timeout "$PENALTY_TIME" maxelem 65536 2>/dev/null || true
    done
}

log "=== GeoIP Firewall V3: Updating IPs ==="
ensure_penalty_ipsets
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
# emergency-reset.sh — wipes all iptables rules and ipsets
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

# Clean up all geo/rl ipsets (penalty + geo + tmp)
while IFS= read -r s; do
    ipset destroy "$s" 2>/dev/null || true
done < <(ipset list -n 2>/dev/null | grep -E '^(geo_|rl_pen_)')

# Legacy xt_recent cleanup
if [[ -d /proc/net/xt_recent ]]; then
    for f in /proc/net/xt_recent/FLOOD_*; do
        [[ -f "$f" ]] && echo "/" > "$f" 2>/dev/null || true
    done
fi

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
Description=GeoIP Firewall V3 — update IP lists after boot
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

log "Creating penalty ipsets..."
create_penalty_ipsets

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
echo "  GEO FIREWALL V3 INSTALLED"
echo "================================================"
echo "  Countries  : ${ALLOW_COUNTRIES[*]}"
echo "  TCP ports  : ${ALLOW_TCP_PORTS[*]}"
echo "  UDP ports  : ${ALLOW_UDP_PORTS[*]}"
echo "  Rate limit : UDP=${RATE_LIMIT_UDP}/s (burst ${BURST_UDP})  TCP=${RATE_LIMIT_TCP}/s (burst ${BURST_TCP})"
echo "               throttle=${THROTTLE_RATE}/s for ${PENALTY_TIME}s"
echo ""
echo "  Optimizations:"
echo "    - xt_recent → ipset SET (O(1) penalty lookup)"
echo "    - TCP rate-limit in raw table (flood dropped before conntrack)"
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
    echo "  Penalty sets:"
    for port in "${ALLOW_UDP_PORTS[@]}"; do
        echo "    UDP $port : ipset list rl_pen_udp_${port}"
    done
    for port in "${ALLOW_TCP_PORTS[@]}"; do
        echo "    TCP $port : ipset list rl_pen_tcp_${port}"
    done
    echo ""
fi
echo "================================================"

#!/bin/bash

clear

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

print_centered() {
    local text="$1"
    local width=$(tput cols)
    local padding=$(( (width - ${#text}) / 2 ))
    printf "%${padding}s%s\n" "" "$text"
}

print_separator() {
    local width=$(tput cols)
    printf '%*s\n' "$width" '' | tr ' ' '='
}

# Check root
[[ "$EUID" -ne 0 ]] && { print_error "Please run with sudo"; exit 1; }

# Config files
TOKEN_FILE="/home/lego/.cloudflare-token"
DOMAIN_FILE="/home/lego/.domain"

# Validate domain
validate_domain() {
    local domain=$1
    [[ ${#domain} -le 253 ]] && \
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] && \
    [[ ! "$domain" =~ \.\. ]]
}

# Validate API token
validate_api_token() {
    [[ ${#1} -ge 40 ]]
}

# Verify Cloudflare token
verify_cloudflare_token() {
    local token=$1
    print_info "Verifying Cloudflare API Token..."
    local response=$(curl -s --connect-timeout 10 -X GET \
        "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json")
    [[ "$response" == *'"success":true'* ]] && [[ "$response" == *"This API Token is valid and active"* ]]
}

# Load saved token
load_saved_token() {
    [[ -f "$TOKEN_FILE" ]] && cat "$TOKEN_FILE"
}

# Save token
save_token() {
    mkdir -p /home/lego
    echo "$1" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
}

# Load saved domain
load_saved_domain() {
    [[ -f "$DOMAIN_FILE" ]] && cat "$DOMAIN_FILE"
}

# Save domain
save_domain() {
    mkdir -p /home/lego
    echo "$1" > "$DOMAIN_FILE"
    chmod 600 "$DOMAIN_FILE"
}

# Check DCV CNAME
check_dcv_cname() {
    local domain=$1
    print_info "Checking for DCV CNAME conflicts..."
    if dig +short "_acme-challenge.${domain}" CNAME 2>/dev/null | grep -q "dcv.cloudflare.com"; then
        print_error "DCV CNAME conflict!"
        echo ""
        print_warning "Fix:"
        echo "  1. Go to Cloudflare DNS settings"
        echo "  2. DELETE: _acme-challenge.${domain}"
        echo "  3. Run script again"
        exit 1
    fi
}

# Check existing cert
check_existing_cert() {
    local domain=$1
    local cert_file="/home/lego/certificates/${domain}.crt"
    
    [[ ! -f "$cert_file" ]] && return 1
    
    print_info "Found existing certificate"
    
    if ! openssl x509 -in "$cert_file" -noout 2>/dev/null; then
        print_warning "Invalid certificate, will obtain new one"
        return 1
    fi
    
    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    print_info "Certificate expires in $days_left days"
    
    if [[ $days_left -lt 30 ]]; then
        print_warning "Certificate expires soon, will renew"
        return 1
    fi
    
    print_success "Certificate is valid"
    return 0
}

# Install Lego
install_lego() {
    print_info "Installing Lego..."
    
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
        *) print_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
    
    local release_url=$(curl -s https://api.github.com/repos/go-acme/lego/releases/latest \
        | grep browser_download_url | grep "_${os}_${arch}.tar.gz" | cut -d'"' -f4)
    
    [[ -z "$release_url" ]] && { print_error "Failed to get Lego URL"; exit 1; }
    
    mkdir -p /home/lego
    curl -sL "$release_url" -o /tmp/lego.tar.gz || { print_error "Download failed"; exit 1; }
    tar -xzf /tmp/lego.tar.gz -C /tmp
    mv /tmp/lego /home/lego/lego
    chmod +x /home/lego/lego
    rm -f /tmp/lego.tar.gz
    
    print_success "Lego installed"
}

# Install MosDNS-X
install_mosdns() {
    print_info "Installing MosDNS-X..."
    
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
        *) print_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
    
    local latest=$(curl -s https://api.github.com/repos/bibicadotnet/mosdns-x/releases/latest \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
    
    [[ -z "$latest" ]] && { print_error "Failed to get MosDNS-X version"; exit 1; }
    
    curl -sL "https://github.com/bibicadotnet/mosdns-x/releases/download/${latest}/mosdns-linux-${arch}.zip" \
        -o /tmp/mosdns.zip || { print_error "Download failed"; exit 1; }
    
    unzip -qo /tmp/mosdns.zip mosdns -d /tmp
    mkdir -p /home/mosdns-x
    mv /tmp/mosdns /home/mosdns-x/mosdns
    chmod +x /home/mosdns-x/mosdns
    rm -f /tmp/mosdns.zip
    
    print_success "MosDNS-X installed"
}

# Download config
download_mosdns_config() {
    print_info "Downloading MosDNS-X config..."
    
    cd /home || exit 1
    
    curl -sL https://github.com/bibicadotnet/mosdns-x-native/archive/HEAD.tar.gz \
        | tar xz --strip-components=1 || { print_error "Download failed"; exit 1; }
    
    rm -f LICENSE README.md
    chmod +x *.sh 2>/dev/null
    mkdir -p /home/mosdns-x/log
    
    print_success "Config downloaded"
}

# Obtain/renew certificate
obtain_or_renew_certificate() {
    local domain=$1
    local token=$2
    local email="admin@${domain}"
    local cert_file="/home/lego/certificates/${domain}.crt"
    local log_file="/tmp/lego-output.log"
    
    cd /home/lego
    > "$log_file"
    
    local cmd="run"
    [[ -f "$cert_file" ]] && cmd="renew"
    
    print_info "${cmd^}ing certificate..."
    
    CLOUDFLARE_DNS_API_TOKEN="$token" \
        /home/lego/lego --accept-tos \
        --dns cloudflare \
        --domains "$domain" \
        --domains "*.$domain" \
        --email "$email" \
        --path /home/lego \
        $cmd --preferred-chain="ISRG Root X1" > "$log_file" 2>&1 &
    
    local lego_pid=$!
    tail -f "$log_file" 2>/dev/null &
    local tail_pid=$!
    
    local timeout=300 elapsed=0
    while kill -0 $lego_pid 2>/dev/null; do
        sleep 2
        ((elapsed+=2))
        
        if grep -q "error: 429.*rateLimited" "$log_file" 2>/dev/null; then
            kill $lego_pid $tail_pid 2>/dev/null
            echo ""
            print_error "Rate limit exceeded!"
            print_warning "Wait 7 days or use different subdomain"
            rm -f "$log_file"
            exit 1
        fi
        
        if grep -q "dcv.cloudflare.com" "$log_file" 2>/dev/null; then
            kill $lego_pid $tail_pid 2>/dev/null
            echo ""
            print_error "DCV CNAME conflict!"
            rm -f "$log_file"
            exit 1
        fi
        
        if [[ $elapsed -ge $timeout ]]; then
            kill $lego_pid $tail_pid 2>/dev/null
            echo ""
            print_error "Timeout (5 minutes)"
            rm -f "$log_file"
            exit 1
        fi
    done
    
    wait $lego_pid
    local exit_code=$?
    kill $tail_pid 2>/dev/null
    wait $tail_pid 2>/dev/null
    
    echo ""
    
    if [[ $exit_code -ne 0 ]] || [[ ! -f "$cert_file" ]]; then
        print_error "Failed to obtain/renew certificate"
        [[ -f "$log_file" ]] && cat "$log_file"
        rm -f "$log_file"
        exit 1
    fi
    
    rm -f "$log_file"
    print_success "Certificate obtained/renewed"
}

# Update MosDNS config
update_mosdns_config() {
    local domain=$1
    
    print_info "Updating MosDNS-X config..."
    
    sed -i "s/dns\.bibica\.net/$domain/g" /home/mosdns-x/config/config.yaml
    
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    local cache_ram_mb=$(awk "BEGIN {printf \"%.0f\", $total_ram_mb * 0.7}")
    
    print_info "Total RAM: ${total_ram_mb} MB | Cache: ${cache_ram_mb} MB (70%)"
    
    local cdn_direct=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.2 * 1024}")
    local cdn_cname=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.2 * 1024}")
    local google=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.3 * 1024}")
    local cloudflare=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.3 * 1024 * 2}")
    
    sed -i "s/size: [0-9]* # google_cache/size: $google # google_cache/" /home/mosdns-x/config/config.yaml
    sed -i "s/size: [0-9]* # cdn_direct_cache/size: $cdn_direct # cdn_direct_cache/" /home/mosdns-x/config/config.yaml
    sed -i "s/size: [0-9]* # cdn_cname_cache/size: $cdn_cname # cdn_cname_cache/" /home/mosdns-x/config/config.yaml
    sed -i "s/size: [0-9]* # cloudflare_cache/size: $cloudflare # cloudflare_cache/" /home/mosdns-x/config/config.yaml
    
    print_success "Config updated"
}

# Create systemd service
create_systemd_service() {
    cat > /etc/systemd/system/mosdns.service <<'EOF'
[Unit]
Description=MosDNS-X DNS Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/mosdns-x
ExecStart=/home/mosdns-x/mosdns start -c /home/mosdns-x/config/config.yaml -d /home/mosdns-x
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable mosdns
    
    if systemctl is-active --quiet mosdns; then
        systemctl restart mosdns
    else
        systemctl start mosdns
    fi
    
    print_success "Systemd service created"
}

# Create renewal script
create_renewal_script() {
    local domain=$1
    
    cat > /home/lego/renew-cert.sh <<EOF
#!/bin/bash
set -euo pipefail

DOMAIN="$domain"
TOKEN_FILE="$TOKEN_FILE"
CERT_FILE="/home/lego/certificates/\${DOMAIN}.crt"
RENEW_DAYS=30

[[ ! -f "\$TOKEN_FILE" ]] && { echo "Token not found!"; exit 1; }
[[ ! -f "\$CERT_FILE" ]] && { echo "Certificate not found!"; exit 1; }

API_TOKEN=\$(cat "\$TOKEN_FILE")
EXPIRY_DATE=\$(openssl x509 -in "\$CERT_FILE" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=\$(date -d "\$EXPIRY_DATE" +%s)
CURRENT_EPOCH=\$(date +%s)
DAYS_LEFT=\$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))

echo "Certificate expires in \$DAYS_LEFT days"

if [[ \$DAYS_LEFT -lt \$RENEW_DAYS ]]; then
    echo "Renewing certificate..."
    cd /home/lego
    CLOUDFLARE_DNS_API_TOKEN="\$API_TOKEN" \\
        /home/lego/lego --accept-tos \\
        --dns cloudflare \\
        --domains "\$DOMAIN" \\
        --domains "*.\$DOMAIN" \\
        --email "admin@\${DOMAIN}" \\
        --path /home/lego \\
        renew --preferred-chain="ISRG Root X1"
    
    if [[ \$? -eq 0 ]]; then
        systemctl reload mosdns 2>/dev/null || systemctl restart mosdns
        echo "Certificate renewed!"
    else
        echo "Renewal failed!"
        exit 1
    fi
else
    echo "Certificate still valid"
fi
EOF
    
    chmod +x /home/lego/renew-cert.sh
    (crontab -l 2>/dev/null | grep -v "/home/lego/renew-cert.sh"; \
     echo "0 2 * * * /home/lego/renew-cert.sh >> /var/log/cert-renewal.log 2>&1") | crontab -
    
    print_success "Renewal script created"
}

# Create DNS command
create_dns_command() {
    cat > /usr/local/bin/dns <<'EOF'
#!/bin/bash
case "$1" in
  restart) exec systemctl restart mosdns ;;
  start) exec systemctl start mosdns ;;
  stop) exec systemctl stop mosdns ;;
  status) exec systemctl status mosdns ;;
  log) exec tail -f /home/mosdns-x/log/mosdns.log ;;
  update)
    echo "Updating MosDNS-X and Lego..."
    echo ""
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MOSDNS_ARCH="amd64" ;;
        aarch64|arm64) MOSDNS_ARCH="arm64" ;;
        armv7l) MOSDNS_ARCH="armv7" ;;
    esac
    
    LATEST=$(curl -s https://api.github.com/repos/bibicadotnet/mosdns-x/releases/latest | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
    curl -sL "https://github.com/bibicadotnet/mosdns-x/releases/download/${LATEST}/mosdns-linux-${MOSDNS_ARCH}.zip" -o /tmp/mosdns.zip
    unzip -qo /tmp/mosdns.zip mosdns -d /tmp
    systemctl stop mosdns
    mv /tmp/mosdns /home/mosdns-x/mosdns
    chmod +x /home/mosdns-x/mosdns
    rm -f /tmp/mosdns.zip
    systemctl start mosdns
    
    echo "MosDNS-X: $(/home/mosdns-x/mosdns version | grep -oP 'version: \K.*')"
    echo ""
    
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    RELEASE_URL=$(curl -s https://api.github.com/repos/go-acme/lego/releases/latest | grep browser_download_url | grep "_${OS}_${MOSDNS_ARCH}.tar.gz" | cut -d'"' -f4)
    curl -sL "$RELEASE_URL" -o /tmp/lego.tar.gz
    tar -xzf /tmp/lego.tar.gz -C /tmp
    mv /tmp/lego /home/lego/lego
    chmod +x /home/lego/lego
    rm -f /tmp/lego.tar.gz
    
    echo "Lego: $(/home/lego/lego --version)"
    ;;
  -v|version)
    echo "MosDNS-X: $(/home/mosdns-x/mosdns version | grep -oP 'version: \K.*')"
    ;;
  -h|help|"")
    echo "MosDNS-X Commands:"
    echo "  dns start    - Start service"
    echo "  dns stop     - Stop service"
    echo "  dns restart  - Restart service"
    echo "  dns status   - Show status"
    echo "  dns log      - View logs"
    echo "  dns update   - Update to latest"
    echo "  dns -v       - Show version"
    ;;
  *)
    echo "Unknown: $1"
    echo "Use 'dns -h' for help"
    exit 1
    ;;
esac
EOF
    chmod +x /usr/local/bin/dns
    hash -r
    print_success "DNS command created"
}

# Fix permissions
fix_permissions() {
    print_info "Fixing permissions..."
    chmod +x /home/*.sh 2>/dev/null
    chmod 600 "$TOKEN_FILE" 2>/dev/null
    chmod 600 "$DOMAIN_FILE" 2>/dev/null
    print_success "Permissions fixed"
}

# Setup cron
setup_cron_jobs() {
    [[ -f /home/setup-cron-mosdns-block-allow.sh ]] && {
        print_info "Setting up ad-blocking cron..."
        /home/setup-cron-mosdns-block-allow.sh >/dev/null 2>&1
        print_success "Cron configured"
    }
}

# Restore from backup
restore_from_backup() {
    print_separator
    print_centered "Restore Mode"
    print_separator
    echo ""
    
    # Check required files
    if [[ ! -f "$TOKEN_FILE" ]] || [[ ! -f "$DOMAIN_FILE" ]]; then
        print_error "Configuration files not found!"
        echo ""
        echo "Required files:"
        echo "  - $TOKEN_FILE"
        echo "  - $DOMAIN_FILE"
        exit 1
    fi
    
    DOMAIN=$(cat "$DOMAIN_FILE")
    print_info "Domain: $DOMAIN"
    echo ""
    
    # Recreate services
    update_mosdns_config "$DOMAIN"
    create_systemd_service
    create_renewal_script "$DOMAIN"
    create_dns_command
    fix_permissions
    setup_cron_jobs
    
    echo ""
    print_separator
    print_centered "Restore Completed!"
    print_separator
    echo ""
    print_success "All services restored!"
}

# Fresh install
fresh_install() {
    print_separator
    print_centered "Public DNS Service Installation"
    print_centered "(MOSDNS-X NATIVE)"
    print_separator
    echo ""

    # Get domain
    SAVED_DOMAIN=$(load_saved_domain)
    DOMAIN=""

    if [[ -n "$SAVED_DOMAIN" ]]; then
        print_info "Found saved domain: $SAVED_DOMAIN"
        echo ""
        
        while true; do
            read -p "Use saved domain? (Y/n): " USE_SAVED_DOMAIN
            USE_SAVED_DOMAIN=${USE_SAVED_DOMAIN:-Y}
            
            if [[ "$USE_SAVED_DOMAIN" =~ ^[Yy]$ ]]; then
                DOMAIN="$SAVED_DOMAIN"
                print_success "Using: $DOMAIN"
                break
            elif [[ "$USE_SAVED_DOMAIN" =~ ^[Nn]$ ]]; then
                break
            else
                print_error "Please enter Y or N"
            fi
        done
    fi

    if [[ -z "$DOMAIN" ]]; then
        echo ""
        while true; do
            read -p "Enter domain (e.g., dns.bibica.net): " DOMAIN
            
            if validate_domain "$DOMAIN"; then
                print_success "Valid domain: $DOMAIN"
                break
            fi
            print_error "Invalid domain"
        done
    fi

    save_domain "$DOMAIN"

    # Get API token
    echo ""
    print_separator
    print_centered "Cloudflare API Token"
    print_separator
    echo ""

    SAVED_TOKEN=$(load_saved_token)
    API_TOKEN=""

    if [[ -n "$SAVED_TOKEN" ]]; then
        print_info "Found saved token"
        echo ""
        
        while true; do
            read -p "Use saved token? (Y/n): " USE_SAVED
            USE_SAVED=${USE_SAVED:-Y}
            
            if [[ "$USE_SAVED" =~ ^[Yy]$ ]]; then
                if verify_cloudflare_token "$SAVED_TOKEN"; then
                    API_TOKEN="$SAVED_TOKEN"
                    print_success "Using saved token"
                    break
                else
                    print_error "Saved token is invalid"
                    break
                fi
            elif [[ "$USE_SAVED" =~ ^[Nn]$ ]]; then
                break
            else
                print_error "Please enter Y or N"
            fi
        done
    fi

    if [[ -z "$API_TOKEN" ]]; then
        echo ""
		echo "  1. Access: https://dash.cloudflare.com/profile/api-tokens"
		echo "  2. Click 'Create Token'"
		echo "  3. Choose Template: 'Edit zone DNS'"
		echo "  4. Click 'Continue to summary' → 'Create Token'"
		echo "  5. Copy the token"
        echo ""
        
        while true; do
            read -p "Enter Cloudflare API Token: " API_TOKEN
            
            if ! validate_api_token "$API_TOKEN"; then
                print_error "Token must be 40+ characters"
                continue
            fi
            
            if verify_cloudflare_token "$API_TOKEN"; then
                print_success "Token is valid"
                save_token "$API_TOKEN"
                break
            fi
            print_error "Token is invalid"
        done
    fi

    echo ""
    print_info "Starting installation..."
    echo ""

    # Install packages
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq curl unzip openssl cron ca-certificates tzdata dnsutils
    elif command -v yum &>/dev/null; then
        yum install -y -q curl unzip openssl cronie ca-certificates bind-utils
        update-ca-trust
    fi

    command -v update-ca-certificates &>/dev/null && update-ca-certificates

    # Install components
    install_lego
    install_mosdns
    download_mosdns_config

    # Check and obtain cert
    check_dcv_cname "$DOMAIN"
    check_existing_cert "$DOMAIN" || obtain_or_renew_certificate "$DOMAIN" "$API_TOKEN"

    # Configure
    update_mosdns_config "$DOMAIN"
    create_systemd_service
    create_renewal_script "$DOMAIN"
    create_dns_command
    fix_permissions
    setup_cron_jobs

    SERVER_IP=$(curl -s https://api.ipify.org)

    echo ""
    print_separator
    print_centered "Installation Successful!"
    print_separator
    echo ""
    print_success "MosDNS-X installed!"
    echo ""
    print_separator
    print_centered "DNS Configuration"
    print_separator
    echo ""
    print_warning "Configure DNS record:"
    echo "  Name: $DOMAIN"
    echo "  Type: A"
    echo "  Value: $SERVER_IP"
    echo ""
    print_separator
    print_centered "Usage"
    print_separator
    echo ""
    echo "  DoH:  https://$DOMAIN/dns-query"
    echo "  DoT:  tls://$DOMAIN"
    echo "  DoH3: h3://$DOMAIN/dns-query"
    echo "  DoQ:  quic://$DOMAIN"
    echo ""
    print_separator
    print_centered "Management"
    print_separator
    echo ""
	echo "  - DNS commands: dns -h"
	echo "  - Certificate renewal: Auto-update daily at 2:00 AM"
	echo "  - Ad-blocking lists: Auto-update daily at 2:00 AM"
    echo ""
    print_success "Done!"
}

# Cleanup
cleanup() {
    rm -f /tmp/lego.tar.gz /tmp/mosdns.zip
}
trap cleanup EXIT

# Main menu
print_separator
print_centered "Installation Mode"
print_separator
echo ""
echo "  1. Fresh Install"
echo "  2. Restore"
echo ""

while true; do
    read -p "Choose (1/2): " MODE
    
    if [[ "$MODE" == "1" ]]; then
        fresh_install
        exit 0
    elif [[ "$MODE" == "2" ]]; then
        restore_from_backup
        exit 0
    else
        print_error "Enter 1 or 2"
    fi
done

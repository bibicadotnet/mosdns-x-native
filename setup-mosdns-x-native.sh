#!/bin/bash

clear

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then 
    print_error "Please run this script with root privileges (sudo)"
    exit 1
fi

validate_domain() {
    local domain=$1
    [[ ${#domain} -le 253 ]] && \
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] && \
    [[ ! "$domain" =~ \.\. ]]
}

validate_api_token() {
    [[ ${#1} -ge 40 ]]
}

verify_cloudflare_token() {
    local token=$1
    print_info "Verifying Cloudflare API Token..."
    
    local response=$(curl -s --connect-timeout 10 -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json")
    
    if [[ "$response" == *"\"success\":true"* ]] && [[ "$response" == *"This API Token is valid and active"* ]]; then
        return 0
    else
        return 1
    fi
}

check_dcv_cname() {
    local domain=$1
    print_info "Checking for DCV CNAME conflicts..."
    
    if dig +short "_acme-challenge.${domain}" CNAME 2>/dev/null | grep -q "dcv.cloudflare.com"; then
        print_error "Domain has DCV CNAME record that conflicts with ACME validation!"
        echo ""
        print_warning "To fix this issue:"
        echo "  1. Go to Cloudflare DNS settings for your domain"
        echo "  2. Find and DELETE the record: _acme-challenge.${domain}"
        echo "  3. Run this script again"
        echo ""
        print_info "After obtaining the certificate, you can recreate the DCV record if needed."
        exit 1
    fi
}

check_existing_cert() {
    local domain=$1
    local cert_file="/home/lego/certificates/${domain}.crt"
    
    if [ -f "$cert_file" ]; then
        print_info "Found existing certificate for $domain"
        
        if ! openssl x509 -in "$cert_file" -noout 2>/dev/null; then
            print_warning "Existing certificate is invalid, will obtain new one"
            return 1
        fi
        
        local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        print_info "Certificate expires in $days_left days"
        
        if [ $days_left -lt 30 ]; then
            print_warning "Certificate expires soon, will renew"
            return 1
        else
            print_success "Certificate is valid, skipping renewal"
            return 0
        fi
    fi
    
    return 1
}

load_saved_token() {
    local token_file="/home/lego/.cloudflare-token"
    if [ -f "$token_file" ]; then
        cat "$token_file"
    fi
}

save_token() {
    local token=$1
    local token_file="/home/lego/.cloudflare-token"
    mkdir -p /home/lego
    echo "$token" > "$token_file"
    chmod 600 "$token_file"
}

install_lego() {
    print_info "Installing lego..."
    
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    RELEASE_URL=$(curl -s https://api.github.com/repos/go-acme/lego/releases/latest \
        | grep browser_download_url \
        | grep "_${OS}_${ARCH}.tar.gz" \
        | cut -d'"' -f4)
    
    if [ -z "$RELEASE_URL" ]; then
        print_error "Failed to get lego download URL"
        exit 1
    fi
    
    mkdir -p /home/lego
    if ! curl -sL "$RELEASE_URL" -o /tmp/lego.tar.gz; then
        print_error "Failed to download lego"
        exit 1
    fi
    
    tar -xzf /tmp/lego.tar.gz -C /tmp
    mv /tmp/lego /home/lego/lego
    chmod +x /home/lego/lego
    rm /tmp/lego.tar.gz
    
    print_success "Lego installed to /home/lego/lego"
}

install_mosdns() {
    print_info "Installing MosDNS-X..."
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MOSDNS_ARCH="amd64" ;;
        aarch64|arm64) MOSDNS_ARCH="arm64" ;;
        armv7l) MOSDNS_ARCH="armv7" ;;
        *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    LATEST=$(curl -s https://api.github.com/repos/pmkol/mosdns-x/releases/latest \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
    
    if [ -z "$LATEST" ]; then
        print_error "Failed to get MosDNS-X version"
        exit 1
    fi
    
    if ! curl -sL "https://github.com/pmkol/mosdns-x/releases/download/${LATEST}/mosdns-linux-${MOSDNS_ARCH}.zip" \
        -o /tmp/mosdns.zip; then
        print_error "Failed to download MosDNS-X"
        exit 1
    fi
    
    unzip -qo /tmp/mosdns.zip mosdns -d /tmp
    mkdir -p /home/mosdns-x
    mv /tmp/mosdns /home/mosdns-x/mosdns
    chmod +x /home/mosdns-x/mosdns
    rm /tmp/mosdns.zip
    
    print_success "MosDNS-X installed to /home/mosdns-x/mosdns"
}

download_mosdns_config() {
    print_info "Downloading MosDNS-X configuration..."
    
    cd /home || exit 1
    
    if ! curl -L https://github.com/bibicadotnet/mosdns-x-native/archive/HEAD.tar.gz 2>/dev/null \
    | tar xz --strip-components=1; then
        print_error "Unable to download MosDNS-X config"
        exit 1
    fi
    
    rm -f LICENSE README.md
    chmod +x *.sh 2>/dev/null
    
    mkdir -p /home/mosdns-x/log
    
    print_success "MosDNS-X configuration downloaded"
}

obtain_or_renew_certificate() {
    local domain=$1
    local token=$2
    local email="admin@${domain}"
    local cert_file="/home/lego/certificates/${domain}.crt"
    local log_file="/tmp/lego-output.log"
    
    cd /home/lego
    
    > "$log_file"  # Clear log file
    
    local cmd
    if [ -f "$cert_file" ]; then
        print_info "Renewing certificate for $domain..."
        cmd="renew"
    else
        print_info "Obtaining new certificate for $domain..."
        cmd="run"
    fi
    
    # Run lego in background
    CLOUDFLARE_DNS_API_TOKEN="$token" \
        /home/lego/lego --accept-tos \
        --dns cloudflare \
        --domains "$domain" \
        --domains "*.$domain" \
        --email "$email" \
        --path /home/lego \
        $cmd --preferred-chain="ISRG Root X1" > "$log_file" 2>&1 &
    
    local lego_pid=$!
    
    # Monitor log in real-time
    tail -f "$log_file" 2>/dev/null &
    local tail_pid=$!
    
    # Check for errors while process runs
    local timeout=300
    local elapsed=0
    while kill -0 $lego_pid 2>/dev/null; do
        sleep 2
        elapsed=$((elapsed + 2))
        
        # Check for rate limit
        if grep -q "error: 429.*rateLimited" "$log_file" 2>/dev/null; then
            kill $lego_pid 2>/dev/null
            kill $tail_pid 2>/dev/null
            echo ""
            print_error "Let's Encrypt rate limit exceeded!"
            echo ""
            grep "too many certificates" "$log_file"
            echo ""
            print_warning "SOLUTIONS:"
            echo "  1. Wait 7 days before trying again"
            echo "  2. Use a different subdomain"
            echo "  3. Restore backup from /home/lego/certificates/"
            rm -f "$log_file"
            exit 1
        fi
        
        # Check for DCV CNAME
        if grep -q "dcv.cloudflare.com" "$log_file" 2>/dev/null; then
            kill $lego_pid 2>/dev/null
            kill $tail_pid 2>/dev/null
            echo ""
            print_error "DCV CNAME conflict!"
            echo ""
            print_warning "Fix: Delete _acme-challenge.${domain} in Cloudflare DNS"
            rm -f "$log_file"
            exit 1
        fi
        
        # Timeout
        if [ $elapsed -ge $timeout ]; then
            kill $lego_pid 2>/dev/null
            kill $tail_pid 2>/dev/null
            echo ""
            print_error "Certificate request timed out (5 minutes)"
            rm -f "$log_file"
            exit 1
        fi
    done
    
    # Wait for lego to finish
    wait $lego_pid
    local exit_code=$?
    kill $tail_pid 2>/dev/null
    wait $tail_pid 2>/dev/null
    
    echo ""
    
    # Check final result
    if [ $exit_code -ne 0 ] || [ ! -f "$cert_file" ]; then
        print_error "Failed to obtain/renew certificate"
        [ -f "$log_file" ] && cat "$log_file"
        rm -f "$log_file"
        exit 1
    fi
    
    rm -f "$log_file"
    print_success "Certificate obtained/renewed successfully"
}

update_mosdns_config() {
    local domain=$1
    
    print_info "Updating MosDNS-X configuration..."
    
    sed -i "s/dns\.bibica\.net/$domain/g" /home/mosdns-x/config/config.yaml
    
    # Calculate cache sizes based on RAM
    print_info "Calculating optimal cache sizes based on available RAM..."
    
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    
    print_info "Total RAM: ${total_ram_mb} MB"
    
    local cache_ram_mb=$(awk "BEGIN {printf \"%.0f\", $total_ram_mb * 0.7}")
    print_info "RAM allocated for cache (70%): ${cache_ram_mb} MB"
    
    local cdn_direct_size=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.2 * 1024}")
    local cdn_cname_size=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.2 * 1024}")
    local google_size=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.3 * 1024}")
    local cloudflare_size=$(awk "BEGIN {printf \"%.0f\", $cache_ram_mb * 0.3 * 1024 * 2}")
    
    print_info "Cache sizes: google=$google_size, cdn_direct=$cdn_direct_size, cdn_cname=$cdn_cname_size, cloudflare=$cloudflare_size"
    
    sed -i "s/size: [0-9]* # google_cache/size: $google_size # google_cache/" /home/mosdns-x/config/config.yaml
    sed -i "s/size: [0-9]* # cdn_direct_cache/size: $cdn_direct_size # cdn_direct_cache/" /home/mosdns-x/config/config.yaml
    sed -i "s/size: [0-9]* # cdn_cname_cache/size: $cdn_cname_size # cdn_cname_cache/" /home/mosdns-x/config/config.yaml
    sed -i "s/size: [0-9]* # cloudflare_cache/size: $cloudflare_size # cloudflare_cache/" /home/mosdns-x/config/config.yaml

    print_success "MosDNS-X configuration updated"
}

create_systemd_service() {
    cat > /etc/systemd/system/mosdns.service <<EOF
[Unit]
Description=Mosdns-x DNS Server
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
    
    print_success "MosDNS-X systemd service created and started"
}

create_renewal_script() {
    local domain=$1
    
    cat > /home/lego/renew-cert.sh <<EOF
#!/bin/bash
set -euo pipefail

DOMAIN="$domain"
TOKEN_FILE="/home/lego/.cloudflare-token"
CERT_FILE="/home/lego/certificates/\${DOMAIN}.crt"
RENEW_DAYS=30

if [ ! -f "\$TOKEN_FILE" ]; then
    echo "API Token file not found!"
    exit 1
fi

if [ ! -f "\$CERT_FILE" ]; then
    echo "Certificate not found!"
    exit 1
fi

API_TOKEN=\$(cat "\$TOKEN_FILE")

EXPIRY_DATE=\$(openssl x509 -in "\$CERT_FILE" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=\$(date -d "\$EXPIRY_DATE" +%s)
CURRENT_EPOCH=\$(date +%s)
DAYS_LEFT=\$(( (\$EXPIRY_EPOCH - \$CURRENT_EPOCH) / 86400 ))

echo "Certificate expires in \$DAYS_LEFT days"

if [ \$DAYS_LEFT -lt \$RENEW_DAYS ]; then
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
    
    if [ \$? -eq 0 ]; then
        systemctl reload mosdns 2>/dev/null || systemctl restart mosdns
        echo "Certificate renewed successfully!"
    else
        echo "Certificate renewal failed!"
        exit 1
    fi
else
    echo "Certificate still valid, no renewal needed"
fi
EOF
    
    chmod +x /home/lego/renew-cert.sh
    
    (crontab -l 2>/dev/null | grep -v "/home/lego/renew-cert.sh"; \
     echo "0 2 * * * /home/lego/renew-cert.sh >> /var/log/cert-renewal.log 2>&1") | \
     crontab - 2>/dev/null
    
    print_success "Certificate renewal script created with daily cron job"
}

# Cleanup function
cleanup() {
    rm -f /tmp/lego.tar.gz /tmp/mosdns.zip
}
trap cleanup EXIT

echo "=========================================="
echo "    PUBLIC DNS SERVICE INSTALLATION"
echo "         (MOSDNS-X NATIVE)"
echo "=========================================="
echo ""

while true; do
    read -p "Enter the domain you want to use (e.g., dns.bibica.net): " DOMAIN
    
    if validate_domain "$DOMAIN"; then
        print_success "Valid domain: $DOMAIN"
        break
    else
        print_error "Invalid domain. Please try again."
    fi
done

echo ""
echo "=========================================="
echo "        CLOUDFLARE API TOKEN"
echo "=========================================="
echo ""

SAVED_TOKEN=$(load_saved_token)

if [ -n "$SAVED_TOKEN" ]; then
    echo "Found saved Cloudflare API Token."
    read -p "Do you want to use the saved token? (Y/n): " USE_SAVED
    USE_SAVED=${USE_SAVED:-Y}
    
    if [[ "$USE_SAVED" =~ ^[Yy]$ ]]; then
        if verify_cloudflare_token "$SAVED_TOKEN"; then
            API_TOKEN="$SAVED_TOKEN"
            print_success "Using saved API Token."
        else
            print_error "Saved token is invalid or inactive. Please enter a new one."
            SAVED_TOKEN=""
        fi
    else
        SAVED_TOKEN=""
    fi
fi

if [ -z "$SAVED_TOKEN" ]; then
    echo "If you don't have an API Token yet, follow these steps:"
    echo ""
    echo "  1. Access: https://dash.cloudflare.com/profile/api-tokens"
    echo "  2. Click 'Create Token'"
    echo "  3. Choose Template: 'Edit zone DNS'"
    echo "  4. Click 'Continue to summary' → 'Create Token'"
    echo "  5. Copy the token"
    echo ""
    
    while true; do
        read -p "Enter Cloudflare API Token: " API_TOKEN
        
        if validate_api_token "$API_TOKEN"; then
            if verify_cloudflare_token "$API_TOKEN"; then
                print_success "API Token is valid and active."
                save_token "$API_TOKEN"
                break
            else
                print_error "API Token is incorrect or inactive."
            fi
        else
            print_error "Invalid API Token format (must be at least 40 characters)."
        fi
    done
fi

echo ""
print_info "Starting installation process..."
echo ""

# Install required packages
if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq curl unzip openssl cron ca-certificates tzdata dnsutils
elif command -v yum &> /dev/null; then
    yum install -y -q curl unzip openssl cronie ca-certificates bind-utils
    update-ca-trust
fi

if command -v update-ca-certificates &> /dev/null; then
    update-ca-certificates
fi

install_lego
install_mosdns
download_mosdns_config

# Check for DCV CNAME conflicts
check_dcv_cname "$DOMAIN"

# Check existing certificate and renew if needed
if ! check_existing_cert "$DOMAIN"; then
    obtain_or_renew_certificate "$DOMAIN" "$API_TOKEN"
fi

update_mosdns_config "$DOMAIN"
create_systemd_service
create_renewal_script "$DOMAIN" "$API_TOKEN"

if [ -f /home/setup-cron-mosdns-block-allow.sh ]; then
    /home/setup-cron-mosdns-block-allow.sh > /dev/null 2>&1
fi

# === DNS wrapper command ===
install -m 755 /dev/stdin /usr/local/bin/dns <<'EOF'
#!/bin/bash
case "$1" in
  restart) exec systemctl restart mosdns ;;
  start)   exec systemctl start mosdns ;;
  stop)    exec systemctl stop mosdns ;;
  status)  exec systemctl status mosdns ;;
  log)     exec tail -f /home/mosdns-x/log/mosdns.log ;;
  update)
    echo "Updating MosDNS-X and Lego..."
    echo ""
    
    # Update MosDNS-X
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MOSDNS_ARCH="amd64" ;;
        aarch64|arm64) MOSDNS_ARCH="arm64" ;;
        armv7l) MOSDNS_ARCH="armv7" ;;
    esac
    
    LATEST=$(curl -s https://api.github.com/repos/pmkol/mosdns-x/releases/latest | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
    curl -sL "https://github.com/pmkol/mosdns-x/releases/download/${LATEST}/mosdns-linux-${MOSDNS_ARCH}.zip" -o /tmp/mosdns.zip
    unzip -qo /tmp/mosdns.zip mosdns -d /tmp
    systemctl stop mosdns
    mv /tmp/mosdns /home/mosdns-x/mosdns
    chmod +x /home/mosdns-x/mosdns
    rm /tmp/mosdns.zip
    systemctl start mosdns
    
    mosdns_version=$(/home/mosdns-x/mosdns version | grep -oP 'version: \K.*')
    echo "MosDNS-X updated successfully"
    echo "mosdns version $mosdns_version"
    echo ""
    
    # Update Lego
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
    esac
    
    RELEASE_URL=$(curl -s https://api.github.com/repos/go-acme/lego/releases/latest | grep browser_download_url | grep "_${OS}_${ARCH}.tar.gz" | cut -d'"' -f4)
    curl -sL "$RELEASE_URL" -o /tmp/lego.tar.gz
    tar -xzf /tmp/lego.tar.gz -C /tmp
    mv /tmp/lego /home/lego/lego
    chmod +x /home/lego/lego
    rm /tmp/lego.tar.gz
    echo "Lego updated successfully"
    /home/lego/lego --version
    ;;
  no-ip-log)
    echo "Installing MosDNS-X (Disable IP logging version)..."
    echo ""
    
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MOSDNS_ARCH="amd64" ;;
        aarch64|arm64) MOSDNS_ARCH="arm64" ;;
        armv7l) MOSDNS_ARCH="armv7" ;;
    esac
    
    # Get latest release from bibicadotnet repo
    LATEST=$(curl -s https://api.github.com/repos/bibicadotnet/mosdns-x/releases/latest | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
    
    # Download and install
    curl -sL "https://github.com/bibicadotnet/mosdns-x/releases/download/${LATEST}/mosdns-linux-${MOSDNS_ARCH}.zip" -o /tmp/mosdns-noip.zip
    unzip -qo /tmp/mosdns-noip.zip mosdns -d /tmp
    systemctl stop mosdns
    mv /tmp/mosdns /home/mosdns-x/mosdns
    chmod +x /home/mosdns-x/mosdns
    rm /tmp/mosdns-noip.zip
    systemctl start mosdns
    
    mosdns_version=$(/home/mosdns-x/mosdns version | grep -oP 'version: \K.*')
    echo "MosDNS-X (Disable IP logging version) installed successfully"
    echo "mosdns version $mosdns_version"
    ;;
  -v|version)
    mosdns_version=$(/home/mosdns-x/mosdns version | grep -oP 'version: \K.*')
    echo "mosdns version $mosdns_version"
    ;;
  -h|help|"")
    echo "MosDNS-X Management Commands:"
    echo "  dns start         - Start MosDNS-X service"
    echo "  dns stop          - Stop MosDNS-X service"
    echo "  dns restart       - Restart MosDNS-X service"
    echo "  dns status        - Show MosDNS-X service status"
    echo "  dns log           - View MosDNS-X logs"
    echo "  dns update        - Update MosDNS-X and Lego to latest version"
    echo "  dns no-ip-log     - Switch to MosDNS-X (Disable IP logging version)"
    echo "  dns -v            - Show MosDNS-X version"
    ;;
  *)
    echo "Unknown command: $1"
    echo "Use 'dns -h' for help"
    exit 1
    ;;
esac
EOF
hash -r

print_success "DNS wrapper command created"

SERVER_IP=$(curl -s https://api.ipify.org)

echo ""
echo "=========================================="
echo "      INSTALLATION SUCCESSFUL!"
echo "=========================================="
echo ""
print_success "Public DNS service (Mosdns-x) has been installed successfully!"
echo ""
echo "=========================================="
echo "          DNS CONFIGURATION"
echo "=========================================="
echo ""
print_warning "Please point your DNS record:"
echo "  - Name: $DOMAIN"
echo "  - Type: A"
echo "  - Value: $SERVER_IP"
echo ""
echo "=========================================="
echo "           USAGE INFORMATION"
echo "=========================================="
echo ""
echo "  DNS-over-HTTPS (DoH): https://$DOMAIN/dns-query"
echo "  DNS-over-TLS (DoT): tls://$DOMAIN"
echo "  DNS-over-HTTP/3 (DoH3): h3://$DOMAIN/dns-query"
echo "  DNS-over-QUIC (DoQ): quic://$DOMAIN"
echo ""
print_warning "Recommended: Use DoH or DoT (safe and stable)"
echo ""
echo "=========================================="
echo "          MANAGEMENT COMMANDS"
echo "=========================================="
echo ""
echo "  - DNS commands: dns -h"
echo "  - Certificate renewal: Automated (daily at 2:00 AM)"
echo "    Manual check: /home/lego/renew-cert.sh"
echo "  - Ad-blocking lists: Auto-update daily at 2:00 AM"
echo ""
print_success "Installation complete!"

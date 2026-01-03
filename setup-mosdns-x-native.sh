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
    
    mkdir -p /home/lego
    curl -sL "$RELEASE_URL" -o /tmp/lego.tar.gz
    tar -xzf /tmp/lego.tar.gz -C /tmp
    mv /tmp/lego /home/lego/lego
    chmod +x /home/lego/lego
    rm /tmp/lego.tar.gz
    
    print_success "Lego installed to /home/lego/lego"
}

install_mosdns() {
    print_info "Installing mosdns-x..."
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MOSDNS_ARCH="amd64" ;;
        aarch64|arm64) MOSDNS_ARCH="arm64" ;;
        armv7l) MOSDNS_ARCH="armv7" ;;
        *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    LATEST=$(curl -s https://api.github.com/repos/pmkol/mosdns-x/releases/latest \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
    
    curl -sL "https://github.com/pmkol/mosdns-x/releases/download/${LATEST}/mosdns-linux-${MOSDNS_ARCH}.zip" \
        -o /tmp/mosdns.zip
    
	unzip -qo /tmp/mosdns.zip mosdns -d /tmp
	mkdir -p /home/mosdns-x
	mv /tmp/mosdns /home/mosdns-x/mosdns
	chmod +x /home/mosdns-x/mosdns
	rm /tmp/mosdns.zip
    
    print_success "Mosdns-x installed to /home/mosdns-x/mosdns"
}

download_mosdns_config() {
    print_info "Downloading mosdns configuration..."
    
    cd /home || exit 1
    
    curl -L https://github.com/bibicadotnet/mosdns-x-native/archive/HEAD.tar.gz 2>/dev/null \
    | tar xz --strip-components=1 \
    && rm -f LICENSE README.md \
    && chmod +x *.sh
    
    if [ $? -ne 0 ]; then
        print_error "Unable to download mosdns config. Please check your internet connection."
        exit 1
    fi
    
    # Create log directory
    mkdir -p /home/mosdns-x/log
    
    print_success "Mosdns configuration downloaded"
}

obtain_certificate() {
    local domain=$1
    local token=$2
    local email="admin@${domain}"
    
    print_info "Obtaining SSL certificate for $domain..."
    
    cd /home/lego
    
    CLOUDFLARE_DNS_API_TOKEN="$token" \
        /home/lego/lego --accept-tos \
        --dns cloudflare \
        --domains "$domain" \
        --domains "*.$domain" \
        --email "$email" \
        --path /home/lego \
        run --preferred-chain="ISRG Root X1"
    
    if [ -f "/home/lego/certificates/${domain}.crt" ]; then
        print_success "Certificate obtained successfully"
        return 0
    else
        print_error "Failed to obtain certificate"
        return 1
    fi
}

update_mosdns_config() {
    local domain=$1
    
    print_info "Updating mosdns configuration..."
    
    # Replace domain in config
    sed -i "s/dns\.bibica\.net/$domain/g" /home/mosdns-x/config/config.yaml

    print_success "Mosdns configuration updated"
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
    systemctl start mosdns
    systemctl restart mosdns
    print_success "Mosdns systemd service created and started"
}

create_renewal_script() {
    local domain=$1
    local token=$2
    
    cat > /home/lego/renew-cert.sh <<'EOF'
#!/bin/bash
set -euo pipefail

DOMAIN="DOMAIN_PLACEHOLDER"
API_TOKEN="TOKEN_PLACEHOLDER"
CERT_FILE="/home/lego/certificates/${DOMAIN}.crt"
RENEW_DAYS=30

if [ ! -f "$CERT_FILE" ]; then
    echo "Certificate not found!"
    exit 1
fi

EXPIRY_DATE=$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

echo "Certificate expires in $DAYS_LEFT days"

if [ $DAYS_LEFT -lt $RENEW_DAYS ]; then
    echo "Renewing certificate..."
    cd /home/lego
    CLOUDFLARE_DNS_API_TOKEN="$API_TOKEN" \
        /home/lego/lego --accept-tos \
        --dns cloudflare \
        --domains "$DOMAIN" \
        --domains "*.$DOMAIN" \
        --email "admin@${DOMAIN}" \
        --path /home/lego \
        renew --preferred-chain="ISRG Root X1"
    
  #  systemctl reload mosdns
    echo "Certificate renewed successfully!"
else
    echo "Certificate still valid, no renewal needed"
fi
EOF
    
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" /home/lego/renew-cert.sh
    sed -i "s/TOKEN_PLACEHOLDER/$token/g" /home/lego/renew-cert.sh
    chmod +x /home/lego/renew-cert.sh
    
    # Add cron job for automatic renewal (runs daily at 2 AM)
	(crontab -l 2>/dev/null | grep -v "/home/lego/renew-cert.sh"; \
	 echo "0 2 * * * /home/lego/renew-cert.sh >> /var/log/cert-renewal.log 2>&1") | \
	 crontab - 2>/dev/null
    
    print_success "Certificate renewal script created with daily cron job"
}

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
            break
        else
            print_error "API Token is incorrect or inactive."
        fi
    else
        print_error "Invalid API Token format (must be at least 40 characters)."
    fi
done

echo ""
print_info "Starting installation process..."
echo ""

# Install required packages
if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq curl unzip openssl cron ca-certificates tzdata
elif command -v yum &> /dev/null; then
    yum install -y -q curl unzip openssl cronie ca-certificates
    # Update CA certificates
    update-ca-trust
fi

# Update CA certificates for Debian/Ubuntu
if command -v update-ca-certificates &> /dev/null; then
    update-ca-certificates
fi

install_lego
install_mosdns
download_mosdns_config
obtain_certificate "$DOMAIN" "$API_TOKEN"
update_mosdns_config "$DOMAIN"
create_systemd_service
create_renewal_script "$DOMAIN" "$API_TOKEN"

# Run the existing cron setup script if it exists
if [ -f /home/setup-cron-mosdns-block-allow.sh ]; then
    /home/setup-cron-mosdns-block-allow.sh > /dev/null 2>&1
fi

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
echo "=========================================="
echo "          MANAGEMENT COMMANDS"
echo "=========================================="
echo ""
echo "  - Check status: systemctl status mosdns"
echo "  - Restart: systemctl restart mosdns"
echo "  - View logs: journalctl -u mosdns -f"
echo "  - View mosdns log: tail -f /home/mosdns-x/log/mosdns.log"
echo "  - Renew cert: /home/lego/renew-cert.sh"
echo "  - Ad-blocking Cron: updates daily at 2:00 AM"
echo ""
print_success "Installation complete!"

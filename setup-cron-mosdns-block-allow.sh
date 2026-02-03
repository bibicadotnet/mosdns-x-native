#!/bin/bash

# Script to create a cron job for updating mosdns-x blocklists/allowlists

CRON_DIR="/home/mosdns-x/cron"
SCRIPT_FILE="$CRON_DIR/blocklists-allowlists.sh"
# Added /bin/bash before the script file so it runs even without chmod +x
CRON_JOB="0 2 * * * /bin/bash $SCRIPT_FILE > /dev/null 2>&1"

# Create directory
mkdir -p "$CRON_DIR"

# Create update-lists.sh script
cat > "$SCRIPT_FILE" << 'EOF'
#!/bin/bash
BLOCK_OUT="/home/mosdns-x/rules/blocklists.txt"
ALLOW_OUT="/home/mosdns-x/rules/allowlists.txt"
TLD_OUT="/home/mosdns-x/rules/valid_tlds.txt"
CLOUDFRONT_OUT="/home/mosdns-x/rules/cloudfront_ips.txt"
FASTLY_OUT="/home/mosdns-x/rules/fastly_ips.txt"
BUNNYCDN_OUT="/home/mosdns-x/rules/bunnycdn_ips.txt"
GCORE_OUT="/home/mosdns-x/rules/gcore_ips.txt"
BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"
TLD_TMP="/tmp/valid_tlds.tmp"
CLOUDFRONT_TMP="/tmp/cloudfront_ips.tmp"
FASTLY_TMP="/tmp/fastly_ips.tmp"
BUNNYCDN_TMP="/tmp/bunnycdn_ips.tmp"
GCORE_TMP="/tmp/gcore_ips.tmp"
mkdir -p /home/mosdns-x/rules

# Clean up temporary files on exit
trap "rm -f $BLOCK_TMP $ALLOW_TMP $TLD_TMP $CLOUDFRONT_TMP $FASTLY_TMP $BUNNYCDN_TMP $GCORE_TMP; exit" INT TERM EXIT

# Set low priority for CPU and I/O
renice -n 19 -p $$ 2>/dev/null
ionice -c3 -p $$ 2>/dev/null

# Function to extract and normalize domains from various list formats
extract_domains() {
  awk '{
    if (/^[[:space:]]*$/ || /^[!#]/) next
    line = tolower($0)
    sub(/^@@\|\|?/, "", line)
    sub(/^\|\|?/, "", line)
    sub(/\^.*/, "", line)
    sub(/[#!].*/, "", line)
    sub(/\/.*/, "", line)
    sub(/:.*/, "", line)
    sub(/^[0-9.]+[[:space:]]+/, "", line)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/ && !seen[line]++) print line
  }'
}

# Download blocklists in parallel
curl -fsSL --compressed --max-time 30 \
https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt \
https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt \
https://raw.githubusercontent.com/bibicadotnet/AdGuard-Home-blocklists/refs/heads/main/byme.txt \
https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts \
https://badmojr.github.io/1Hosts/Lite/adblock.txt \
| extract_domains > "$BLOCK_TMP" &

# Download allowlist in parallel
curl -fsSL --compressed --max-time 30 \
https://raw.githubusercontent.com/bibicadotnet/AdGuard-Home-blocklists/refs/heads/main/whitelist.txt \
| extract_domains > "$ALLOW_TMP" &

# Download IANA TLDs list
curl -fsSL --max-time 30 https://data.iana.org/TLD/tlds-alpha-by-domain.txt | grep -v '^#' | tr '[:upper:]' '[:lower:]' > "$TLD_TMP" &

# Download AWS CloudFront IP ranges
curl -fsSL --max-time 30 https://ip-ranges.amazonaws.com/ip-ranges.json | \
jq -r '.prefixes[] | select(.service == "CLOUDFRONT") | .ip_prefix' > "$CLOUDFRONT_TMP" &

# Download Fastly IP ranges
curl -fsSL --max-time 30 https://api.fastly.com/public-ip-list | \
jq -r '.addresses[]' > "$FASTLY_TMP" &

# Download BunnyCDN IP ranges
curl -fsSL --max-time 30 https://bunnycdn.com/api/system/edgeserverlist | \
jq -r '.[]' > "$BUNNYCDN_TMP" &

# Download Gcore IP ranges
curl -fsSL --max-time 30 https://api.gcore.com/cdn/public-ip-list | \
jq -r '.addresses[]' > "$GCORE_TMP" &

wait

# Replace existing files if download was successful (non-empty) and content changed or file doesn't exist
[ -s "$BLOCK_TMP" ] && { [ ! -f "$BLOCK_OUT" ] || ! cmp -s "$BLOCK_TMP" "$BLOCK_OUT"; } && mv -f "$BLOCK_TMP" "$BLOCK_OUT"
[ -s "$ALLOW_TMP" ] && { [ ! -f "$ALLOW_OUT" ] || ! cmp -s "$ALLOW_TMP" "$ALLOW_OUT"; } && mv -f "$ALLOW_TMP" "$ALLOW_OUT"
[ -s "$TLD_TMP" ] && { [ ! -f "$TLD_OUT" ] || ! cmp -s "$TLD_TMP" "$TLD_OUT"; } && mv -f "$TLD_TMP" "$TLD_OUT"
[ -s "$CLOUDFRONT_TMP" ] && { [ ! -f "$CLOUDFRONT_OUT" ] || ! cmp -s "$CLOUDFRONT_TMP" "$CLOUDFRONT_OUT"; } && mv -f "$CLOUDFRONT_TMP" "$CLOUDFRONT_OUT"
[ -s "$FASTLY_TMP" ] && { [ ! -f "$FASTLY_OUT" ] || ! cmp -s "$FASTLY_TMP" "$FASTLY_OUT"; } && mv -f "$FASTLY_TMP" "$FASTLY_OUT"
[ -s "$BUNNYCDN_TMP" ] && { [ ! -f "$BUNNYCDN_OUT" ] || ! cmp -s "$BUNNYCDN_TMP" "$BUNNYCDN_OUT"; } && mv -f "$BUNNYCDN_TMP" "$BUNNYCDN_OUT"
[ -s "$GCORE_TMP" ] && { [ ! -f "$GCORE_OUT" ] || ! cmp -s "$GCORE_TMP" "$GCORE_OUT"; } && mv -f "$GCORE_TMP" "$GCORE_OUT"
EOF

# Still keeping chmod for manual execution convenience
chmod +x "$SCRIPT_FILE"
echo "Script created: $SCRIPT_FILE"

# Initial run
echo "Running script for the first time..."
/bin/bash "$SCRIPT_FILE"

# Add/update crontab
crontab -l 2>/dev/null | grep -v "$SCRIPT_FILE" | crontab - 2>/dev/null || true
(crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab - 2>/dev/null

echo "Cron job installed: scheduled to run at 2:00 AM daily"

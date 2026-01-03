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
BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"

mkdir -p /home/mosdns-x/rules

# Clean up temporary files on exit
trap "rm -f $BLOCK_TMP $ALLOW_TMP; exit" INT TERM EXIT

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

wait

# Replace existing files if download was successful (non-empty)
[ -s "$BLOCK_TMP" ] && mv -f "$BLOCK_TMP" "$BLOCK_OUT"
[ -s "$ALLOW_TMP" ] && mv -f "$ALLOW_TMP" "$ALLOW_OUT"
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

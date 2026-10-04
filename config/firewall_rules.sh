#!/usr/bin/env bash
# =============================================================================
# config/firewall_rules.sh
#
# Baseline nftables ruleset for the IoT IDS/IPS system.
#
# Run this script ONCE before starting the IDS/IPS to create the table and
# chain structure that nftables_manager.py expects. The IDS/IPS inserts
# dynamic block/rate-limit rules into inet ids input at runtime.
#
# Usage:
#   sudo bash config/firewall_rules.sh          # apply rules
#   sudo bash config/firewall_rules.sh --flush  # flush all IDS rules and reset
#
# Requirements:
#   - nftables >= 0.9.3
#   - Run as root (or with CAP_NET_ADMIN)
# =============================================================================

set -euo pipefail

FLUSH_ONLY=false
if [[ "${1:-}" == "--flush" ]]; then
    FLUSH_ONLY=true
fi

# ---------------------------------------------------------------------------
# Flush existing IDS-managed rules
# ---------------------------------------------------------------------------
echo "[firewall_rules.sh] Flushing existing IDS rules..."

# Remove any rules with our comment prefix
nft list chain inet ids input 2>/dev/null | \
    grep -oP 'handle \K\d+(?=.*ids-(block|ratelimit))' | \
    while read -r handle; do
        nft delete rule inet ids input handle "$handle" 2>/dev/null || true
    done

if $FLUSH_ONLY; then
    echo "[firewall_rules.sh] Flush complete."
    exit 0
fi

# ---------------------------------------------------------------------------
# Create table and chains if they don't exist
# ---------------------------------------------------------------------------
echo "[firewall_rules.sh] Ensuring nftables table 'inet ids' exists..."

# Create the table (idempotent — nft ignores 'already exists' errors)
nft add table inet ids 2>/dev/null || true

# Create INPUT chain with default ACCEPT policy
# (IDS rules are inserted at the top; legitimate traffic falls through)
nft add chain inet ids input \
    '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true

# Create OUTPUT chain (for rate-limit egress rules if needed)
nft add chain inet ids output \
    '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true

# ---------------------------------------------------------------------------
# Baseline allow rules (inserted at low priority so IDS rules take precedence)
# ---------------------------------------------------------------------------
echo "[firewall_rules.sh] Adding baseline allow rules..."

# Allow established/related connections
nft add rule inet ids input \
    ct state established,related counter accept \
    comment "ids-baseline-established" 2>/dev/null || true

# Allow loopback
nft add rule inet ids input \
    iif lo counter accept \
    comment "ids-baseline-loopback" 2>/dev/null || true

# Allow ICMP (ping)
nft add rule inet ids input \
    ip protocol icmp counter accept \
    comment "ids-baseline-icmp" 2>/dev/null || true

# Allow SSH (management access — adjust port if needed)
nft add rule inet ids input \
    tcp dport 22 ct state new counter accept \
    comment "ids-baseline-ssh" 2>/dev/null || true

# Allow the IDS/IPS API port
nft add rule inet ids input \
    tcp dport 8000 ct state new counter accept \
    comment "ids-baseline-api" 2>/dev/null || true

# Allow IoT protocol ports (MQTT, CoAP, Modbus, BACnet)
for port in 1883 8883 5683 502 47808; do
    nft add rule inet ids input \
        tcp dport "$port" ct state new counter accept \
        comment "ids-baseline-iot-$port" 2>/dev/null || true
done

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo "[firewall_rules.sh] Baseline ruleset applied successfully."
echo "[firewall_rules.sh] Current INPUT chain:"
nft list chain inet ids input 2>/dev/null || echo "(nftables not available — simulation mode)"

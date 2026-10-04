#!/usr/bin/env bash
# =============================================================================
# scripts/reset_firewall.sh
#
# Flush all IDS/IPS-managed nftables rules and restore the baseline ruleset.
#
# Use this script to:
#   - Clear all dynamic block/rate-limit rules after an incident
#   - Reset the firewall to a known-good state before testing
#   - Recover from a misconfigured ruleset
#
# Usage:
#   sudo bash scripts/reset_firewall.sh           # flush IDS rules, keep baseline
#   sudo bash scripts/reset_firewall.sh --full    # flush everything including baseline
#
# Requirements:
#   - nftables >= 0.9.3
#   - Run as root (or with CAP_NET_ADMIN)
# =============================================================================

set -euo pipefail

FULL_RESET=false
if [[ "${1:-}" == "--full" ]]; then
    FULL_RESET=true
fi

echo "[reset_firewall.sh] Starting firewall reset..."

# ---------------------------------------------------------------------------
# Count rules before reset
# ---------------------------------------------------------------------------
BEFORE=$(nft list chain ip filter INPUT 2>/dev/null | grep -c "ids-block\|ids-ratelimit" || echo 0)
echo "[reset_firewall.sh] Found $BEFORE IDS-managed rules to remove."

# ---------------------------------------------------------------------------
# Remove all IDS-managed dynamic rules (block + rate-limit)
# ---------------------------------------------------------------------------
echo "[reset_firewall.sh] Removing IDS block rules..."
nft list chain ip filter INPUT 2>/dev/null | \
    grep -oP 'handle \K\d+(?=.*ids-block)' | \
    while read -r handle; do
        echo "  Removing block rule handle $handle"
        nft delete rule ip filter INPUT handle "$handle" 2>/dev/null || true
    done

echo "[reset_firewall.sh] Removing IDS rate-limit rules..."
nft list chain ip filter INPUT 2>/dev/null | \
    grep -oP 'handle \K\d+(?=.*ids-ratelimit)' | \
    while read -r handle; do
        echo "  Removing rate-limit rule handle $handle"
        nft delete rule ip filter INPUT handle "$handle" 2>/dev/null || true
    done

# ---------------------------------------------------------------------------
# Full reset: flush the entire table
# ---------------------------------------------------------------------------
if $FULL_RESET; then
    echo "[reset_firewall.sh] Full reset: flushing entire ip filter table..."
    nft flush table ip filter 2>/dev/null || true
    echo "[reset_firewall.sh] Re-applying baseline ruleset..."
    bash "$(dirname "$0")/../config/firewall_rules.sh"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
AFTER=$(nft list chain ip filter INPUT 2>/dev/null | grep -c "ids-block\|ids-ratelimit" || echo 0)
echo "[reset_firewall.sh] Reset complete. IDS rules remaining: $AFTER"
echo "[reset_firewall.sh] Current INPUT chain:"
nft list chain ip filter INPUT 2>/dev/null || echo "(nftables not available — simulation mode)"

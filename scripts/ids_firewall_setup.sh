#!/usr/bin/env bash
set -euo pipefail

# Dedicated IDS chain; Docker's iptables-nft tables remain untouched.
nft add table inet ids 2>/dev/null || true
nft add chain inet ids input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
nft list chain inet ids input
"""
Unit tests for nftables_manager.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

from backend.firewall import nftables_manager


@pytest.fixture(autouse=True)
def cleanup_rules():
    """Clear the active rules dictionary before and after each test."""
    nftables_manager._active_rules.clear()
    yield
    nftables_manager._active_rules.clear()


@pytest.fixture
def mock_subprocess_success():
    """Mock subprocess.run to simulate successful nftables execution."""
    with patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        yield mock_run


@pytest.fixture
def mock_subprocess_simulation():
    """Mock subprocess.run to simulate nftables not found (simulation mode)."""
    with patch.dict(os.environ, {"FIREWALL_MODE": "simulation", "FIREWALL_EXECUTOR_SOCKET": ""}), \
            patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("nftables not found")
        yield mock_run


@pytest.fixture
def mock_subprocess_list_success():
    """Mock subprocess.run for remove_rule with handles."""
    with patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
        
        def side_effect(*args, **kwargs):
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            
            cmd = args[0]
            if "list" in cmd:
                rule = next(iter(nftables_manager._active_rules.values()), None)
                if rule and rule.action == "rate_limit":
                    mock_result.stdout = (
                        f'rule ip saddr {rule.ip} limit rate over 100/second counter drop '
                        f'comment "ids-ratelimit-{rule.rule_id}" handle 54'
                    )
                elif rule:
                    mock_result.stdout = (
                        f'rule ip saddr {rule.ip} counter drop '
                        f'comment "ids-block-{rule.rule_id}" handle 54'
                    )
                else:
                    mock_result.stdout = ""
            else:
                mock_result.stdout = ""
            return mock_result
            
        mock_run.side_effect = side_effect
        yield mock_run


class TestNftablesManager:
    # ------------------------------------------------------------------
    # block_ip
    # ------------------------------------------------------------------

    def test_add_block_rule_success(self, mock_subprocess_success):
        """Test: add_block_rule creates a rule and adds it to tracking."""
        ip = "192.168.1.10"
        ttl_seconds = 300

        rule_id = nftables_manager.add_block_rule(ip, ttl_seconds)

        # Verify tracking
        assert rule_id in nftables_manager._active_rules
        rule = nftables_manager._active_rules[rule_id]
        assert rule.ip == ip
        assert rule.action == "drop"
        assert rule.chain == "INPUT"
        assert rule.expires_at is not None

        # Verify expiry time is roughly correct (allow 1s drift)
        expected_expiry = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        diff = abs((rule.expires_at - expected_expiry).total_seconds())
        assert diff < 1.0

    def test_add_block_rule_calls_nft_with_correct_args(self, mock_subprocess_success):
        """Test: add_block_rule calls nft with correct arguments."""
        ip = "10.0.0.5"
        ttl_seconds = 60

        rule_id = nftables_manager.add_block_rule(ip, ttl_seconds)

        assert mock_subprocess_success.call_count >= 1
        call_args = mock_subprocess_success.call_args_list[-1][0][0]

        # Verify command construction
        assert call_args[0] == "nft"
        assert "insert" in call_args
        assert "drop" in call_args
        assert ip in call_args
        assert f"ids-block-{rule_id}" in call_args

    def test_add_block_rule_failure(self):
        """Test: add_block_rule fails gracefully on subprocess error."""
        with patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "Permission denied"
            mock_run.return_value = mock_result

            rule_id = nftables_manager.add_block_rule("192.168.1.1", 300)

            # Verification
            assert rule_id not in nftables_manager._active_rules

    # ------------------------------------------------------------------
    # rate_limit
    # ------------------------------------------------------------------

    def test_add_rate_limit_rule_success(self, mock_subprocess_success):
        """Test: add_rate_limit_rule creates a rule and adds it to tracking."""
        ip = "192.168.1.20"
        pps_limit = 50
        ttl_seconds = 300

        rule_id = nftables_manager.add_rate_limit_rule(ip, pps_limit, ttl_seconds)

        # Verify tracking
        assert rule_id in nftables_manager._active_rules
        rule = nftables_manager._active_rules[rule_id]
        assert rule.ip == ip
        assert rule.action == "rate_limit"
        assert rule.chain == "INPUT"
        assert rule.expires_at is not None
        expected_expiry = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        assert abs((rule.expires_at - expected_expiry).total_seconds()) < 1.0

    def test_add_rate_limit_rule_calls_nft_with_limit(self, mock_subprocess_success):
        """Test: add_rate_limit_rule calls nft with rate limit parameters."""
        ip = "10.0.0.6"
        pps_limit = 25

        rule_id = nftables_manager.add_rate_limit_rule(ip, pps_limit)

        assert mock_subprocess_success.call_count >= 1
        call_args = mock_subprocess_success.call_args_list[-1][0][0]

        # Verify command construction
        assert "nft" in call_args
        assert "over" in call_args
        assert f"{pps_limit}/second" in call_args
        assert "drop" in call_args
        assert ip in call_args

    def test_add_rate_limit_rule_rejects_invalid_parameters(self):
        with pytest.raises(ValueError, match="pps_limit"):
            nftables_manager.add_rate_limit_rule("192.0.2.1", 0)
        with pytest.raises(ValueError, match="ttl_seconds"):
            nftables_manager.add_rate_limit_rule("192.0.2.1", 10, 0)

    def test_add_rate_limit_rule_renews_existing_expiry(self, mock_subprocess_success):
        ip = "192.0.2.2"
        rule_id = nftables_manager.add_rate_limit_rule(ip, 25, 60)
        previous_expiry = nftables_manager._active_rules[rule_id].expires_at

        renewed_id = nftables_manager.add_rate_limit_rule(ip, 25, 600)

        assert renewed_id == rule_id
        assert nftables_manager._active_rules[rule_id].expires_at > previous_expiry

    def test_clear_expired_rate_limit_rule(self, mock_subprocess_list_success):
        rule_id = nftables_manager.add_rate_limit_rule("192.0.2.3", 25, 60)
        rule = nftables_manager._active_rules[rule_id]
        nftables_manager._active_rules[rule_id] = rule._replace(
            expires_at=datetime.utcnow() - timedelta(seconds=1)
        )

        assert nftables_manager.clear_expired_rules() == 1
        assert rule_id not in nftables_manager._active_rules

    def test_add_rate_limit_rule_failure(self):
        """Test: add_rate_limit_rule fails gracefully on subprocess error."""
        with patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_run.return_value = mock_result

            rule_id = nftables_manager.add_rate_limit_rule("192.168.1.2", 100)

            # Verification
            assert rule_id not in nftables_manager._active_rules

    # ------------------------------------------------------------------
    # remove_rule
    # ------------------------------------------------------------------

    def test_remove_rule_success(self, mock_subprocess_list_success):
        """Test: remove_rule deletes the rule from tracking on success."""
        ip = "192.168.1.30"
        ttl_seconds = 300

        rule_id = nftables_manager.add_block_rule(ip, ttl_seconds)
        assert rule_id in nftables_manager._active_rules

        # Remove rule
        result = nftables_manager.remove_rule(rule_id)

        # Verification
        assert result is True
        assert rule_id not in nftables_manager._active_rules

    def test_remove_rule_not_found(self, mock_subprocess_success):
        """Test: remove_rule returns False if rule ID is not tracked."""
        nonexistent_rule_id = "abc12345"

        result = nftables_manager.remove_rule(nonexistent_rule_id)

        assert result is False
        mock_subprocess_success.assert_not_called()

    # ------------------------------------------------------------------
    # clear_expired_rules
    # ------------------------------------------------------------------

    def test_clear_expired_rules_removes_old_rules(self, mock_subprocess_list_success):
        """Test: clear_expired_rules removes rules past their expiry time."""
        ip = "192.168.1.40"
        
        # Add rule and force its expiry to the past
        rule_id = nftables_manager.add_block_rule(ip, 300)
        past_time = datetime.utcnow() - timedelta(minutes=10)
        nftables_manager._active_rules[rule_id] = nftables_manager.FirewallRule(
            rule_id, ip, "drop", "INPUT", past_time
        )

        # Clear expired
        count = nftables_manager.clear_expired_rules()

        # Verification
        assert count == 1
        assert rule_id not in nftables_manager._active_rules

    def test_clear_expired_rules_keeps_active_rules(self, mock_subprocess_success):
        """Test: clear_expired_rules does not remove unexpired rules."""
        ip = "192.168.1.50"
        ttl_seconds = 300

        # Add rule
        rule_id = nftables_manager.add_block_rule(ip, ttl_seconds)

        # Clear expired (should do nothing)
        count = nftables_manager.clear_expired_rules()

        # Verification
        assert count == 0
        assert rule_id in nftables_manager._active_rules

    # ------------------------------------------------------------------
    # Simulation Mode
    # ------------------------------------------------------------------

    def test_simulation_mode_add_block_rule(self, mock_subprocess_simulation):
        """Tests for simulation mode (nftables not available)."""
        ip = "192.168.1.100"
        ttl_seconds = 300

        rule_id = nftables_manager.add_block_rule(ip, ttl_seconds)

        # Verification
        assert rule_id in nftables_manager._active_rules
        rule = nftables_manager._active_rules[rule_id]
        assert rule.ip == ip
        assert rule.action == "drop"

    def test_simulation_mode_remove_rule(self, mock_subprocess_simulation):
        """Test remove_rule works in simulation mode."""
        ip = "192.168.1.102"
        rule_id = nftables_manager.add_block_rule(ip, 300)

        result = nftables_manager.remove_rule(rule_id)

        assert result is True
        assert rule_id not in nftables_manager._active_rules


# ---------------------------------------------------------------------------
# Property-Based Tests
# ---------------------------------------------------------------------------

from hypothesis import given, settings, assume
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# Task 10.2 — Property 7: Add then remove is a no-op on state
# Validates: Requirements 8.7
# ---------------------------------------------------------------------------

# Strategy: build IPs in the 192.168.x.y range to avoid any OS-level
# filtering concerns while still exercising the full TTL range.
_valid_ip_strategy = st.builds(
    lambda x, y: f"192.168.{x}.{y}",
    x=st.integers(min_value=0, max_value=255),
    y=st.integers(min_value=1, max_value=254),
)

_ttl_strategy = st.integers(min_value=1, max_value=86400)


class TestPropertyAddThenRemoveNoOp:
    """
    **Validates: Requirements 8.7**

    Property 7: For all valid IP addresses and TTL values in [1, 86400],
    calling add_block_rule followed by remove_rule leaves _active_rules in
    the same state as before both calls.
    """

    @given(ip=_valid_ip_strategy, ttl=_ttl_strategy)
    @settings(max_examples=100, deadline=None)
    def test_add_then_remove_is_noop(self, ip, ttl):
        """
        **Validates: Requirements 8.7**

        Add a block rule then immediately remove it; the _active_rules dict
        must be identical (same keys and values) to its state before the
        two calls.
        """
        from unittest.mock import patch

        with patch.dict(os.environ, {"FIREWALL_MODE": "simulation", "FIREWALL_EXECUTOR_SOCKET": ""}), \
            patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
            # Simulate nftables not found so remove_rule uses simulation path
            mock_run.side_effect = FileNotFoundError("nftables not found")

            # Ensure a clean slate for this example
            nftables_manager._active_rules.clear()

            # Snapshot state before
            state_before = dict(nftables_manager._active_rules)

            # Exercise: add then remove
            rule_id = nftables_manager.add_block_rule(ip, ttl)
            removed = nftables_manager.remove_rule(rule_id)

            # Snapshot state after
            state_after = dict(nftables_manager._active_rules)

            # Property assertion
            assert removed is True, (
                f"remove_rule returned False for rule_id={rule_id!r} "
                f"(ip={ip!r}, ttl={ttl})"
            )
            assert state_after == state_before, (
                f"_active_rules changed after add+remove: "
                f"before={state_before!r}, after={state_after!r}"
            )


# ---------------------------------------------------------------------------
# Task 10.3 — Property 8: Non-expired rules are never removed
# Validates: Requirements 8.8
# ---------------------------------------------------------------------------

class TestPropertyClearExpiredRulesCorrectness:
    """
    **Validates: Requirements 8.8**

    Property 8: For all sets of rules with distinct expiry times,
    clear_expired_rules() only removes rules whose expires_at <= now.
    Rules with expires_at > now must remain untouched.
    """

    @given(
        expired_count=st.integers(min_value=0, max_value=10),
        active_count=st.integers(min_value=0, max_value=10),
    )
    @settings(max_examples=100, deadline=None)
    def test_only_expired_rules_are_removed(self, expired_count, active_count):
        """
        **Validates: Requirements 8.8**

        Manually insert FirewallRule objects with controlled expires_at
        timestamps (some in the past, some in the future), call
        clear_expired_rules(), and verify:
          - every past-expired rule has been removed
          - every future-active rule is still present
        """
        from unittest.mock import patch

        with patch.dict(os.environ, {"FIREWALL_MODE": "simulation", "FIREWALL_EXECUTOR_SOCKET": ""}), \
            patch("backend.firewall.nftables_manager.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("nftables not found")

            nftables_manager._active_rules.clear()

            now = datetime.utcnow()

            # Insert expired rules (expires_at in the past)
            expired_ids = []
            for i in range(expired_count):
                rid = f"exp{i:04d}"
                past_time = now - timedelta(seconds=60 + i)
                nftables_manager._active_rules[rid] = nftables_manager.FirewallRule(
                    rule_id=rid,
                    ip=f"10.0.{i // 256}.{i % 256}",
                    action="drop",
                    chain="INPUT",
                    expires_at=past_time,
                )
                expired_ids.append(rid)

            # Insert active rules (expires_at in the future)
            active_ids = []
            for i in range(active_count):
                rid = f"act{i:04d}"
                future_time = now + timedelta(seconds=3600 + i)
                nftables_manager._active_rules[rid] = nftables_manager.FirewallRule(
                    rule_id=rid,
                    ip=f"172.16.{i // 256}.{i % 256}",
                    action="drop",
                    chain="INPUT",
                    expires_at=future_time,
                )
                active_ids.append(rid)

            # Exercise
            removed_count = nftables_manager.clear_expired_rules()

            # Property assertions
            assert removed_count == expired_count, (
                f"Expected {expired_count} rules removed, got {removed_count}"
            )

            # All expired rules must be gone
            for rid in expired_ids:
                assert rid not in nftables_manager._active_rules, (
                    f"Expired rule {rid!r} was not removed by clear_expired_rules()"
                )

            # All active rules must still be present
            for rid in active_ids:
                assert rid in nftables_manager._active_rules, (
                    f"Active rule {rid!r} was incorrectly removed by clear_expired_rules()"
                )

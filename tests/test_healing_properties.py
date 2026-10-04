"""
Property-based tests for healing agent service restart logic.

Property 9: Success path always returns True
Validates: Requirements 9.5
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.healing.service_restart import restart_service

# ---------------------------------------------------------------------------
# Strategy: valid service names
# ---------------------------------------------------------------------------

# A valid service name is a non-empty string of alphanumeric characters,
# hyphens, underscores, and dots — matching real systemd/init service names.
valid_service_name = st.text(
    min_size=1,
    max_size=64,
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="-_.",
    ),
)


# ---------------------------------------------------------------------------
# Property 9: Success path always returns True
# ---------------------------------------------------------------------------


class TestSuccessPathAlwaysReturnsTrue:
    """
    Property 9: Success path always returns True
    **Validates: Requirements 9.5**

    For any valid service name, when the underlying subprocess always exits
    with returncode 0 (success), restart_service must return True.
    """

    @given(service_name=valid_service_name)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_success_path_always_returns_true(self, service_name: str) -> None:
        """
        **Validates: Requirements 9.5**

        Generate random valid service names, mock subprocess to always succeed
        (returncode=0), and verify restart_service always returns True.
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "backend.healing.service_restart.shutil.which",
            side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None,
        ), patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = asyncio.run(restart_service(service_name))

        assert result is True, (
            f"restart_service({service_name!r}) returned {result!r} "
            "but expected True when subprocess always succeeds"
        )


# ---------------------------------------------------------------------------
# Property 10: Retry limit is always respected
# ---------------------------------------------------------------------------


class TestRetryLimitIsAlwaysRespected:
    """
    Property 10: Retry limit is always respected
    **Validates: Requirements 9.6**

    For any valid service name, when the underlying subprocess always exits
    with a non-zero returncode (failure), restart_service must make no more
    than 3 subprocess attempts before giving up and returning False.
    """

    @given(service_name=valid_service_name)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_retry_limit_is_always_respected(self, service_name: str) -> None:
        """
        **Validates: Requirements 9.6**

        Mock subprocess to always fail (returncode != 0), count the number of
        subprocess calls, and verify it never exceeds 3.
        """
        call_count = 0

        async def failing_subprocess(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_proc = MagicMock()
            mock_proc.returncode = 1  # always fail
            mock_proc.communicate = AsyncMock(return_value=(b"", b"restart failed"))
            return mock_proc

        async def run_with_no_sleep(*args, **kwargs):
            # Skip actual sleep to keep tests fast
            pass

        with patch(
            "backend.healing.service_restart.shutil.which",
            side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None,
        ), patch("asyncio.create_subprocess_exec", side_effect=failing_subprocess), \
             patch("asyncio.sleep", side_effect=run_with_no_sleep):
            result = asyncio.run(restart_service(service_name))

        assert result is False, (
            f"restart_service({service_name!r}) returned {result!r} "
            "but expected False when subprocess always fails"
        )
        assert call_count <= 3, (
            f"restart_service({service_name!r}) made {call_count} subprocess calls "
            "but the retry limit is 3 — limit was exceeded"
        )
        assert call_count > 0, (
            f"restart_service({service_name!r}) made 0 subprocess calls "
            "but at least one attempt is expected"
        )

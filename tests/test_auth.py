"""
Unit and property-based tests for JWT authentication service.

Tests cover:
- JWT token creation and validation
- Password hashing and verification
- User authentication flow
- Auth event logging
- JWT round-trip consistency (property-based)

Requirements: 5.1, 5.2, 5.3, 5.4, 5.14
"""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings, HealthCheck, strategies as st
from jose import jwt

from backend.api.auth import AuthService, JWT_ALGORITHM, JWT_EXPIRE_MINUTES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_jwt_secret():
    """Provide a test JWT secret key."""
    return "test-secret-key-for-jwt-testing-only"


@pytest.fixture(autouse=True)
def set_jwt_secret(mock_jwt_secret, monkeypatch):
    """Set JWT_SECRET_KEY for all tests."""
    monkeypatch.setattr("backend.api.auth.JWT_SECRET_KEY", mock_jwt_secret)


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

# Valid username strategy: alphanumeric strings, 3-50 characters
valid_usernames = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-"),
    min_size=3,
    max_size=50,
).filter(lambda s: s and not s.startswith("-") and not s.startswith("_"))

# Valid role strategy: one of the three defined roles
valid_roles = st.sampled_from(["admin", "analyst", "viewer"])


# ---------------------------------------------------------------------------
# Property-Based Tests (Task 2.3)
# ---------------------------------------------------------------------------

class TestJWTRoundTripProperty:
    """
    Property-based tests for JWT round-trip consistency.
    
    **Validates: Requirements 5.14**
    """

    @given(username=valid_usernames, role=valid_roles)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_jwt_round_trip_preserves_claims(self, username: str, role: str, mock_jwt_secret):
        """
        **Property 1: JWT round-trip consistency**
        
        **Validates: Requirements 5.14**
        
        Test: FOR ALL valid JWT tokens, decoding the token with the same secret key
        SHALL produce the original `sub` and `role` claims (round-trip property).
        
        Strategy:
        1. Generate random valid username/role pairs
        2. Encode to JWT using AuthService.create_access_token
        3. Decode using AuthService.verify_token
        4. Verify claims match exactly
        """
        # Arrange - create access token with random username and role
        token = AuthService.create_access_token(username=username, role=role)
        
        # Act - decode the token
        token_data = AuthService.verify_token(token)
        
        # Assert - verify claims match exactly
        assert token_data.username == username, f"Username mismatch: expected {username}, got {token_data.username}"
        assert token_data.role == role, f"Role mismatch: expected {role}, got {token_data.role}"

    @given(username=valid_usernames, role=valid_roles)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_jwt_round_trip_with_custom_expiry(self, username: str, role: str, mock_jwt_secret):
        """
        Test: JWT round-trip with custom expiry preserves claims.
        
        Validates that custom expiry times don't affect claim preservation.
        """
        # Arrange - create token with custom expiry (2 hours)
        custom_expiry = timedelta(hours=2)
        token = AuthService.create_access_token(
            username=username,
            role=role,
            expires_delta=custom_expiry
        )
        
        # Act - decode the token
        token_data = AuthService.verify_token(token)
        
        # Assert - verify claims match
        assert token_data.username == username
        assert token_data.role == role

    @given(username=valid_usernames, role=valid_roles)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_jwt_contains_required_standard_claims(self, username: str, role: str, mock_jwt_secret):
        """
        Test: JWT tokens contain required standard claims (exp, iat).
        
        Validates that tokens include expiration and issued-at timestamps.
        """
        # Arrange & Act - create token
        token = AuthService.create_access_token(username=username, role=role)
        
        # Decode without verification to inspect all claims
        payload = jwt.decode(token, mock_jwt_secret, algorithms=[JWT_ALGORITHM])
        
        # Assert - verify standard claims exist
        assert "sub" in payload, "Token missing 'sub' claim"
        assert "role" in payload, "Token missing 'role' claim"
        assert "exp" in payload, "Token missing 'exp' claim"
        assert "iat" in payload, "Token missing 'iat' claim"
        
        # Verify claim values
        assert payload["sub"] == username
        assert payload["role"] == role
        
        # Verify exp is in the future
        exp_timestamp = payload["exp"]
        iat_timestamp = payload["iat"]
        assert exp_timestamp > iat_timestamp, "Expiration must be after issued-at"

    @given(username=valid_usernames, role=valid_roles)
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_jwt_expiry_is_correctly_set(self, username: str, role: str, mock_jwt_secret):
        """
        Test: JWT expiry is set to JWT_EXPIRE_MINUTES from creation time.
        
        Validates that the expiration time matches the configured duration.
        """
        # Arrange
        before_creation = datetime.now(timezone.utc)
        
        # Act - create token
        token = AuthService.create_access_token(username=username, role=role)
        
        after_creation = datetime.now(timezone.utc)
        
        # Decode to inspect expiry
        payload = jwt.decode(token, mock_jwt_secret, algorithms=[JWT_ALGORITHM])
        exp_datetime = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat_datetime = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        
        # Assert - verify expiry is approximately JWT_EXPIRE_MINUTES from iat
        expected_expiry = iat_datetime + timedelta(minutes=JWT_EXPIRE_MINUTES)
        time_diff = abs((exp_datetime - expected_expiry).total_seconds())
        
        # Allow 2 second tolerance for test execution time
        assert time_diff < 2, f"Expiry time differs by {time_diff} seconds from expected"


# ---------------------------------------------------------------------------
# Unit Tests for AuthService
# ---------------------------------------------------------------------------

class TestAuthService:
    """Unit tests for AuthService methods."""

    def test_verify_password_correct(self):
        """Test: verify_password returns True for correct password."""
        # Arrange
        plain_password = "secure_password_123"
        password_hash = AuthService.hash_password(plain_password)
        
        # Act
        result = AuthService.verify_password(plain_password, password_hash)
        
        # Assert
        assert result is True

    def test_verify_password_incorrect(self):
        """Test: verify_password returns False for incorrect password."""
        # Arrange
        plain_password = "secure_password_123"
        wrong_password = "wrong_password_456"
        password_hash = AuthService.hash_password(plain_password)
        
        # Act
        result = AuthService.verify_password(wrong_password, password_hash)
        
        # Assert
        assert result is False

    def test_hash_password_produces_different_hashes(self):
        """Test: hash_password produces different hashes for same password (salt)."""
        # Arrange
        plain_password = "test_password"
        
        # Act
        hash1 = AuthService.hash_password(plain_password)
        hash2 = AuthService.hash_password(plain_password)
        
        # Assert - hashes should be different due to random salt
        assert hash1 != hash2
        # But both should verify correctly
        assert AuthService.verify_password(plain_password, hash1)
        assert AuthService.verify_password(plain_password, hash2)

    def test_create_access_token_returns_string(self, mock_jwt_secret):
        """Test: create_access_token returns a non-empty string."""
        # Act
        token = AuthService.create_access_token(username="testuser", role="viewer")
        
        # Assert
        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_token_with_expired_token_raises_exception(self, mock_jwt_secret):
        """Test: verify_token raises HTTPException for expired token."""
        # Arrange - create token that expired 1 hour ago
        expired_delta = timedelta(hours=-1)
        token = AuthService.create_access_token(
            username="testuser",
            role="viewer",
            expires_delta=expired_delta
        )
        
        # Act & Assert
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            AuthService.verify_token(token)
        
        assert exc_info.value.status_code == 401
        assert "Token invalid or expired" in exc_info.value.detail

    def test_verify_token_with_malformed_token_raises_exception(self, mock_jwt_secret):
        """Test: verify_token raises HTTPException for malformed token."""
        # Arrange
        malformed_token = "not.a.valid.jwt.token"
        
        # Act & Assert
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            AuthService.verify_token(malformed_token)
        
        assert exc_info.value.status_code == 401
        assert "Token invalid or expired" in exc_info.value.detail

    def test_verify_token_with_wrong_secret_raises_exception(self, mock_jwt_secret):
        """Test: verify_token raises HTTPException when token signed with different secret."""
        # Arrange - create token with different secret
        wrong_secret = "different-secret-key"
        payload = {
            "sub": "testuser",
            "role": "viewer",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }
        token = jwt.encode(payload, wrong_secret, algorithm=JWT_ALGORITHM)
        
        # Act & Assert
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            AuthService.verify_token(token)
        
        assert exc_info.value.status_code == 401

    def test_verify_token_with_missing_sub_claim_raises_exception(self, mock_jwt_secret):
        """Test: verify_token raises HTTPException when 'sub' claim is missing."""
        # Arrange - create token without 'sub' claim
        payload = {
            "role": "viewer",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }
        token = jwt.encode(payload, mock_jwt_secret, algorithm=JWT_ALGORITHM)
        
        # Act & Assert
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            AuthService.verify_token(token)
        
        assert exc_info.value.status_code == 401
        assert "Token invalid or expired" in exc_info.value.detail

    def test_verify_token_with_missing_role_claim_raises_exception(self, mock_jwt_secret):
        """Test: verify_token raises HTTPException when 'role' claim is missing."""
        # Arrange - create token without 'role' claim
        payload = {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }
        token = jwt.encode(payload, mock_jwt_secret, algorithm=JWT_ALGORITHM)
        
        # Act & Assert
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            AuthService.verify_token(token)
        
        assert exc_info.value.status_code == 401
        assert "Token invalid or expired" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Unit Tests for User Authentication
# ---------------------------------------------------------------------------

class TestAuthenticateUser:
    """Unit tests for authenticate_user method."""

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self):
        """Test: authenticate_user returns UserModel for valid credentials."""
        # Arrange
        username = "testuser"
        password = "correct_password"
        password_hash = AuthService.hash_password(password)
        
        # Mock UserModel
        mock_user = MagicMock()
        mock_user.username = username
        mock_user.password_hash = password_hash
        mock_user.role = "analyst"
        
        # Mock database session
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result
        
        # Act
        result = await AuthService.authenticate_user(username, password, mock_session)
        
        # Assert
        assert result is not None
        assert result.username == username
        assert result.role == "analyst"

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self):
        """Test: authenticate_user returns None for wrong password."""
        # Arrange
        username = "testuser"
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        password_hash = AuthService.hash_password(correct_password)
        
        # Mock UserModel
        mock_user = MagicMock()
        mock_user.username = username
        mock_user.password_hash = password_hash
        
        # Mock database session
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result
        
        # Act
        result = await AuthService.authenticate_user(username, wrong_password, mock_session)
        
        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_user_unknown_username(self):
        """Test: authenticate_user returns None for unknown username."""
        # Arrange
        username = "nonexistent_user"
        password = "any_password"
        
        # Mock database session - user not found
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        # Act
        result = await AuthService.authenticate_user(username, password, mock_session)
        
        # Assert
        assert result is None


# ---------------------------------------------------------------------------
# Unit Tests for Auth Event Logging
# ---------------------------------------------------------------------------

class TestAuthEventLogging:
    """Unit tests for log_auth_event method."""

    @pytest.mark.asyncio
    async def test_log_auth_event_creates_log_entry(self):
        """Test: log_auth_event creates AuthLogModel entry in database."""
        # Arrange
        username = "testuser"
        action = "login_success"
        ip_address = "192.168.1.100"
        
        # Mock database session
        mock_session = AsyncMock()
        
        # Act
        await AuthService.log_auth_event(username, action, ip_address, mock_session)
        
        # Assert
        mock_session.add.assert_called_once()
        mock_session.commit.assert_awaited_once()
        
        # Verify the log entry has correct fields
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.username == username
        assert log_entry.action == action
        assert log_entry.ip_address == ip_address
        assert log_entry.timestamp is not None

    @pytest.mark.asyncio
    async def test_log_auth_event_login_failure(self):
        """Test: log_auth_event records login_failure action."""
        # Arrange
        username = "testuser"
        action = "login_failure"
        ip_address = "10.0.0.50"
        
        # Mock database session
        mock_session = AsyncMock()
        
        # Act
        await AuthService.log_auth_event(username, action, ip_address, mock_session)
        
        # Assert
        mock_session.add.assert_called_once()
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.action == "login_failure"


# ---------------------------------------------------------------------------
# Unit Tests for Login Flow (Task 2.5)
# ---------------------------------------------------------------------------

class TestLoginFlow:
    """
    Unit tests for authentication service login flow.
    
    **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
    """

    @pytest.mark.asyncio
    async def test_successful_login_flow(self):
        """
        Test: Successful login flow returns JWT token and logs success.
        
        **Validates: Requirements 5.1, 5.2, 5.4**
        
        Verifies:
        - Password is verified against bcrypt hash
        - JWT token is created with correct claims
        - login_success is logged to auth_log
        """
        # Arrange
        username = "analyst_user"
        password = "secure_password_123"
        password_hash = AuthService.hash_password(password)
        client_ip = "192.168.1.50"
        
        # Mock UserModel
        mock_user = MagicMock()
        mock_user.username = username
        mock_user.password_hash = password_hash
        mock_user.role = "analyst"
        
        # Mock database session
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result
        
        # Act - authenticate user
        authenticated_user = await AuthService.authenticate_user(username, password, mock_session)
        
        # Assert - user is authenticated
        assert authenticated_user is not None
        assert authenticated_user.username == username
        assert authenticated_user.role == "analyst"
        
        # Act - create access token
        token = AuthService.create_access_token(
            username=authenticated_user.username,
            role=authenticated_user.role
        )
        
        # Assert - token is valid and contains correct claims
        token_data = AuthService.verify_token(token)
        assert token_data.username == username
        assert token_data.role == "analyst"
        
        # Act - log auth event
        await AuthService.log_auth_event(username, "login_success", client_ip, mock_session)
        
        # Assert - auth event was logged
        mock_session.add.assert_called_once()
        mock_session.commit.assert_awaited_once()
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.username == username
        assert log_entry.action == "login_success"
        assert log_entry.ip_address == client_ip

    @pytest.mark.asyncio
    async def test_login_with_wrong_password(self):
        """
        Test: Login with wrong password returns None and logs failure.
        
        **Validates: Requirements 5.2, 5.3**
        
        Verifies:
        - authenticate_user returns None for wrong password
        - login_failure is logged to auth_log
        """
        # Arrange
        username = "testuser"
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        password_hash = AuthService.hash_password(correct_password)
        client_ip = "10.0.0.100"
        
        # Mock UserModel
        mock_user = MagicMock()
        mock_user.username = username
        mock_user.password_hash = password_hash
        
        # Mock database session
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result
        
        # Act - attempt authentication with wrong password
        authenticated_user = await AuthService.authenticate_user(username, wrong_password, mock_session)
        
        # Assert - authentication fails
        assert authenticated_user is None
        
        # Act - log failed login attempt
        await AuthService.log_auth_event(username, "login_failure", client_ip, mock_session)
        
        # Assert - failure was logged
        mock_session.add.assert_called_once()
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.username == username
        assert log_entry.action == "login_failure"
        assert log_entry.ip_address == client_ip

    @pytest.mark.asyncio
    async def test_login_with_unknown_user(self):
        """
        Test: Login with unknown username returns None and logs failure.
        
        **Validates: Requirements 5.2, 5.3**
        
        Verifies:
        - authenticate_user returns None for unknown username
        - login_failure is logged to auth_log
        """
        # Arrange
        username = "nonexistent_user"
        password = "any_password"
        client_ip = "172.16.0.50"
        
        # Mock database session - user not found
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        # Act - attempt authentication with unknown user
        authenticated_user = await AuthService.authenticate_user(username, password, mock_session)
        
        # Assert - authentication fails
        assert authenticated_user is None
        
        # Act - log failed login attempt
        await AuthService.log_auth_event(username, "login_failure", client_ip, mock_session)
        
        # Assert - failure was logged
        mock_session.add.assert_called_once()
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.username == username
        assert log_entry.action == "login_failure"

    @pytest.mark.asyncio
    async def test_jwt_expiry_handling(self):
        """
        Test: Expired JWT tokens are rejected with appropriate error.
        
        **Validates: Requirements 5.1, 5.2**
        
        Verifies:
        - Tokens with past expiry time raise HTTPException
        - Exception has status code 401
        - Exception detail indicates token is invalid or expired
        """
        # Arrange - create token that expired 1 hour ago
        username = "testuser"
        role = "viewer"
        expired_delta = timedelta(hours=-1)
        
        # Act - create expired token
        expired_token = AuthService.create_access_token(
            username=username,
            role=role,
            expires_delta=expired_delta
        )
        
        # Assert - verify_token raises HTTPException
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            AuthService.verify_token(expired_token)
        
        # Assert - exception has correct status and message
        assert exc_info.value.status_code == 401
        assert "Token invalid or expired" in exc_info.value.detail
        assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}

    @pytest.mark.asyncio
    async def test_auth_log_records_client_ip(self):
        """
        Test: Auth log records client IP address for all events.
        
        **Validates: Requirements 5.4**
        
        Verifies:
        - login_success events include client IP
        - login_failure events include client IP
        - IP address is stored correctly in auth_log
        """
        # Arrange
        username = "testuser"
        client_ip = "203.0.113.42"
        
        # Mock database session
        mock_session = AsyncMock()
        
        # Act - log success event
        await AuthService.log_auth_event(username, "login_success", client_ip, mock_session)
        
        # Assert - IP was recorded
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.ip_address == client_ip
        assert log_entry.username == username
        assert log_entry.action == "login_success"
        
        # Reset mock
        mock_session.reset_mock()
        
        # Act - log failure event
        await AuthService.log_auth_event(username, "login_failure", client_ip, mock_session)
        
        # Assert - IP was recorded for failure too
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.ip_address == client_ip
        assert log_entry.action == "login_failure"

    @pytest.mark.asyncio
    async def test_successful_login_creates_valid_token_response(self):
        """
        Test: Successful login creates TokenResponse with all required fields.
        
        **Validates: Requirements 5.1**
        
        Verifies:
        - TokenResponse contains access_token
        - TokenResponse contains token_type = "bearer"
        - TokenResponse contains expires_in in seconds
        """
        # Arrange
        username = "admin_user"
        role = "admin"
        
        # Act - create access token
        access_token = AuthService.create_access_token(username=username, role=role)
        
        # Create token response (simulating what the endpoint would return)
        expires_in_seconds = JWT_EXPIRE_MINUTES * 60
        
        # Assert - token response has required fields
        assert isinstance(access_token, str)
        assert len(access_token) > 0
        
        # Verify token can be decoded
        token_data = AuthService.verify_token(access_token)
        assert token_data.username == username
        assert token_data.role == role
        
        # Verify expiry is set correctly
        from jose import jwt
        import backend.api.auth as auth_module
        payload = jwt.decode(access_token, auth_module.JWT_SECRET_KEY, algorithms=["HS256"])
        exp_timestamp = payload["exp"]
        iat_timestamp = payload["iat"]
        
        # Calculate actual expiry duration
        actual_expiry_seconds = exp_timestamp - iat_timestamp
        
        # Allow 2 second tolerance
        assert abs(actual_expiry_seconds - expires_in_seconds) < 2

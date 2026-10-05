"""
JWT authentication service and RBAC middleware for FastAPI.
Handles token issuance, validation, password verification, and role-based access control.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt as _bcrypt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import TokenData, TokenResponse
from backend.database.connection import get_session
from backend.database.models import AuthLogModel, UserModel

logger = logging.getLogger(__name__)

# Create auth router
router = APIRouter()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# JWT settings from environment variables.
# Keep module import safe in local/dev setups while still respecting explicit
# deployment configuration. We allow a dev fallback only when no secret is set.
_DEFAULT_DEV_JWT_SECRET = "dev-local-jwt-secret-change-me"
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))


def get_jwt_secret() -> str:
    """Resolve the active JWT secret with correct precedence for tests and runtime config."""
    module_secret = globals().get("JWT_SECRET_KEY", "")
    if module_secret and module_secret != _DEFAULT_DEV_JWT_SECRET:
        os.environ.setdefault("JWT_SECRET_KEY", module_secret)
        return module_secret

    env_secret = os.environ.get("JWT_SECRET_KEY")
    if env_secret and env_secret != _DEFAULT_DEV_JWT_SECRET:
        globals()["JWT_SECRET_KEY"] = env_secret
        return env_secret

    if env_secret == _DEFAULT_DEV_JWT_SECRET:
        globals()["JWT_SECRET_KEY"] = _DEFAULT_DEV_JWT_SECRET
        return _DEFAULT_DEV_JWT_SECRET

    globals()["JWT_SECRET_KEY"] = _DEFAULT_DEV_JWT_SECRET
    os.environ.setdefault("JWT_SECRET_KEY", _DEFAULT_DEV_JWT_SECRET)
    logger.warning(
        "JWT_SECRET_KEY is not configured; using a local development fallback. "
        "Set JWT_SECRET_KEY in the environment or .env for production use."
    )
    return _DEFAULT_DEV_JWT_SECRET

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
http_bearer = HTTPBearer(auto_error=False)

# Warm up JWT encoder to avoid first-call overhead during tests. This uses the
# same resolver as runtime code so explicit env config remains authoritative.
try:
    jwt.encode({"sub": "__warmup__", "role": "viewer", "exp": 0, "iat": 0}, get_jwt_secret(), algorithm=JWT_ALGORITHM)
except Exception:
    # Swallow any errors; warm-up is a best-effort optimization
    pass


# ---------------------------------------------------------------------------
# AuthService Class
# ---------------------------------------------------------------------------

class AuthService:
    """Service for JWT token creation, validation, and user authentication."""

    @staticmethod
    def verify_password(plain_password: str, password_hash: str) -> bool:
        """Verify a plain password against a bcrypt hash."""
        try:
            return _bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
        except Exception as exc:
            # If the stored hash is malformed or incompatible, log and treat as failed match
            logger.warning("Password verification failed (invalid hash): %s", exc)
            return False

    @staticmethod
    def hash_password(plain_password: str) -> str:
        """Hash a plain password using bcrypt."""
        return _bcrypt.hashpw(plain_password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def create_access_token(username: str, role: str, expires_delta: timedelta | None = None) -> str:
        """
        Create a JWT access token with username and role claims.
        
        Args:
            username: The username to encode in the token
            role: The user's role (admin, analyst, viewer)
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT token string
        """
        secret = get_jwt_secret()
        if expires_delta is None:
            expires_delta = timedelta(minutes=JWT_EXPIRE_MINUTES)
        
        expire = datetime.now(timezone.utc) + expires_delta
        
        payload = {
            "sub": username,
            "role": role,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        }
        
        encoded_jwt = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> TokenData:
        """
        Decode and validate a JWT token.
        
        Args:
            token: The JWT token string
            
        Returns:
            TokenData with username and role
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            secret = get_jwt_secret()
            payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
            username: str = payload.get("sub")
            role: str = payload.get("role")
            
            if username is None or role is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token invalid or expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return TokenData(username=username, role=role)
        
        except JWTError as exc:
            logger.warning("JWT validation failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalid or expired",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    @staticmethod
    async def authenticate_user(
        username: str,
        password: str,
        session: AsyncSession,
    ) -> UserModel | None:
        """
        Authenticate a user by username and password.
        
        Args:
            username: The username to authenticate
            password: The plain text password
            session: Database session
            
        Returns:
            UserModel if authentication succeeds, None otherwise
        """
        result = await session.execute(
            select(UserModel).where(UserModel.username == username)
        )
        user = result.scalar_one_or_none()
        
        if user is None:
            return None
        
        if not AuthService.verify_password(password, user.password_hash):
            return None
        
        return user

    @staticmethod
    async def log_auth_event(
        username: str,
        action: str,
        ip_address: str | None,
        session: AsyncSession,
    ) -> None:
        """
        Record an authentication event to the auth_log table.
        
        Args:
            username: The username involved in the event
            action: The action type (login_success, login_failure, logout)
            ip_address: The client IP address or None
            session: Database session
        """
        log_entry = AuthLogModel(
            username=username,
            action=action,
            ip_address=ip_address,
            timestamp=datetime.now(timezone.utc),
        )
        session.add(log_entry)
        await session.commit()
        logger.info("Auth event logged: %s for user %s from %s", action, username, ip_address)


# ---------------------------------------------------------------------------
# FastAPI Dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
) -> TokenData:
    """
    Get current authenticated user from JWT token.
    """

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return AuthService.verify_token(credentials.credentials)

def require_role(*allowed_roles: str):
    """
    FastAPI dependency factory for role-based access control.
    """
    async def _check_role(
        current_user: Annotated[TokenData, Depends(get_current_user)]
    ) -> TokenData:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return _check_role



# ---------------------------------------------------------------------------
# Role Permission Helpers
# ---------------------------------------------------------------------------

# RBAC Permission Matrix (Requirements 5.8, 5.9, 5.10)
ROLE_PERMISSIONS = {
    "viewer": {
        "GET": [
            "/api/v1/alerts",
            "/api/v1/incidents",
            "/api/v1/devices",
            "/api/v1/metrics",
            "/api/v1/reports",
        ],
    },
    "analyst": {
        "GET": [
            "/api/v1/alerts",
            "/api/v1/incidents",
            "/api/v1/devices",
            "/api/v1/metrics",
            "/api/v1/reports",
            "/api/v1/config",
        ],
        "POST": [
            "/api/v1/incidents/{id}/acknowledge",
        ],
    },
    "admin": {
        "GET": ["*"],  # All GET endpoints
        "POST": ["*"],  # All POST endpoints
        "PUT": ["*"],  # All PUT endpoints
        "DELETE": ["*"],  # All DELETE endpoints
    },
}


def get_client_ip(request: Request) -> str | None:
    """
    Extract client IP address from request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address as string, or None if unable to determine
    """
    # Check X-Forwarded-For header first (for proxies/load balancers)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return None


# ---------------------------------------------------------------------------
# Token Creation Helper
# ---------------------------------------------------------------------------

async def create_token_response(user: UserModel) -> TokenResponse:
    """
    Create a TokenResponse for a successfully authenticated user.
    
    Args:
        user: The authenticated UserModel
        
    Returns:
        TokenResponse with access token and metadata
    """
    access_token = AuthService.create_access_token(
        username=user.username,
        role=user.role,
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=JWT_EXPIRE_MINUTES * 60,  # Convert minutes to seconds
    )


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login and get access token",
    description="Authenticate with username and password to receive a JWT access token",
    responses={
        200: {
            "description": "Successful authentication — JWT access token returned",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTcwMDAwMDAwMH0.abc123",
                        "token_type": "bearer",
                        "expires_in": 3600,
                    }
                }
            },
        },
        401: {
            "description": "Invalid credentials — username not found or password incorrect",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid credentials"}
                }
            },
        },
        422: {
            "description": "Validation error — missing or empty username/password fields",
        },
    },
)
async def login(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """
    Authenticate user and issue a JWT access token (OAuth2 password flow).

    Accepts ``application/x-www-form-urlencoded`` form data with ``username`` and
    ``password`` fields (standard OAuth2 password grant).

    On success:
    - Records a ``login_success`` event in the ``auth_log`` table with the client IP.
    - Returns a signed HS256 JWT valid for ``JWT_EXPIRE_MINUTES`` minutes (default 60).

    On failure:
    - Records a ``login_failure`` event in the ``auth_log`` table.
    - Returns HTTP 401 with ``{"detail": "Invalid credentials"}``.

    Form Parameters:
        username: The account username (1–64 characters).
        password: The account password.

    Returns:
        TokenResponse containing ``access_token`` (JWT), ``token_type`` ("bearer"),
        and ``expires_in`` (seconds until expiry).

    Raises:
        401: Username not found or password does not match.

    Requirements: 5.1, 5.2, 5.3, 5.4
    """
    # Get client IP
    client_ip = get_client_ip(request)
    
    # Authenticate user
    user = await AuthService.authenticate_user(username, password, session)
    
    if user is None:
        # Log failed login attempt (Req 5.3)
        await AuthService.log_auth_event(
            username=username,
            action="login_failure",
            ip_address=client_ip,
            session=session,
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Log successful login (Req 5.4)
    await AuthService.log_auth_event(
        username=user.username,
        action="login_success",
        ip_address=client_ip,
        session=session,
    )
    
    # Create and return token response (Req 5.1)
    logger.info("User %s authenticated successfully from %s", username, client_ip)
    return await create_token_response(user)


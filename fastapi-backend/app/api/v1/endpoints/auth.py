"""
Authentication endpoints
"""
from datetime import datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.core.auth import (
    authenticate_user,
    create_token_pair,
    get_current_user,
    get_current_active_user,
    get_password_hash,
    get_user_by_email,
    verify_token
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import (
    UserCreate,
    UserResponse,
    UserLogin,
    Token,
    RefreshTokenRequest,
    PasswordChange,
    UserUpdate
)

router = APIRouter()
logger = structlog.get_logger()
security = HTTPBearer()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    *,
    db: AsyncSession = Depends(get_db),
    user_in: UserCreate
) -> Any:
    """
    Register a new user and send verification email
    """
    import os
    from datetime import datetime, timedelta
    from app.services.email_service import email_service, generate_verification_token
    
    # Check if user already exists
    existing_user = await get_user_by_email(db, user_in.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists"
        )
    
    # Generate verification token
    verification_token = generate_verification_token()
    token_expires = datetime.utcnow() + timedelta(hours=24)
    
    # Create new user
    hashed_password = get_password_hash(user_in.password)
    
    db_user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        organization=user_in.organization,
        timezone=user_in.timezone,
        hashed_password=hashed_password,
        is_active=True,
        is_verified=False,  # User starts unverified
        verification_token=verification_token,
        verification_token_expires=token_expires
    )
    
    try:
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        
        # Send verification email
        base_url = os.getenv("FRONTEND_URL", "http://localhost")
        await email_service.send_verification_email(
            to_email=db_user.email,
            verification_token=verification_token,
            base_url=base_url
        )
        
        logger.info("User registered successfully", user_id=db_user.id, email=db_user.email)
        
        return {
            "message": "Registration successful! Please check your email to verify your account.",
            "email": db_user.email
        }
        
    except Exception as e:
        await db.rollback()
        logger.error("User registration failed", email=user_in.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/login", response_model=Token)
async def login(
    *,
    db: AsyncSession = Depends(get_db),
    user_credentials: UserLogin
) -> Any:
    """
    Login user and return JWT tokens
    """
    user = await authenticate_user(db, user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Update last login time
    user.last_login_at = datetime.utcnow()
    await db.commit()
    
    # Create token pair
    token_data = create_token_pair(user)
    
    logger.info("User logged in", user_id=user.id, email=user.email)
    
    return token_data


@router.post("/refresh", response_model=Token)
async def refresh_token(
    *,
    db: AsyncSession = Depends(get_db),
    refresh_request: RefreshTokenRequest
) -> Any:
    """
    Refresh access token using refresh token
    """
    token_data = verify_token(refresh_request.refresh_token, "refresh")
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create new token pair
    new_token_data = create_token_pair(user)
    
    logger.info("Token refreshed", user_id=user.id, email=user.email)
    
    return new_token_data


@router.get("/me")
async def get_current_user_info(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Get current user information
    """
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "is_active": current_user.is_active,
        "is_admin": current_user.is_admin,
        "is_verified": current_user.is_verified
    }


@router.get("/verify-email")
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Verify user email address using verification token
    """
    from datetime import datetime
    from sqlalchemy import select
    
    # Find user by verification token
    result = await db.execute(
        select(User).where(User.verification_token == token)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )
    
    # Check if token is expired
    if user.verification_token_expires and user.verification_token_expires < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has expired. Please request a new one."
        )
    
    # Verify the user
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    
    await db.commit()
    
    logger.info("User email verified", user_id=user.id, email=user.email)
    
    return {
        "message": "Email verified successfully! You can now log in to the platform.",
        "verified": True
    }


@router.post("/resend-verification")
async def resend_verification(
    email_request: dict,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Resend verification email
    """
    import os
    from datetime import datetime, timedelta
    from app.services.email_service import email_service, generate_verification_token
    
    email = email_request.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    user = await get_user_by_email(db, email)
    if not user:
        # Don't reveal if user exists or not for security
        return {"message": "If an account with this email exists, we've sent a verification email."}
    
    if user.is_verified:
        return {"message": "This account is already verified."}
    
    # Generate new verification token
    verification_token = generate_verification_token()
    token_expires = datetime.utcnow() + timedelta(hours=24)
    
    user.verification_token = verification_token
    user.verification_token_expires = token_expires
    
    await db.commit()
    
    # Send verification email
    base_url = os.getenv("FRONTEND_URL", "http://localhost")
    await email_service.send_verification_email(
        to_email=user.email,
        verification_token=verification_token,
        base_url=base_url
    )
    
    logger.info("Verification email resent", user_id=user.id, email=user.email)
    
    return {"message": "Verification email sent! Please check your inbox."}


@router.patch("/me", response_model=UserResponse)
async def update_current_user(
    *,
    db: AsyncSession = Depends(get_db),
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Update current user information
    """
    update_data = user_update.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(current_user, field, value)
    
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(current_user)
    
    logger.info("User profile updated", user_id=current_user.id, email=current_user.email)
    
    return current_user


@router.post("/change-password")
async def change_password(
    *,
    db: AsyncSession = Depends(get_db),
    password_change: PasswordChange,
    current_user: User = Depends(get_current_active_user)
) -> dict:
    """
    Change user password
    """
    from app.core.auth import verify_password
    
    # Verify current password
    if not verify_password(password_change.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )
    
    # Update password
    current_user.hashed_password = get_password_hash(password_change.new_password)
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    
    logger.info("Password changed", user_id=current_user.id, email=current_user.email)
    
    return {"message": "Password updated successfully"}


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user)
) -> dict:
    """
    Logout user (client should discard tokens)
    """
    logger.info("User logged out", user_id=current_user.id, email=current_user.email)
    
    return {"message": "Successfully logged out"}


# Demo endpoint to create initial admin user
@router.post("/create-admin", response_model=UserResponse)
async def create_admin_user(
    *,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Create initial admin user for demo purposes
    """
    admin_email = "admin@osint-platform.local"
    admin_password = "AdminPassword123!"
    
    # Check if admin already exists
    existing_admin = await get_user_by_email(db, admin_email)
    if existing_admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin user already exists"
        )
    
    # Create admin user
    hashed_password = get_password_hash(admin_password)
    
    db_user = User(
        email=admin_email,
        full_name="Platform Administrator",
        organization="OSINT Platform",
        timezone="UTC",
        hashed_password=hashed_password,
        is_admin=True,
        is_verified=True
    )
    
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    
    logger.info("Admin user created", user_id=db_user.id, email=db_user.email)
    
    return db_user
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
import logging
from typing import Dict, Any

from src.models.auth_models import (
    UserSignUpRequest,
    UserLoginRequest,
    PasswordResetRequest,
    PasswordResetConfirmRequest,
    TokenResponse,
    MessageResponse,
    UserResponse
)
from src.services.supabase_service import supabase_service
from src.services.session_service import session_service
from src.services.email_service import email_service
from src.middleware.auth_middleware import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User Sign Up",
    description="Register a new user account with email verification required"
)
async def sign_up(user_data: UserSignUpRequest) -> JSONResponse:
    """
    Register a new user account
    
    Creates a new user account using Supabase Auth and sends a welcome email.
    Email verification is required before the account is fully activated.
    
    - **email**: User's email address (must be unique)
    - **password**: Strong password meeting security requirements
    - **first_name**: User's first name
    - **last_name**: User's last name
    - **phone**: Optional phone number
    """
    try:
        logger.info(f"User signup attempt: {user_data.email}")
        
        # Prepare user metadata
        user_metadata = {
            "first_name": user_data.first_name,
            "last_name": user_data.last_name,
            "phone": user_data.phone,
            "email_verified": False,
            "2fa_enabled": True  # 2FA is mandatory
        }
        
        # Sign up user with Supabase
        success, result = await supabase_service.sign_up_user(
            email=user_data.email,
            password=user_data.password,
            user_metadata=user_metadata
        )
        
        if not success:
            error_msg = result.get("error", "Failed to create user account")
            logger.error(f"Signup failed for {user_data.email}: {error_msg}")
            
            # Handle specific error cases
            if "already registered" in error_msg.lower() or "already exists" in error_msg.lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="An account with this email already exists"
                )
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )
        
        # Send welcome email
        await email_service.send_welcome_email(user_data.email, user_data.first_name)
        
        logger.info(f"User signup successful: {user_data.email}")
        
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "message": "Account created successfully. Please check your email for verification instructions.",
                "success": True
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during signup for {user_data.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating your account"
        )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User Login",
    description="Authenticate user with email and password, returns access token for 2FA completion"
)
async def login(credentials: UserLoginRequest) -> JSONResponse:
    """
    Authenticate user with email and password
    
    Validates user credentials and returns an access token.
    Note: 2FA completion is required for full access to protected resources.
    
    - **email**: User's email address
    - **password**: User's password
    """
    try:
        logger.info(f"Login attempt for: {credentials.email}")
        
        # Sign in user with Supabase
        success, result = await supabase_service.sign_in_user(
            email=credentials.email,
            password=credentials.password
        )
        
        if not success:
            error_msg = result.get("error", "Invalid credentials")
            logger.warning(f"Login failed for {credentials.email}: {error_msg}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        user = result["user"]
        
        # Check if email is verified
        email_verified = user.email_confirmed_at is not None
        
        if not email_verified:
            logger.warning(f"Login attempt with unverified email: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please verify your email address before logging in"
            )
        
        # Create session (without 2FA completion initially)
        session_data = session_service.create_session(
            user_id=user.id,
            user_email=user.email,
            additional_data={
                "email_verified": email_verified,
                "2fa_completed": False  # Will be set to True after 2FA
            }
        )
        
        # Prepare user response
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.user_metadata.get("first_name"),
            last_name=user.user_metadata.get("last_name"),
            phone=user.user_metadata.get("phone"),
            email_verified=email_verified,
            created_at=user.created_at,
            last_sign_in_at=user.last_sign_in_at
        )
        
        logger.info(f"Login successful for: {credentials.email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": session_data["access_token"],
                "token_type": "bearer",
                "expires_in": session_data["expires_in"],
                "user": user_response.dict()
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login for {credentials.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login"
        )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="User Logout",
    description="Sign out user and invalidate session"
)
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    """
    Sign out user and invalidate session
    
    Revokes the current session and signs out the user from Supabase.
    """
    try:
        user_email = current_user["email"]
        session_id = current_user["session_id"]
        
        logger.info(f"Logout attempt for: {user_email}")
        
        # Revoke session
        session_service.revoke_session(session_id)
        
        # Note: Supabase session is handled by the client-side SDK
        # The server-side logout primarily involves session cleanup
        
        logger.info(f"Logout successful for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Logged out successfully",
                "success": True
            }
        )
        
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during logout"
        )


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request Password Reset",
    description="Send password reset email to user"
)
async def forgot_password(request: PasswordResetRequest) -> JSONResponse:
    """
    Send password reset email
    
    Sends a password reset link to the user's email address.
    
    - **email**: User's email address
    """
    try:
        logger.info(f"Password reset request for: {request.email}")
        
        # Send password reset email via Supabase
        success, result = await supabase_service.reset_password(request.email)
        
        if not success:
            # Don't reveal whether the email exists or not for security
            logger.warning(f"Password reset failed for {request.email}: {result.get('error')}")
        
        logger.info(f"Password reset email sent to: {request.email}")
        
        # Always return success message for security
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "If an account with this email exists, you will receive password reset instructions.",
                "success": True
            }
        )
        
    except Exception as e:
        logger.error(f"Error during password reset request for {request.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request"
        )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset Password",
    description="Reset user password with token"
)
async def reset_password(request: PasswordResetConfirmRequest) -> JSONResponse:
    """
    Reset user password with token
    
    Resets the user's password using the token received via email.
    
    - **token**: Password reset token from email
    - **new_password**: New password meeting security requirements
    """
    try:
        logger.info("Password reset confirmation attempt")
        
        # Note: Supabase handles password reset tokens automatically
        # This endpoint would typically be handled by the frontend
        # redirecting to Supabase's reset password flow
        
        # For now, return a message indicating the process
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Password reset functionality is handled by Supabase Auth flow. Please use the reset link from your email.",
                "success": True
            }
        )
        
    except Exception as e:
        logger.error(f"Error during password reset: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting your password"
        )


@router.get(
    "/verify-email",
    summary="Verify Email",
    description="Verify user email with token"
)
async def verify_email(token: str, email: str) -> JSONResponse:
    """
    Verify user email with token

    Verifies the user's email address using the token received via email.
    On success, returns a friendly message and a preliminary access token
    with flags: email_verified=True and 2fa_completed=False so frontend
    can seamlessly proceed to the 2FA step.

    - token: Email verification token
    - email: User's email address
    """
    try:
        logger.info(f"Email verification attempt for: {email}")

        # Verify email with Supabase (and ensure metadata updates)
        success, result = await supabase_service.verify_email(token, email)

        if not success:
            error_msg = result.get("error", "Invalid verification token")
            logger.error(f"Email verification failed for {email}: {error_msg}")

            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "message": "The verification link is invalid or has expired. Please request a new verification email.",
                    "success": False
                }
            )

        user = result.get("user")
        # Create a preliminary session to move user into 2FA step
        # This mirrors login behavior but sets 2FA incomplete.
        email_verified_flag = True
        session_data = session_service.create_session(
            user_id=user.id,
            user_email=user.email,
            additional_data={
                "email_verified": email_verified_flag,
                "2fa_completed": False
            }
        )

        logger.info(f"Email verified successfully for: {email}")

        # Provide a user-friendly message and include token for frontend to immediately prompt 2FA
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Email verified successfully! For your security, please complete 2FA to finish signing in.",
                "success": True,
                "access_token": session_data["access_token"],
                "token_type": "bearer",
                "expires_in": session_data["expires_in"]
            }
        )

    except Exception as e:
        logger.error(f"Error during email verification for {email}: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "message": "We couldn't verify your email due to a server error. Please try again shortly.",
                "success": False
            }
        )

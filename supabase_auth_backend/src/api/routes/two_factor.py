from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
import logging
from typing import Dict, Any

from src.models.auth_models import (
    TwoFactorSendRequest,
    TwoFactorRequest,
    MessageResponse,
    TokenResponse,
    UserResponse
)
from src.services.email_service import email_service
from src.services.session_service import session_service
from src.middleware.auth_middleware import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/2fa", tags=["Two-Factor Authentication"])


@router.post(
    "/send-otp",
    response_model=MessageResponse,
    summary="Send 2FA OTP",
    description="Send OTP code via email for two-factor authentication"
)
async def send_2fa_otp(
    request: TwoFactorSendRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> JSONResponse:
    """
    Send OTP code via email for two-factor authentication
    
    Sends a 6-digit OTP code to the user's email address for 2FA verification.
    The OTP expires after 10 minutes and allows up to 3 verification attempts.
    
    - **email**: User's email address (must match authenticated user)
    """
    try:
        user_email = current_user["email"]
        
        # Verify that the requested email matches the authenticated user
        if request.email != user_email:
            logger.warning(f"2FA OTP request email mismatch: {request.email} vs {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address must match your authenticated account"
            )
        
        logger.info(f"2FA OTP send request for: {user_email}")

        # Only allow sending when 2FA is still required
        token_payload = current_user.get("token_payload", {})
        if token_payload.get("2fa_completed", False):
            logger.info(f"2FA already completed; skipping OTP send for: {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA already completed for this session"
            )

        # Send OTP email
        success, otp_code = await email_service.send_otp_email(user_email, purpose="2fa")
        
        if not success:
            logger.error(f"Failed to send 2FA OTP to {user_email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP. Please try again."
            )
        
        logger.info(f"2FA OTP sent successfully to: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "OTP sent to your email address. Please check your inbox.",
                "success": True
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending 2FA OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while sending OTP"
        )


@router.post(
    "/verify-otp",
    response_model=TokenResponse,
    summary="Verify 2FA OTP",
    description="Verify OTP code and complete two-factor authentication"
)
async def verify_2fa_otp(
    request: TwoFactorRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> JSONResponse:
    """
    Verify OTP code and complete two-factor authentication
    
    Verifies the 6-digit OTP code and updates the user's session to indicate
    that 2FA has been completed, granting full access to protected resources.
    
    - **email**: User's email address (must match authenticated user)
    - **otp_code**: 6-digit OTP code received via email
    """
    try:
        user_email = current_user["email"]
        user_id = current_user["user_id"]
        session_id = current_user["session_id"]
        
        # Verify that the requested email matches the authenticated user
        if request.email != user_email:
            logger.warning(f"2FA OTP verification email mismatch: {request.email} vs {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address must match your authenticated account"
            )
        
        logger.info(f"2FA OTP verification attempt for: {user_email}")
        
        # Ensure this is a preliminary session that still requires 2FA
        token_payload = current_user.get("token_payload", {})
        if token_payload.get("2fa_completed", False):
            logger.info(f"2FA already completed for: {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA already completed for this session"
            )

        # Verify OTP
        is_valid = email_service.verify_otp(user_email, request.otp_code, purpose="2fa")
        if not is_valid:
            logger.warning(f"Invalid 2FA OTP for: {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP code"
            )

        # Revoke current preliminary session
        session_service.revoke_session(session_id)

        # Create new final session with 2FA completed
        new_session_data = session_service.create_session(
            user_id=user_id,
            user_email=user_email,
            additional_data={
                "email_verified": True,
                "2fa_completed": True
            }
        )

        # Prepare user response based on previous payload (profile metadata)
        user_response = UserResponse(
            id=user_id,
            email=user_email,
            first_name=token_payload.get("first_name"),
            last_name=token_payload.get("last_name"),
            phone=token_payload.get("phone"),
            email_verified=True,
            created_at=token_payload.get("created_at"),
            last_sign_in_at=token_payload.get("last_sign_in_at")
        )

        logger.info(f"2FA OTP verified successfully for: {user_email}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": new_session_data["access_token"],
                "token_type": "bearer",
                "expires_in": new_session_data["expires_in"],
                "user": user_response.dict()
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying 2FA OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during OTP verification"
        )


@router.post(
    "/resend-otp",
    response_model=MessageResponse,
    summary="Resend 2FA OTP",
    description="Resend OTP code for two-factor authentication"
)
async def resend_2fa_otp(
    request: TwoFactorSendRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> JSONResponse:
    """
    Resend OTP code for two-factor authentication
    
    Resends a new 6-digit OTP code to the user's email address.
    This invalidates any previously sent OTP codes.
    
    - **email**: User's email address (must match authenticated user)
    """
    try:
        user_email = current_user["email"]
        
        # Verify that the requested email matches the authenticated user
        if request.email != user_email:
            logger.warning(f"2FA OTP resend email mismatch: {request.email} vs {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address must match your authenticated account"
            )
        
        logger.info(f"2FA OTP resend request for: {user_email}")

        # Only allow resending when 2FA is still required
        token_payload = current_user.get("token_payload", {})
        if token_payload.get("2fa_completed", False):
            logger.info(f"2FA already completed; skipping OTP resend for: {user_email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA already completed for this session"
            )

        # Send new OTP email (this will invalidate the previous one)
        success, otp_code = await email_service.send_otp_email(user_email, purpose="2fa")
        
        if not success:
            logger.error(f"Failed to resend 2FA OTP to {user_email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to resend OTP. Please try again."
            )
        
        logger.info(f"2FA OTP resent successfully to: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "A new OTP has been sent to your email address.",
                "success": True
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resending 2FA OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resending OTP"
        )


@router.get(
    "/status",
    response_model=MessageResponse,
    summary="Get 2FA Status",
    description="Check if 2FA has been completed for the current session"
)
async def get_2fa_status(current_user: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    """
    Check if 2FA has been completed for the current session
    
    Returns the current 2FA status for the authenticated user's session.
    """
    try:
        token_payload = current_user.get("token_payload", {})
        two_fa_completed = token_payload.get("2fa_completed", False)
        requiring_2fa = not two_fa_completed

        logger.info(f"2FA status check for: {current_user['email']} - Completed: {two_fa_completed}")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"2FA {'completed' if two_fa_completed else 'required'}",
                "success": True,
                "2fa_completed": two_fa_completed,
                "requiring_2fa": requiring_2fa
            }
        )
        
    except Exception as e:
        logger.error(f"Error checking 2FA status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while checking 2FA status"
        )

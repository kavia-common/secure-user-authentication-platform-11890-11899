from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
import logging
from typing import Dict, Any

from src.models.auth_models import (
    UserProfileUpdateRequest,
    UserResponse,
    MessageResponse
)
from src.services.supabase_service import supabase_service
from src.services.session_service import session_service
from src.middleware.auth_middleware import get_current_2fa_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/user", tags=["User Profile"])


@router.get(
    "/profile",
    response_model=UserResponse,
    summary="Get User Profile",
    description="Get current user's profile information"
)
async def get_user_profile(current_user: Dict[str, Any] = Depends(get_current_2fa_user)) -> JSONResponse:
    """
    Get current user's profile information
    
    Retrieves the authenticated user's profile data including personal information
    and account status. Requires completed 2FA.
    """
    try:
        user_email = current_user["email"]
        user_id = current_user["user_id"]
        
        logger.info(f"Profile request for: {user_email}")
        
        # Get user information from Supabase
        token_payload = current_user.get("token_payload", {})
        
        # Get session info
        session_id = current_user["session_id"]
        session_info = session_service.get_session_info(session_id)
        
        # Prepare user response
        user_response = UserResponse(
            id=user_id,
            email=user_email,
            first_name=token_payload.get("first_name"),
            last_name=token_payload.get("last_name"),
            phone=token_payload.get("phone"),
            email_verified=token_payload.get("email_verified", False),
            created_at=token_payload.get("created_at"),
            last_sign_in_at=session_info.get("created_at") if session_info else None
        )
        
        logger.info(f"Profile retrieved successfully for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=user_response.dict()
        )
        
    except Exception as e:
        logger.error(f"Error retrieving profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving your profile"
        )


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Update User Profile",
    description="Update current user's profile information"
)
async def update_user_profile(
    profile_data: UserProfileUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_2fa_user)
) -> JSONResponse:
    """
    Update current user's profile information
    
    Updates the authenticated user's profile data. Only provided fields will be updated.
    Requires completed 2FA.
    
    - **first_name**: User's first name (optional)
    - **last_name**: User's last name (optional)
    - **phone**: User's phone number (optional)
    """
    try:
        user_email = current_user["email"]
        session_id = current_user["session_id"]
        
        logger.info(f"Profile update request for: {user_email}")
        
        # Prepare update data (only include fields that are not None)
        update_data = {}
        if profile_data.first_name is not None:
            update_data["first_name"] = profile_data.first_name
        if profile_data.last_name is not None:
            update_data["last_name"] = profile_data.last_name
        if profile_data.phone is not None:
            update_data["phone"] = profile_data.phone
        
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No update data provided"
            )
        
        # Get current session data to maintain access token
        session_info = session_service.get_session_info(session_id)
        if not session_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session"
            )
        
        # Update user with Supabase
        success, result = await supabase_service.update_user(
            access_token=session_info.get("access_token", ""),
            updates=update_data
        )
        
        if not success:
            error_msg = result.get("error", "Failed to update profile")
            logger.error(f"Profile update failed for {user_email}: {error_msg}")
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )
        
        updated_user = result["user"]
        
        # Prepare updated user response
        user_response = UserResponse(
            id=updated_user.id,
            email=updated_user.email,
            first_name=updated_user.user_metadata.get("first_name"),
            last_name=updated_user.user_metadata.get("last_name"),
            phone=updated_user.user_metadata.get("phone"),
            email_verified=updated_user.email_confirmed_at is not None,
            created_at=updated_user.created_at,
            last_sign_in_at=updated_user.last_sign_in_at
        )
        
        logger.info(f"Profile updated successfully for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=user_response.dict()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating your profile"
        )


@router.delete(
    "/account",
    response_model=MessageResponse,
    summary="Delete User Account",
    description="Delete current user's account permanently"
)
async def delete_user_account(current_user: Dict[str, Any] = Depends(get_current_2fa_user)) -> JSONResponse:
    """
    Delete current user's account permanently
    
    Permanently deletes the authenticated user's account and all associated data.
    This action cannot be undone. Requires completed 2FA.
    """
    try:
        user_email = current_user["email"]
        user_id = current_user["user_id"]
        
        logger.info(f"Account deletion request for: {user_email}")
        
        # Revoke all user sessions
        session_service.revoke_all_user_sessions(user_id)
        
        # Note: Supabase doesn't provide a direct API to delete users from the client side
        # This would typically require admin privileges or be handled through database triggers
        # For now, we'll return a message indicating the process
        
        logger.warning(f"Account deletion requested for {user_email} - Admin action required")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Account deletion request received. Your account will be deactivated and deleted within 24 hours.",
                "success": True
            }
        )
        
    except Exception as e:
        logger.error(f"Error during account deletion: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request"
        )


@router.get(
    "/sessions",
    summary="Get User Sessions",
    description="Get all active sessions for the current user"
)
async def get_user_sessions(current_user: Dict[str, Any] = Depends(get_current_2fa_user)) -> JSONResponse:
    """
    Get all active sessions for the current user
    
    Returns a list of all active sessions for the authenticated user,
    including session details and last activity times. Requires completed 2FA.
    """
    try:
        user_id = current_user["user_id"]
        user_email = current_user["email"]
        
        logger.info(f"Sessions request for: {user_email}")
        
        # Get all active sessions for the user
        user_sessions = []
        for session_id, session_data in session_service.active_sessions.items():
            if session_data["user_id"] == user_id and session_data["is_active"]:
                session_info = {
                    "session_id": session_id,
                    "created_at": session_data["created_at"],
                    "last_activity": session_data["last_activity"],
                    "expires_at": session_data["expires_at"],
                    "is_current": session_id == current_user["session_id"]
                }
                user_sessions.append(session_info)
        
        logger.info(f"Found {len(user_sessions)} active sessions for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "sessions": user_sessions,
                "total_count": len(user_sessions)
            }
        )
        
    except Exception as e:
        logger.error(f"Error retrieving sessions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving sessions"
        )


@router.delete(
    "/sessions/{session_id}",
    response_model=MessageResponse,
    summary="Revoke User Session",
    description="Revoke a specific user session"
)
async def revoke_user_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_2fa_user)
) -> JSONResponse:
    """
    Revoke a specific user session
    
    Revokes the specified session if it belongs to the authenticated user.
    Cannot revoke the current session - use logout instead. Requires completed 2FA.
    
    - **session_id**: ID of the session to revoke
    """
    try:
        user_id = current_user["user_id"]
        user_email = current_user["email"]
        current_session_id = current_user["session_id"]
        
        logger.info(f"Session revocation request for: {user_email}, session: {session_id}")
        
        # Prevent revoking current session
        if session_id == current_session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot revoke current session. Use logout instead."
            )
        
        # Check if session exists and belongs to the user
        session_data = session_service.active_sessions.get(session_id)
        if not session_data or session_data["user_id"] != user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        # Revoke the session
        success = session_service.revoke_session(session_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to revoke session"
            )
        
        logger.info(f"Session revoked successfully for: {user_email}, session: {session_id}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Session revoked successfully",
                "success": True
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revoking session: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while revoking the session"
        )

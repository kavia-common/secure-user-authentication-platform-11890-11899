from fastapi import HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any
import logging
from src.services.session_service import session_service
from src.services.jwt_service import jwt_service

logger = logging.getLogger(__name__)

security = HTTPBearer()


class AuthMiddleware:
    """Middleware for handling authentication and session validation"""
    
    def __init__(self):
        """Initialize authentication middleware"""
        self.security = HTTPBearer()
    
    # PUBLIC_INTERFACE
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
        """
        Get current user from access token
        
        Args:
            credentials: HTTP authorization credentials
            
        Returns:
            User information from token
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            token = credentials.credentials
            
            # Validate session using token
            is_valid, session_data = session_service.validate_session(token)
            
            if not is_valid or not session_data:
                logger.warning("Invalid or expired session")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Verify JWT token
            token_payload = jwt_service.verify_token(token)
            if not token_payload:
                logger.warning("Invalid JWT token")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Extend session on activity
            session_service.extend_session(session_data["session_id"])
            
            # Return user information
            return {
                "user_id": session_data["user_id"],
                "email": session_data["user_email"],
                "session_id": session_data["session_id"],
                "token_payload": token_payload
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in get_current_user: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # PUBLIC_INTERFACE
    async def get_optional_current_user(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Get current user from request (optional - doesn't raise exception if no token)
        
        Args:
            request: FastAPI request object
            
        Returns:
            User information or None if no valid token
        """
        try:
            authorization = request.headers.get("Authorization")
            if not authorization or not authorization.startswith("Bearer "):
                return None
            
            token = authorization.split(" ")[1]
            
            # Validate session using token
            is_valid, session_data = session_service.validate_session(token)
            
            if not is_valid or not session_data:
                return None
            
            # Verify JWT token
            token_payload = jwt_service.verify_token(token)
            if not token_payload:
                return None
            
            # Extend session on activity
            session_service.extend_session(session_data["session_id"])
            
            return {
                "user_id": session_data["user_id"],
                "email": session_data["user_email"],
                "session_id": session_data["session_id"],
                "token_payload": token_payload
            }
            
        except Exception as e:
            logger.error(f"Error in get_optional_current_user: {str(e)}")
            return None
    
    # PUBLIC_INTERFACE
    async def require_verified_email(self, current_user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Require that the user has a verified email address
        
        Args:
            current_user: Current user information
            
        Returns:
            User information if email is verified
            
        Raises:
            HTTPException: If email is not verified
        """
        try:
            # Get token payload
            token_payload = current_user.get("token_payload", {})
            
            # Check if email is verified (this would come from Supabase user metadata)
            email_verified = token_payload.get("email_verified", False)
            
            if not email_verified:
                logger.warning(f"Email not verified for user: {current_user['email']}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Email verification required",
                )
            
            return current_user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in require_verified_email: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication check failed",
            )
    
    # PUBLIC_INTERFACE
    async def require_2fa_completed(self, current_user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Require that the user has completed 2FA
        
        Args:
            current_user: Current user information
            
        Returns:
            User information if 2FA is completed
            
        Raises:
            HTTPException: If 2FA is not completed
        """
        try:
            # Get token payload
            token_payload = current_user.get("token_payload", {})
            
            # Check if 2FA is completed
            two_fa_completed = token_payload.get("2fa_completed", False)
            
            if not two_fa_completed:
                logger.warning(f"2FA not completed for user: {current_user['email']}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Two-factor authentication required",
                )
            
            return current_user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in require_2fa_completed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication check failed",
            )


# Global middleware instance
auth_middleware = AuthMiddleware()


# Dependency functions for FastAPI
async def get_current_user(credentials: HTTPAuthorizationCredentials = security) -> Dict[str, Any]:
    """FastAPI dependency for getting current user"""
    return await auth_middleware.get_current_user(credentials)


async def get_current_verified_user(current_user: Dict[str, Any] = get_current_user) -> Dict[str, Any]:
    """FastAPI dependency for getting current user with verified email"""
    return await auth_middleware.require_verified_email(current_user)


async def get_current_2fa_user(current_user: Dict[str, Any] = get_current_verified_user) -> Dict[str, Any]:
    """FastAPI dependency for getting current user with completed 2FA"""
    return await auth_middleware.require_2fa_completed(current_user)

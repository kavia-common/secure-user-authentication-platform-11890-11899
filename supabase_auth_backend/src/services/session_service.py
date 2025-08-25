from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging
import uuid
from src.services.jwt_service import jwt_service

logger = logging.getLogger(__name__)


class SessionService:
    """Service for managing user sessions and inactivity detection"""
    
    def __init__(self):
        """Initialize session service"""
        # In-memory session storage (in production, use Redis or database)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout_minutes = 30
    
    # PUBLIC_INTERFACE
    def create_session(self, user_id: str, user_email: str, additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a new user session
        
        Args:
            user_id: User's unique identifier
            user_email: User's email address
            additional_data: Additional session data
            
        Returns:
            Session information including access token
        """
        try:
            # Generate session ID
            session_id = str(uuid.uuid4())
            
            # Create JWT token payload
            token_payload = {
                "sub": user_id,
                "email": user_email,
                "session_id": session_id,
                "type": "access"
            }
            
            # Add additional data to token if provided
            if additional_data:
                token_payload.update(additional_data)
            
            # Create access token
            access_token = jwt_service.create_access_token(token_payload)
            
            # Store session data
            session_data = {
                "session_id": session_id,
                "user_id": user_id,
                "user_email": user_email,
                "created_at": datetime.utcnow(),
                "last_activity": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(minutes=self.session_timeout_minutes),
                "is_active": True,
                "access_token": access_token,
                "additional_data": additional_data or {}
            }
            
            self.active_sessions[session_id] = session_data
            
            logger.info(f"Session created for user {user_email}: {session_id}")
            
            return {
                "session_id": session_id,
                "access_token": access_token,
                "expires_at": session_data["expires_at"],
                "expires_in": self.session_timeout_minutes * 60  # in seconds
            }
            
        except Exception as e:
            logger.error(f"Error creating session for user {user_email}: {str(e)}")
            raise
    
    # PUBLIC_INTERFACE
    def validate_session(self, access_token: str) -> tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate a session using access token
        
        Args:
            access_token: JWT access token
            
        Returns:
            Tuple of (is_valid: bool, session_data: Optional[Dict])
        """
        try:
            # Verify JWT token
            token_payload = jwt_service.verify_token(access_token)
            if not token_payload:
                logger.warning("Invalid access token")
                return False, None
            
            session_id = token_payload.get("session_id")
            if not session_id:
                logger.warning("No session ID in token")
                return False, None
            
            # Check if session exists
            session_data = self.active_sessions.get(session_id)
            if not session_data:
                logger.warning(f"Session not found: {session_id}")
                return False, None
            
            # Check if session is active
            if not session_data["is_active"]:
                logger.warning(f"Session is inactive: {session_id}")
                return False, None
            
            # Check if session has expired
            if datetime.utcnow() > session_data["expires_at"]:
                logger.warning(f"Session expired: {session_id}")
                self._expire_session(session_id)
                return False, None
            
            # Update last activity
            session_data["last_activity"] = datetime.utcnow()
            
            logger.info(f"Session validated successfully: {session_id}")
            return True, session_data
            
        except Exception as e:
            logger.error(f"Error validating session: {str(e)}")
            return False, None
    
    # PUBLIC_INTERFACE
    def extend_session(self, session_id: str) -> bool:
        """
        Extend session expiration time
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if extended successfully, False otherwise
        """
        try:
            session_data = self.active_sessions.get(session_id)
            if not session_data or not session_data["is_active"]:
                return False
            
            # Extend expiration time
            session_data["expires_at"] = datetime.utcnow() + timedelta(minutes=self.session_timeout_minutes)
            session_data["last_activity"] = datetime.utcnow()
            
            logger.info(f"Session extended: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error extending session {session_id}: {str(e)}")
            return False
    
    # PUBLIC_INTERFACE
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a specific session
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if revoked successfully, False otherwise
        """
        try:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                logger.info(f"Session revoked: {session_id}")
                return True
            else:
                logger.warning(f"Session not found for revocation: {session_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error revoking session {session_id}: {str(e)}")
            return False
    
    # PUBLIC_INTERFACE
    def revoke_all_user_sessions(self, user_id: str) -> int:
        """
        Revoke all sessions for a specific user
        
        Args:
            user_id: User's unique identifier
            
        Returns:
            Number of sessions revoked
        """
        try:
            sessions_to_revoke = [
                session_id for session_id, session_data in self.active_sessions.items()
                if session_data["user_id"] == user_id
            ]
            
            for session_id in sessions_to_revoke:
                del self.active_sessions[session_id]
            
            logger.info(f"Revoked {len(sessions_to_revoke)} sessions for user: {user_id}")
            return len(sessions_to_revoke)
            
        except Exception as e:
            logger.error(f"Error revoking sessions for user {user_id}: {str(e)}")
            return 0
    
    # PUBLIC_INTERFACE
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session information
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information or None if not found
        """
        try:
            session_data = self.active_sessions.get(session_id)
            if session_data:
                return {
                    "session_id": session_data["session_id"],
                    "user_id": session_data["user_id"],
                    "user_email": session_data["user_email"],
                    "created_at": session_data["created_at"],
                    "last_activity": session_data["last_activity"],
                    "expires_at": session_data["expires_at"],
                    "is_active": session_data["is_active"],
                    "time_until_expiry": session_data["expires_at"] - datetime.utcnow()
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting session info for {session_id}: {str(e)}")
            return None
    
    # PUBLIC_INTERFACE
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            current_time = datetime.utcnow()
            expired_sessions = [
                session_id for session_id, session_data in self.active_sessions.items()
                if current_time > session_data["expires_at"]
            ]
            
            for session_id in expired_sessions:
                del self.active_sessions[session_id]
            
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            
            return len(expired_sessions)
            
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {str(e)}")
            return 0
    
    def _expire_session(self, session_id: str) -> None:
        """
        Mark a session as expired
        
        Args:
            session_id: Session identifier
        """
        session_data = self.active_sessions.get(session_id)
        if session_data:
            session_data["is_active"] = False
            logger.info(f"Session marked as expired: {session_id}")


# Global service instance
session_service = SessionService()

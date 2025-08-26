from supabase import create_client, Client
from typing import Dict, Any, Tuple
import logging
from src.config.settings import settings

logger = logging.getLogger(__name__)


class SupabaseService:
    """Service for handling Supabase authentication operations"""
    
    def __init__(self):
        """Initialize Supabase client"""
        self.supabase: Client = create_client(
            settings.supabase_url,
            settings.supabase_anon_key
        )
        self.admin_client: Client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key
        )
    
    # PUBLIC_INTERFACE
    async def sign_up_user(self, email: str, password: str, user_metadata: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Sign up a new user with Supabase Auth
        
        Args:
            email: User's email address
            password: User's password
            user_metadata: Additional user metadata (first_name, last_name, phone)
            
        Returns:
            Tuple of (success: bool, result: Dict)
        """
        try:
            # Sign up user with Supabase Auth
            response = self.supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": user_metadata,
                    "email_redirect_to": f"{settings.site_url}/auth/verify-email"
                }
            })
            
            if response.user:
                logger.info(f"User signed up successfully: {email}")
                return True, {
                    "user": response.user,
                    "session": response.session
                }
            else:
                logger.error(f"Failed to sign up user: {email}")
                return False, {"error": "Failed to create user account"}
                
        except Exception as e:
            logger.error(f"Error signing up user {email}: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def sign_in_user(self, email: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Sign in user with email and password
        
        Args:
            email: User's email address
            password: User's password
            
        Returns:
            Tuple of (success: bool, result: Dict)
        """
        try:
            response = self.supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if response.user and response.session:
                logger.info(f"User signed in successfully: {email}")
                return True, {
                    "user": response.user,
                    "session": response.session
                }
            else:
                logger.error(f"Failed to sign in user: {email}")
                return False, {"error": "Invalid email or password"}
                
        except Exception as e:
            logger.error(f"Error signing in user {email}: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def get_user_by_token(self, access_token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Get user information by access token
        
        Args:
            access_token: JWT access token
            
        Returns:
            Tuple of (success: bool, user_data: Dict)
        """
        try:
            # Set the session token
            self.supabase.auth.set_session(access_token, refresh_token="")
            
            # Get user
            response = self.supabase.auth.get_user()
            
            if response.user:
                return True, {"user": response.user}
            else:
                return False, {"error": "Invalid token"}
                
        except Exception as e:
            logger.error(f"Error getting user by token: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def refresh_session(self, refresh_token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Refresh user session
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            Tuple of (success: bool, result: Dict)
        """
        try:
            response = self.supabase.auth.refresh_session(refresh_token)
            
            if response.session:
                return True, {"session": response.session}
            else:
                return False, {"error": "Failed to refresh session"}
                
        except Exception as e:
            logger.error(f"Error refreshing session: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def sign_out_user(self, access_token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Sign out user
        
        Args:
            access_token: JWT access token
            
        Returns:
            Tuple of (success: bool, result: Dict)
        """
        try:
            # Set the session token
            self.supabase.auth.set_session(access_token, refresh_token="")
            
            # Sign out
            self.supabase.auth.sign_out()
            
            logger.info("User signed out successfully")
            return True, {"message": "Signed out successfully"}
            
        except Exception as e:
            logger.error(f"Error signing out user: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def reset_password(self, email: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Send password reset email
        
        Args:
            email: User's email address
            
        Returns:
            Tuple of (success: bool, result: Dict)
        """
        try:
            self.supabase.auth.reset_password_email(
                email,
                {
                    "redirect_to": f"{settings.site_url}/auth/reset-password"
                }
            )
            
            logger.info(f"Password reset email sent to: {email}")
            return True, {"message": "Password reset email sent"}
            
        except Exception as e:
            logger.error(f"Error sending password reset email to {email}: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def update_user(self, access_token: str, updates: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Update user profile
        
        Args:
            access_token: JWT access token
            updates: Dictionary of fields to update
            
        Returns:
            Tuple of (success: bool, result: Dict)
        """
        try:
            # Set the session token
            self.supabase.auth.set_session(access_token, refresh_token="")
            
            # Update user
            response = self.supabase.auth.update({
                "data": updates
            })
            
            if response.user:
                logger.info(f"User updated successfully: {response.user.email}")
                return True, {"user": response.user}
            else:
                return False, {"error": "Failed to update user"}
                
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            return False, {"error": str(e)}
    
    # PUBLIC_INTERFACE
    async def verify_email(self, token: str, email: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify user email with token and ensure user meta is updated, and a fresh
        preliminary session is available for subsequent 2FA.

        Args:
            token: Email verification token
            email: User's email address

        Returns:
            Tuple of (success: bool, result: Dict)
            On success, result contains:
            {
                "user": <user_object>,
                "session": <session_or_none>,
                "email_verified": True
            }
        """
        try:
            # Verify email via OTP
            response = self.supabase.auth.verify_otp({
                "email": email,
                "token": token,
                "type": "email"
            })

            if not response or not response.user:
                return False, {"error": "Invalid or expired verification token"}

            user = response.user
            logger.info(f"Email verified via OTP for: {email}")

            # Ensure user metadata reflects email_verified = True
            try:
                # Some SDKs may already set email_confirmed_at, but we persist a meta flag for downstream logic
                meta_updates = {"email_verified": True}
                update_resp = self.admin_client.auth.admin.update_user_by_id(user.id, user_data={"user_metadata": meta_updates})
                if getattr(update_resp, "user", None):
                    user = update_resp.user  # refresh local user reference
                    logger.info(f"User metadata updated with email_verified=True for: {email}")
            except Exception as meta_err:
                logger.warning(f"Unable to update user metadata email_verified for {email}: {str(meta_err)}")

            # The Supabase verify_otp may or may not return a session. We return it through for the caller
            return True, {
                "user": user,
                "session": getattr(response, "session", None),
                "email_verified": True
            }

        except Exception as e:
            logger.error(f"Error verifying email for {email}: {str(e)}")
            return False, {"error": str(e)}


# Global service instance
supabase_service = SupabaseService()

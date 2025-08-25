from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging
from src.config.settings import settings

logger = logging.getLogger(__name__)


class JWTService:
    """Service for handling JWT token operations"""
    
    def __init__(self):
        """Initialize JWT service with settings"""
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.jwt_access_token_expire_minutes
    
    # PUBLIC_INTERFACE
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token
        
        Args:
            data: Data to encode in the token
            expires_delta: Custom expiration time
            
        Returns:
            JWT token string
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        try:
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            logger.info(f"Created access token for subject: {data.get('sub', 'unknown')}")
            return encoded_jwt
        except Exception as e:
            logger.error(f"Error creating access token: {str(e)}")
            raise
    
    # PUBLIC_INTERFACE
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token
        
        Args:
            token: JWT token to verify
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is expired
            exp = payload.get("exp")
            if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
                logger.warning("Token has expired")
                return None
            
            logger.info(f"Token verified successfully for subject: {payload.get('sub', 'unknown')}")
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error verifying token: {str(e)}")
            return None
    
    # PUBLIC_INTERFACE
    def get_token_expiry(self, token: str) -> Optional[datetime]:
        """
        Get the expiration time of a token
        
        Args:
            token: JWT token
            
        Returns:
            Expiration datetime or None if invalid
        """
        payload = self.verify_token(token)
        if payload and "exp" in payload:
            return datetime.utcfromtimestamp(payload["exp"])
        return None
    
    # PUBLIC_INTERFACE
    def is_token_expired(self, token: str) -> bool:
        """
        Check if a token is expired
        
        Args:
            token: JWT token
            
        Returns:
            True if expired, False otherwise
        """
        expiry = self.get_token_expiry(token)
        if expiry:
            return datetime.utcnow() > expiry
        return True
    
    # PUBLIC_INTERFACE
    def refresh_token_if_needed(self, token: str, refresh_threshold_minutes: int = 5) -> Optional[str]:
        """
        Refresh token if it's close to expiry
        
        Args:
            token: Current JWT token
            refresh_threshold_minutes: Minutes before expiry to refresh
            
        Returns:
            New token if refreshed, None if not needed or failed
        """
        payload = self.verify_token(token)
        if not payload:
            return None
        
        exp = payload.get("exp")
        if exp:
            expiry_time = datetime.utcfromtimestamp(exp)
            time_until_expiry = expiry_time - datetime.utcnow()
            
            if time_until_expiry <= timedelta(minutes=refresh_threshold_minutes):
                # Remove exp and iat from payload for new token
                payload.pop("exp", None)
                payload.pop("iat", None)
                
                try:
                    new_token = self.create_access_token(payload)
                    logger.info(f"Token refreshed for subject: {payload.get('sub', 'unknown')}")
                    return new_token
                except Exception as e:
                    logger.error(f"Error refreshing token: {str(e)}")
                    return None
        
        return None


# Global service instance
jwt_service = JWTService()

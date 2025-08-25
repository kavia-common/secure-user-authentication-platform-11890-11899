from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, Dict, Any
from datetime import datetime
import re


class UserSignUpRequest(BaseModel):
    """User registration request model"""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="User password (minimum 8 characters)")
    first_name: str = Field(..., min_length=1, max_length=50, description="User's first name")
    last_name: str = Field(..., min_length=1, max_length=50, description="User's last name")
    phone: Optional[str] = Field(None, description="User's phone number")
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserLoginRequest(BaseModel):
    """User login request model"""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User password")


class PasswordResetRequest(BaseModel):
    """Password reset request model"""
    email: EmailStr = Field(..., description="User's email address")


class PasswordResetConfirmRequest(BaseModel):
    """Password reset confirmation model"""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, description="New password")
    
    @validator('new_password')
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class TwoFactorRequest(BaseModel):
    """Two-factor authentication request model"""
    email: EmailStr = Field(..., description="User's email address")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")


class TwoFactorSendRequest(BaseModel):
    """Request to send 2FA OTP model"""
    email: EmailStr = Field(..., description="User's email address")


class EmailVerificationRequest(BaseModel):
    """Email verification request model"""
    token: str = Field(..., description="Email verification token")


class UserProfileUpdateRequest(BaseModel):
    """User profile update request model"""
    first_name: Optional[str] = Field(None, min_length=1, max_length=50, description="User's first name")
    last_name: Optional[str] = Field(None, min_length=1, max_length=50, description="User's last name")
    phone: Optional[str] = Field(None, description="User's phone number")


class UserResponse(BaseModel):
    """User response model"""
    id: str = Field(..., description="User's unique identifier")
    email: str = Field(..., description="User's email address")
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")
    phone: Optional[str] = Field(None, description="User's phone number")
    email_verified: bool = Field(..., description="Whether email is verified")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_sign_in_at: Optional[datetime] = Field(None, description="Last sign in timestamp")


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user: UserResponse = Field(..., description="User information")


class MessageResponse(BaseModel):
    """Generic message response model"""
    message: str = Field(..., description="Response message")
    success: bool = Field(..., description="Operation success status")


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    status_code: int = Field(..., description="HTTP status code")


class DashboardData(BaseModel):
    """Dashboard data response model"""
    user: UserResponse = Field(..., description="User information")
    session_info: Dict[str, Any] = Field(..., description="Session information")
    stats: Dict[str, Any] = Field(..., description="User statistics")

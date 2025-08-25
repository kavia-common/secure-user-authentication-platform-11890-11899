import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any
import logging
from datetime import datetime, timedelta
from src.config.settings import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Service for handling email operations including OTP sending"""
    
    def __init__(self):
        """Initialize email service with SMTP settings"""
        self.smtp_host = settings.email_smtp_host
        self.smtp_port = settings.email_smtp_port
        self.smtp_user = settings.email_smtp_user
        self.smtp_password = settings.email_smtp_password
        self.from_email = settings.email_from
        
        # In-memory OTP storage (in production, use Redis or database)
        self.otp_storage: Dict[str, Dict[str, Any]] = {}
    
    # PUBLIC_INTERFACE
    def generate_otp(self, length: int = 6) -> str:
        """
        Generate a random OTP code
        
        Args:
            length: Length of the OTP code
            
        Returns:
            Random OTP string
        """
        return ''.join(random.choices(string.digits, k=length))
    
    # PUBLIC_INTERFACE
    async def send_otp_email(self, email: str, purpose: str = "2fa") -> tuple[bool, str]:
        """
        Send OTP via email
        
        Args:
            email: Recipient email address
            purpose: Purpose of OTP (2fa, verification, etc.)
            
        Returns:
            Tuple of (success: bool, otp_code: str)
        """
        try:
            # Generate OTP
            otp_code = self.generate_otp()
            
            # Store OTP with expiration
            self.otp_storage[email] = {
                "code": otp_code,
                "purpose": purpose,
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(minutes=10),
                "attempts": 0
            }
            
            # Create email content
            subject = "Your Verification Code"
            if purpose == "2fa":
                body = f"""
                <html>
                <body>
                    <h2>Two-Factor Authentication</h2>
                    <p>Your verification code is: <strong>{otp_code}</strong></p>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                </body>
                </html>
                """
            else:
                body = f"""
                <html>
                <body>
                    <h2>Email Verification</h2>
                    <p>Your verification code is: <strong>{otp_code}</strong></p>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                </body>
                </html>
                """
            
            # Send email
            success = await self._send_email(email, subject, body)
            
            if success:
                logger.info(f"OTP sent successfully to {email} for {purpose}")
                return True, otp_code
            else:
                logger.error(f"Failed to send OTP to {email}")
                return False, ""
                
        except Exception as e:
            logger.error(f"Error sending OTP to {email}: {str(e)}")
            return False, ""
    
    # PUBLIC_INTERFACE
    def verify_otp(self, email: str, otp_code: str, purpose: str = "2fa") -> bool:
        """
        Verify OTP code
        
        Args:
            email: Email address
            otp_code: OTP code to verify
            purpose: Purpose of OTP
            
        Returns:
            True if OTP is valid, False otherwise
        """
        try:
            stored_otp = self.otp_storage.get(email)
            
            if not stored_otp:
                logger.warning(f"No OTP found for email: {email}")
                return False
            
            # Check if OTP has expired
            if datetime.utcnow() > stored_otp["expires_at"]:
                logger.warning(f"OTP expired for email: {email}")
                del self.otp_storage[email]
                return False
            
            # Check if too many attempts
            if stored_otp["attempts"] >= 3:
                logger.warning(f"Too many OTP attempts for email: {email}")
                del self.otp_storage[email]
                return False
            
            # Increment attempts
            stored_otp["attempts"] += 1
            
            # Check if OTP matches and purpose is correct
            if stored_otp["code"] == otp_code and stored_otp["purpose"] == purpose:
                logger.info(f"OTP verified successfully for {email}")
                del self.otp_storage[email]  # Remove OTP after successful verification
                return True
            else:
                logger.warning(f"Invalid OTP for email: {email}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying OTP for {email}: {str(e)}")
            return False
    
    # PUBLIC_INTERFACE
    async def send_welcome_email(self, email: str, first_name: str) -> bool:
        """
        Send welcome email to new user
        
        Args:
            email: Recipient email address
            first_name: User's first name
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            subject = "Welcome to Our Platform!"
            body = f"""
            <html>
            <body>
                <h2>Welcome, {first_name}!</h2>
                <p>Thank you for signing up for our platform.</p>
                <p>Please verify your email address to complete your registration.</p>
                <p>If you have any questions, feel free to contact our support team.</p>
                <br>
                <p>Best regards,<br>The Team</p>
            </body>
            </html>
            """
            
            success = await self._send_email(email, subject, body)
            
            if success:
                logger.info(f"Welcome email sent to {email}")
            else:
                logger.error(f"Failed to send welcome email to {email}")
                
            return success
            
        except Exception as e:
            logger.error(f"Error sending welcome email to {email}: {str(e)}")
            return False
    
    async def _send_email(self, to_email: str, subject: str, body: str) -> bool:
        """
        Send email using SMTP
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            body: Email body (HTML)
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = to_email
            
            # Add HTML body
            html_part = MIMEText(body, "html")
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False


# Global service instance
email_service = EmailService()

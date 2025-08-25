from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
import logging
from typing import Dict, Any
from datetime import datetime, timedelta

from src.models.auth_models import DashboardData, UserResponse
from src.services.session_service import session_service
from src.middleware.auth_middleware import get_current_2fa_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/",
    response_model=DashboardData,
    summary="Get Dashboard Data",
    description="Get comprehensive dashboard data for authenticated user"
)
async def get_dashboard_data(current_user: Dict[str, Any] = Depends(get_current_2fa_user)) -> JSONResponse:
    """
    Get comprehensive dashboard data for authenticated user
    
    Retrieves user profile information, session details, and usage statistics
    for display on the protected dashboard. Requires completed 2FA.
    """
    try:
        user_id = current_user["user_id"]
        user_email = current_user["email"]
        session_id = current_user["session_id"]
        
        logger.info(f"Dashboard data request for: {user_email}")
        
        # Get user profile information
        token_payload = current_user.get("token_payload", {})
        
        user_response = UserResponse(
            id=user_id,
            email=user_email,
            first_name=token_payload.get("first_name"),
            last_name=token_payload.get("last_name"),
            phone=token_payload.get("phone"),
            email_verified=token_payload.get("email_verified", False),
            created_at=token_payload.get("created_at"),
            last_sign_in_at=token_payload.get("last_sign_in_at")
        )
        
        # Get session information
        session_info = session_service.get_session_info(session_id)
        if not session_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session"
            )
        
        # Calculate session statistics
        session_duration = datetime.utcnow() - session_info["created_at"]
        time_until_expiry = session_info["expires_at"] - datetime.utcnow()
        
        session_data = {
            "session_id": session_id,
            "created_at": session_info["created_at"],
            "last_activity": session_info["last_activity"],
            "expires_at": session_info["expires_at"],
            "session_duration_minutes": int(session_duration.total_seconds() / 60),
            "time_until_expiry_minutes": max(0, int(time_until_expiry.total_seconds() / 60)),
            "is_active": session_info["is_active"]
        }
        
        # Get user statistics
        total_sessions = len([
            s for s in session_service.active_sessions.values()
            if s["user_id"] == user_id
        ])
        
        # Calculate account age
        account_created = token_payload.get("created_at")
        account_age_days = 0
        if account_created:
            if isinstance(account_created, str):
                try:
                    created_date = datetime.fromisoformat(account_created.replace('Z', '+00:00'))
                    account_age_days = (datetime.utcnow() - created_date.replace(tzinfo=None)).days
                except:
                    pass
            elif isinstance(account_created, datetime):
                account_age_days = (datetime.utcnow() - account_created).days
        
        stats = {
            "total_active_sessions": total_sessions,
            "account_age_days": account_age_days,
            "email_verified": token_payload.get("email_verified", False),
            "2fa_enabled": True,  # 2FA is mandatory in our system
            "last_login": session_info["created_at"],
            "security_score": calculate_security_score(token_payload, total_sessions)
        }
        
        dashboard_data = DashboardData(
            user=user_response,
            session_info=session_data,
            stats=stats
        )
        
        logger.info(f"Dashboard data retrieved successfully for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=dashboard_data.dict()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving dashboard data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while loading dashboard data"
        )


@router.get(
    "/activity",
    summary="Get User Activity",
    description="Get recent user activity and session history"
)
async def get_user_activity(current_user: Dict[str, Any] = Depends(get_current_2fa_user)) -> JSONResponse:
    """
    Get recent user activity and session history
    
    Retrieves recent activity logs and session history for the authenticated user.
    Requires completed 2FA.
    """
    try:
        user_id = current_user["user_id"]
        user_email = current_user["email"]
        
        logger.info(f"Activity request for: {user_email}")
        
        # Get recent sessions for the user
        recent_sessions = []
        current_time = datetime.utcnow()
        
        for session_id, session_data in session_service.active_sessions.items():
            if session_data["user_id"] == user_id:
                # Include sessions from the last 30 days
                if (current_time - session_data["created_at"]).days <= 30:
                    session_activity = {
                        "session_id": session_id,
                        "created_at": session_data["created_at"],
                        "last_activity": session_data["last_activity"],
                        "is_active": session_data["is_active"],
                        "duration_minutes": int((
                            session_data["last_activity"] - session_data["created_at"]
                        ).total_seconds() / 60) if session_data["is_active"] else None
                    }
                    recent_sessions.append(session_activity)
        
        # Sort by creation time (most recent first)
        recent_sessions.sort(key=lambda x: x["created_at"], reverse=True)
        
        # Generate activity summary
        today = current_time.date()
        this_week = current_time - timedelta(days=7)
        this_month = current_time - timedelta(days=30)
        
        activity_summary = {
            "sessions_today": len([
                s for s in recent_sessions
                if s["created_at"].date() == today
            ]),
            "sessions_this_week": len([
                s for s in recent_sessions
                if s["created_at"] >= this_week
            ]),
            "sessions_this_month": len([
                s for s in recent_sessions
                if s["created_at"] >= this_month
            ]),
            "total_active_sessions": len([
                s for s in recent_sessions
                if s["is_active"]
            ])
        }
        
        logger.info(f"Activity data retrieved successfully for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "recent_sessions": recent_sessions[:10],  # Limit to 10 most recent
                "activity_summary": activity_summary,
                "total_sessions": len(recent_sessions)
            }
        )
        
    except Exception as e:
        logger.error(f"Error retrieving activity data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while loading activity data"
        )


@router.get(
    "/security",
    summary="Get Security Overview",
    description="Get security status and recommendations"
)
async def get_security_overview(current_user: Dict[str, Any] = Depends(get_current_2fa_user)) -> JSONResponse:
    """
    Get security status and recommendations
    
    Provides an overview of the user's account security status,
    including verification status, 2FA status, and security recommendations.
    Requires completed 2FA.
    """
    try:
        user_email = current_user["email"]
        user_id = current_user["user_id"]
        
        logger.info(f"Security overview request for: {user_email}")
        
        token_payload = current_user.get("token_payload", {})
        
        # Calculate security metrics
        email_verified = token_payload.get("email_verified", False)
        two_fa_enabled = True  # Always true in our system
        has_strong_password = True  # Assume true since we enforce strong passwords
        
        # Count active sessions
        active_sessions = len([
            s for s in session_service.active_sessions.values()
            if s["user_id"] == user_id and s["is_active"]
        ])
        
        # Calculate security score
        security_score = calculate_security_score(token_payload, active_sessions)
        
        # Generate security recommendations
        recommendations = []
        
        if not email_verified:
            recommendations.append({
                "type": "warning",
                "title": "Verify Your Email",
                "description": "Please verify your email address to secure your account."
            })
        
        if active_sessions > 5:
            recommendations.append({
                "type": "info",
                "title": "Multiple Active Sessions",
                "description": f"You have {active_sessions} active sessions. Consider revoking unused sessions."
            })
        
        if security_score >= 90:
            recommendations.append({
                "type": "success",
                "title": "Excellent Security",
                "description": "Your account security is excellent. Keep up the good practices!"
            })
        elif security_score >= 70:
            recommendations.append({
                "type": "info",
                "title": "Good Security",
                "description": "Your account security is good. Consider the recommendations above to improve it further."
            })
        else:
            recommendations.append({
                "type": "warning",
                "title": "Security Needs Improvement",
                "description": "Please review and implement the security recommendations above."
            })
        
        security_overview = {
            "security_score": security_score,
            "email_verified": email_verified,
            "2fa_enabled": two_fa_enabled,
            "strong_password": has_strong_password,
            "active_sessions_count": active_sessions,
            "last_password_change": None,  # Would need to track this
            "recommendations": recommendations
        }
        
        logger.info(f"Security overview retrieved successfully for: {user_email}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=security_overview
        )
        
    except Exception as e:
        logger.error(f"Error retrieving security overview: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while loading security overview"
        )


def calculate_security_score(token_payload: Dict[str, Any], active_sessions: int) -> int:
    """
    Calculate a security score based on various factors
    
    Args:
        token_payload: User token payload
        active_sessions: Number of active sessions
        
    Returns:
        Security score (0-100)
    """
    score = 0
    
    # Email verification (30 points)
    if token_payload.get("email_verified", False):
        score += 30
    
    # 2FA enabled (40 points) - always true in our system
    score += 40
    
    # Strong password (20 points) - assumed true since we enforce it
    score += 20
    
    # Session management (10 points)
    if active_sessions <= 3:
        score += 10
    elif active_sessions <= 5:
        score += 5
    
    return min(score, 100)

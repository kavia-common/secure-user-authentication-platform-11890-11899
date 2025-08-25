from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
import logging
import time
from contextlib import asynccontextmanager

from src.api.routes import (
    auth_router,
    two_factor_router,
    user_router,
    dashboard_router
)
from src.services.session_service import session_service
from src.config.settings import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting Supabase Auth Backend")
    yield
    logger.info("Shutting down Supabase Auth Backend")


# FastAPI app configuration with comprehensive metadata
app = FastAPI(
    title="Supabase Authentication Backend",
    description="""
    A comprehensive authentication backend powered by Supabase with advanced security features.
    
    ## Features
    
    * **User Registration & Login** - Secure user account creation and authentication
    * **Email Verification** - Mandatory email verification for account activation
    * **Two-Factor Authentication** - Email-based OTP 2FA for enhanced security
    * **Session Management** - JWT-based sessions with automatic timeout and activity tracking
    * **Password Reset** - Secure password reset flow via email
    * **User Profile Management** - CRUD operations for user profile data
    * **Protected Dashboard** - Secure dashboard with user statistics and activity
    * **Security Monitoring** - Real-time security status and recommendations
    
    ## Authentication Flow
    
    1. **Sign Up** - Create account with email/password and profile information
    2. **Email Verification** - Verify email address via token sent to email
    3. **Login** - Authenticate with email/password (requires verified email)
    4. **2FA** - Complete mandatory 2FA via email OTP
    5. **Access Protected Resources** - Use JWT token for authenticated requests
    
    ## Security Features
    
    * Strong password requirements with validation
    * Email verification mandatory before login
    * Two-factor authentication required for all users
    * Session timeout after 30 minutes of inactivity
    * Multiple session management and monitoring
    * Comprehensive security scoring and recommendations
    
    ## API Usage
    
    ### Authentication Required
    Most endpoints require authentication via Bearer token in the Authorization header:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
    
    ### 2FA Required
    Endpoints marked with 🔐 require completed two-factor authentication.
    
    ### WebSocket Support
    Real-time session monitoring and security alerts available via WebSocket connections.
    Connect to `/ws` endpoint with valid authentication token.
    """,
    version="1.0.0",
    contact={
        "name": "API Support",
        "email": "support@yourapp.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "User authentication operations including signup, login, logout, and password reset"
        },
        {
            "name": "Two-Factor Authentication", 
            "description": "2FA operations for enhanced security including OTP sending and verification"
        },
        {
            "name": "User Profile",
            "description": "User profile management and account operations"
        },
        {
            "name": "Dashboard",
            "description": "Protected dashboard data and user statistics"
        }
    ],
    lifespan=lifespan,
    debug=settings.debug
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.site_url,
        "http://localhost:3000",
        "http://localhost:3001",
        "https://localhost:3000",
        "https://localhost:3001"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add request processing time to response headers"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Session cleanup middleware
@app.middleware("http")
async def session_cleanup_middleware(request: Request, call_next):
    """Cleanup expired sessions on each request"""
    try:
        # Cleanup expired sessions periodically
        if hasattr(request.state, 'cleanup_counter'):
            request.state.cleanup_counter += 1
        else:
            request.state.cleanup_counter = 1
        
        # Cleanup every 100 requests to avoid performance impact
        if request.state.cleanup_counter % 100 == 0:
            cleaned_sessions = session_service.cleanup_expired_sessions()
            if cleaned_sessions > 0:
                logger.info(f"Cleaned up {cleaned_sessions} expired sessions")
        
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error(f"Error in session cleanup middleware: {str(e)}")
        response = await call_next(request)
        return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors"""
    logger.error(f"Unhandled exception on {request.method} {request.url}: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred. Please try again later.",
            "status_code": 500
        }
    )


# Include all routers
app.include_router(auth_router)
app.include_router(two_factor_router)
app.include_router(user_router)
app.include_router(dashboard_router)


# Health check endpoint
@app.get(
    "/",
    tags=["Health"],
    summary="Health Check",
    description="Check if the API is running and healthy"
)
async def health_check():
    """
    Health check endpoint
    
    Returns the health status of the API and basic system information.
    """
    return {
        "status": "healthy",
        "message": "Supabase Authentication Backend is running",
        "version": "1.0.0",
        "timestamp": time.time()
    }


# API status endpoint
@app.get(
    "/status",
    tags=["Health"],
    summary="API Status",
    description="Get detailed API status and statistics"
)
async def api_status():
    """
    Get detailed API status and statistics
    
    Returns comprehensive status information including active sessions and system health.
    """
    active_sessions_count = len([
        s for s in session_service.active_sessions.values()
        if s["is_active"]
    ])
    
    return {
        "status": "operational",
        "version": "1.0.0",
        "environment": "development" if settings.debug else "production",
        "active_sessions": active_sessions_count,
        "features": {
            "authentication": True,
            "two_factor_auth": True,
            "email_verification": True,
            "session_management": True,
            "user_profiles": True,
            "dashboard": True
        },
        "timestamp": time.time()
    }


# WebSocket endpoint for real-time notifications
@app.websocket("/ws")
async def websocket_endpoint(websocket):
    """
    WebSocket endpoint for real-time session monitoring and security alerts
    
    Provides real-time updates for:
    - Session expiry warnings
    - Security alerts
    - Account activity notifications
    
    Authentication required via query parameter: ?token=<jwt-token>
    """
    from fastapi import WebSocketDisconnect
    from src.services.jwt_service import jwt_service
    
    # Get token from query parameters
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return
    
    # Verify token
    token_payload = jwt_service.verify_token(token)
    if not token_payload:
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    user_email = token_payload.get("email")
    logger.info(f"WebSocket connection established for: {user_email}")
    
    await websocket.accept()
    
    try:
        while True:
            # Keep connection alive and send periodic updates
            await websocket.receive_text()
            
            # Send session status update
            session_id = token_payload.get("session_id")
            if session_id:
                session_info = session_service.get_session_info(session_id)
                if session_info:
                    time_until_expiry = session_info["time_until_expiry"].total_seconds()
                    
                    if time_until_expiry < 300:  # 5 minutes warning
                        await websocket.send_json({
                            "type": "session_warning",
                            "message": f"Session expires in {int(time_until_expiry/60)} minutes",
                            "time_until_expiry": time_until_expiry
                        })
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for: {user_email}")
    except Exception as e:
        logger.error(f"WebSocket error for {user_email}: {str(e)}")
        await websocket.close(code=4000, reason="Internal error")


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema with additional metadata"""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token obtained from login endpoint"
        }
    }
    
    # Add security to protected endpoints
    for path_item in openapi_schema["paths"].values():
        for operation in path_item.values():
            if isinstance(operation, dict) and "tags" in operation:
                # Add security requirement to all endpoints except health checks
                if "Health" not in operation["tags"]:
                    operation["security"] = [{"BearerAuth": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info("Supabase Auth Backend started successfully")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Site URL: {settings.site_url}")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info("Supabase Auth Backend shutting down")
    
    # Cleanup all sessions
    total_sessions = len(session_service.active_sessions)
    if total_sessions > 0:
        session_service.active_sessions.clear()
        logger.info(f"Cleaned up {total_sessions} active sessions")

from .auth import router as auth_router
from .two_factor import router as two_factor_router
from .user import router as user_router
from .dashboard import router as dashboard_router

__all__ = [
    "auth_router",
    "two_factor_router",
    "user_router",
    "dashboard_router"
]

# Supabase Authentication Backend

A comprehensive FastAPI backend for user authentication powered by Supabase with advanced security features including mandatory 2FA, session management, and real-time monitoring.

## Features

### 🔐 Authentication & Security
- **User Registration & Login** - Secure account creation and authentication
- **Email Verification** - Mandatory email verification for account activation
- **Two-Factor Authentication** - Email-based OTP 2FA for enhanced security
- **Strong Password Policy** - Enforced password strength requirements
- **Session Management** - JWT-based sessions with automatic timeout
- **Password Reset** - Secure password reset flow via email

### 👤 User Management
- **User Profile Management** - CRUD operations for user profile data
- **Account Management** - Account deletion and session management
- **Multiple Sessions** - Support for multiple concurrent sessions

### 📊 Dashboard & Monitoring
- **Protected Dashboard** - Secure dashboard with user statistics
- **Activity Tracking** - User activity and session history
- **Security Monitoring** - Real-time security status and recommendations
- **Session Analytics** - Comprehensive session statistics

### 🔌 API & Integration
- **RESTful API** - Well-documented REST endpoints
- **WebSocket Support** - Real-time notifications and session monitoring
- **OpenAPI/Swagger** - Complete API documentation
- **CORS Support** - Configurable cross-origin resource sharing

## Quick Start

### Prerequisites
- Python 3.8+
- Supabase account and project
- SMTP email service (Gmail, SendGrid, etc.)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd supabase_auth_backend
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run the application**
   ```bash
   PYTHONPATH=. uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

5. **Access the API**
   - API: http://localhost:8000
   - Documentation: http://localhost:8000/docs
   - OpenAPI Spec: http://localhost:8000/openapi.json

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email Configuration
EMAIL_FROM=noreply@yourapp.com
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USER=your-email@gmail.com
EMAIL_SMTP_PASSWORD=your-app-password

# Application Configuration
SITE_URL=http://localhost:3000
BACKEND_URL=http://localhost:8000
DEBUG=True
```

### Supabase Setup

Refer to `assets/supabase.md` for detailed Supabase configuration including:
- Database schema
- Authentication settings
- Email templates
- Security policies

## API Endpoints

### Authentication
- `POST /auth/signup` - Register new user
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset password
- `GET /auth/verify-email` - Verify email address

### Two-Factor Authentication
- `POST /2fa/send-otp` - Send OTP code
- `POST /2fa/verify-otp` - Verify OTP and complete 2FA
- `POST /2fa/resend-otp` - Resend OTP code
- `GET /2fa/status` - Check 2FA status

### User Profile
- `GET /user/profile` - Get user profile
- `PUT /user/profile` - Update user profile
- `DELETE /user/account` - Delete user account
- `GET /user/sessions` - Get active sessions
- `DELETE /user/sessions/{id}` - Revoke specific session

### Dashboard
- `GET /dashboard/` - Get dashboard data
- `GET /dashboard/activity` - Get user activity
- `GET /dashboard/security` - Get security overview

### Health & Status
- `GET /` - Health check
- `GET /status` - API status and statistics

### WebSocket
- `WS /ws?token=<jwt-token>` - Real-time notifications

## Authentication Flow

1. **User Registration**
   ```bash
   POST /auth/signup
   {
     "email": "user@example.com",
     "password": "SecurePass123!",
     "first_name": "John",
     "last_name": "Doe"
   }
   ```

2. **Email Verification**
   - User receives email with verification link
   - Click link or use verification endpoint

3. **User Login**
   ```bash
   POST /auth/login
   {
     "email": "user@example.com",
     "password": "SecurePass123!"
   }
   ```

4. **Two-Factor Authentication**
   ```bash
   # Send OTP
   POST /2fa/send-otp
   {
     "email": "user@example.com"
   }
   
   # Verify OTP
   POST /2fa/verify-otp
   {
     "email": "user@example.com",
     "otp_code": "123456"
   }
   ```

5. **Access Protected Resources**
   ```bash
   GET /user/profile
   Authorization: Bearer <jwt-token>
   ```

## Security Features

### Password Policy
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

### Session Management
- JWT-based authentication
- 30-minute session timeout
- Automatic session cleanup
- Multiple session support
- Session activity tracking

### Two-Factor Authentication
- Mandatory for all users
- Email-based OTP delivery
- 10-minute OTP expiration
- Maximum 3 verification attempts
- Automatic OTP cleanup

### Security Monitoring
- Real-time security scoring
- Activity tracking
- Session monitoring
- Security recommendations
- Threat detection

## Development

### Project Structure
```
src/
├── api/
│   ├── main.py              # FastAPI application
│   └── routes/              # API route modules
│       ├── auth.py          # Authentication routes
│       ├── two_factor.py    # 2FA routes
│       ├── user.py          # User management routes
│       └── dashboard.py     # Dashboard routes
├── config/
│   └── settings.py          # Configuration management
├── models/
│   └── auth_models.py       # Pydantic models
├── services/
│   ├── supabase_service.py  # Supabase integration
│   ├── jwt_service.py       # JWT token handling
│   ├── email_service.py     # Email and OTP service
│   └── session_service.py   # Session management
└── middleware/
    └── auth_middleware.py   # Authentication middleware
```

### Code Quality
- Type hints throughout
- Comprehensive documentation
- Error handling and logging
- Input validation with Pydantic
- Security best practices

### Testing
```bash
# Run linting
flake8 src/ --max-line-length=120

# Run tests (when implemented)
pytest tests/
```

## Deployment

### Production Considerations
- Use environment-specific configuration
- Enable HTTPS/TLS
- Configure proper CORS origins
- Set up monitoring and logging
- Use Redis for session storage
- Configure email service properly
- Set up database backups
- Enable rate limiting

### Docker Deployment
```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## API Documentation

The API is fully documented with OpenAPI/Swagger:
- Interactive docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI spec: http://localhost:8000/openapi.json

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run linting and tests
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the API documentation
- Review the Supabase configuration guide
- Open an issue on GitHub

## Changelog

### v1.0.0
- Initial release
- Complete authentication system
- Mandatory 2FA implementation
- Session management
- User profile management
- Dashboard with analytics
- Real-time WebSocket support
- Comprehensive API documentation

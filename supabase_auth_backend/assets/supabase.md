# Supabase Configuration for Authentication Backend

This document outlines the Supabase configuration required for the authentication backend.

Note on environment and CORS:
- Backend uses SITE_URL (frontend public URL) and BACKEND_URL (public backend URL). Ensure these are set in .env.
- FastAPI CORS is configured to allow http://localhost:3000 and SITE_URL. Adjust in production accordingly.
- Frontend should use its SITE_URL env for Supabase emailRedirectTo when applicable.

Example (frontend):
```js
supabase.auth.signInWithOtp({
  email,
  options: { emailRedirectTo: `${import.meta.env.VITE_SITE_URL}/auth/callback` }
});
```

## Required Supabase Configuration

### 1. Project Setup
- Create a new Supabase project or use existing one
- Note down the project URL and API keys
- Enable authentication in the Supabase dashboard

### 2. Authentication Settings

#### Email Configuration
```sql
-- Enable email authentication
UPDATE auth.config SET 
  site_url = 'http://localhost:3000',
  email_confirm_url = 'http://localhost:3000/auth/verify-email',
  email_change_confirm_url = 'http://localhost:3000/auth/verify-email-change',
  password_reset_url = 'http://localhost:3000/auth/reset-password';
```

#### Security Settings
- Enable email confirmation required
- Set password minimum length to 8 characters
- Enable password strength requirements
- Configure session timeout to 30 minutes

### 3. Database Schema

#### User Profiles Table
```sql
-- Create user profiles table for extended user data
CREATE TABLE public.user_profiles (
  id UUID REFERENCES auth.users(id) PRIMARY KEY,
  first_name TEXT,
  last_name TEXT,
  phone TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS (Row Level Security)
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY "Users can view own profile" ON public.user_profiles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON public.user_profiles
  FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON public.user_profiles
  FOR INSERT WITH CHECK (auth.uid() = id);
```

#### User Activity Log Table
```sql
-- Create activity log table for tracking user actions
CREATE TABLE public.user_activity (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id),
  action TEXT NOT NULL,
  details JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE public.user_activity ENABLE ROW LEVEL SECURITY;

-- Create policy
CREATE POLICY "Users can view own activity" ON public.user_activity
  FOR SELECT USING (auth.uid() = user_id);
```

### 4. Database Functions

#### Function to handle new user registration
```sql
-- Function to create user profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.user_profiles (id, first_name, last_name, phone)
  VALUES (
    NEW.id,
    NEW.raw_user_meta_data->>'first_name',
    NEW.raw_user_meta_data->>'last_name',
    NEW.raw_user_meta_data->>'phone'
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for new user signup
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
```

#### Function to update profile timestamp
```sql
-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for profile updates
CREATE TRIGGER update_user_profiles_updated_at
  BEFORE UPDATE ON public.user_profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
```

### 5. Email Templates

#### Confirmation Email Template
```html
<!DOCTYPE html>
<html>
<head>
  <title>Confirm Your Email</title>
</head>
<body>
  <h2>Welcome to Our Platform!</h2>
  <p>Hi {{ .Name }},</p>
  <p>Thank you for signing up! Please confirm your email address by clicking the link below:</p>
  <a href="{{ .ConfirmationURL }}" 
     style="background-color: #2563EB; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
    Confirm Email Address
  </a>
  <p>If you didn't create an account, you can safely ignore this email.</p>
  <p>This link will expire in 24 hours.</p>
</body>
</html>
```

#### Password Reset Email Template
```html
<!DOCTYPE html>
<html>
<head>
  <title>Reset Your Password</title>
</head>
<body>
  <h2>Password Reset Request</h2>
  <p>Hi there,</p>
  <p>We received a request to reset your password. Click the link below to set a new password:</p>
  <a href="{{ .ConfirmationURL }}" 
     style="background-color: #DC2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
    Reset Password
  </a>
  <p>If you didn't request this password reset, you can safely ignore this email.</p>
  <p>This link will expire in 1 hour.</p>
</body>
</html>
```

### 6. Environment Variables Required

```bash
# Supabase Configuration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-anon-key-here
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key-here
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email Configuration (for OTP)
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

### 7. API Configuration

#### Rate Limiting
Configure rate limiting in Supabase for:
- Login attempts: 5 per minute per IP
- Signup attempts: 3 per minute per IP
- Password reset: 1 per minute per email
- OTP requests: 3 per 10 minutes per email

#### CORS Settings
Configure allowed origins in Supabase dashboard:
- http://localhost:3000 (development frontend)
- https://yourapp.com (production frontend)

### 8. Security Considerations

1. **API Keys**: Never expose service role key in client-side code
2. **RLS**: Always enable Row Level Security on user data tables
3. **Email Verification**: Require email confirmation before allowing login
4. **Password Policy**: Enforce strong password requirements
5. **Session Management**: Implement proper session timeout and cleanup
6. **2FA**: Mandatory two-factor authentication via email OTP
7. **Audit Logging**: Track all authentication and user actions

### 9. Testing Configuration

For testing environments:
- Use separate Supabase project
- Configure test email templates
- Set shorter token expiration times
- Enable detailed logging

### 10. Production Checklist

- [ ] Enable email confirmation required
- [ ] Configure custom SMTP settings
- [ ] Set up proper error monitoring
- [ ] Configure rate limiting
- [ ] Enable audit logging
- [ ] Set up database backups
- [ ] Configure SSL/TLS properly
- [ ] Review and test all security policies
- [ ] Set up monitoring and alerts
- [ ] Configure proper CORS origins

## Integration Notes

The backend automatically handles:
- User registration with profile creation
- Email verification workflow
- Password reset functionality
- Session management with JWT tokens
- 2FA via email OTP
- User profile CRUD operations
- Security monitoring and recommendations

All Supabase interactions are handled through the SupabaseService class in the backend, which provides a clean interface for authentication operations while maintaining security best practices.

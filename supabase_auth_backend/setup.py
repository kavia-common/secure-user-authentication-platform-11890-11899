#!/usr/bin/env python3
"""
Setup script for Supabase Authentication Backend
This script helps set up the development environment
"""

import os
import sys
import subprocess
import secrets
import string


def generate_secret_key(length=64):
    """Generate a secure random secret key"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")


def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        sys.exit(1)


def setup_env_file():
    """Set up environment file with generated secrets"""
    if os.path.exists(".env"):
        print("⚠️  .env file already exists")
        response = input("Do you want to regenerate it? (y/N): ")
        if response.lower() != 'y':
            return
    
    print("🔧 Setting up .env file...")
    
    # Generate secure JWT secret
    jwt_secret = generate_secret_key()
    
    env_content = f"""# Supabase Configuration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-anon-key-here
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here

# JWT Configuration  
JWT_SECRET_KEY={jwt_secret}
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
"""
    
    with open(".env", "w") as f:
        f.write(env_content)
    
    print("✅ .env file created with secure JWT secret")
    print("📝 Please update the following in your .env file:")
    print("   - SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY")
    print("   - EMAIL_* configuration for your SMTP provider")


def validate_setup():
    """Validate that the setup is working"""
    print("🔍 Validating setup...")
    try:
        # Set PYTHONPATH
        env = os.environ.copy()
        env['PYTHONPATH'] = '.'
        
        result = subprocess.run(
            [sys.executable, "-c", "import src.api.main; print('✅ Setup validation successful')"],
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(result.stdout.strip())
            return True
        else:
            print("❌ Setup validation failed:")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Setup validation failed: {e}")
        return False


def main():
    """Main setup function"""
    print("🚀 Supabase Authentication Backend Setup")
    print("========================================")
    
    # Check Python version
    check_python_version()
    
    # Install dependencies
    install_dependencies()
    
    # Setup environment file
    setup_env_file()
    
    # Validate setup
    if validate_setup():
        print("\n🎉 Setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Update your .env file with Supabase and email credentials")
        print("2. Run: chmod +x deploy.sh && ./deploy.sh")
        print("3. Or run manually: PYTHONPATH=. uvicorn src.api.main:app --reload")
        print("\n📚 Documentation will be available at http://localhost:8000/docs")
    else:
        print("\n❌ Setup completed with warnings. Please check your configuration.")


if __name__ == "__main__":
    main()

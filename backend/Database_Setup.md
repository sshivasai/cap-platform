# CAP Platform Database Setup Guide

This guide covers the complete database setup for the CAP Platform authentication system.

## 🏗️ Architecture Overview

The CAP Platform uses a comprehensive multi-database architecture:

- **PostgreSQL**: Primary relational database for user accounts, organizations, sessions
- **MongoDB**: Document storage for conversations, knowledge base content
- **Qdrant**: Vector database for semantic search and embeddings
- **Redis**: Caching, session management, and message queuing

## 📋 Prerequisites

1. **Python 3.11+** with pip
2. **PostgreSQL 15+** running and accessible
3. **MongoDB 7+** (optional for auth system)
4. **Redis 7+** (optional for auth system)
5. **Required Python packages** (installed via requirements.txt)

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Navigate to backend directory
cd backend

# Copy environment template
cp .env.example .env

# Edit .env with your database credentials
nano .env
```

### 2. Required Environment Variables

```bash
# PostgreSQL Configuration
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=cap_user
POSTGRES_PASSWORD=cap_password
POSTGRES_DB=cap_platform

# Optional: MongoDB Configuration
MONGODB_URL=mongodb://cap_user:cap_password@localhost:27017/cap_platform

# Optional: Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Database Setup

```bash
# Make setup script executable
chmod +x setup_database.sh

# Run the setup script
./setup_database.sh
```

**OR** manually:

```bash
# Initialize and migrate database
python manage_db.py init

# Seed with test data (optional)
python manage_db.py seed
```

## 🗄️ Database Schema

### Core Tables

#### 1. Organizations (Multi-tenant)
```sql
organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    subscription_tier VARCHAR(50) DEFAULT 'free',
    credit_balance DECIMAL(10,2) DEFAULT 0.00,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
)
```

#### 2. Users (Comprehensive Authentication)
```sql
users (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) DEFAULT 'member',
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    -- Security fields
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    -- OAuth fields  
    google_id VARCHAR(255) UNIQUE,
    microsoft_id VARCHAR(255) UNIQUE,
    -- Audit fields
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
)
```

#### 3. User Sessions (JWT Management)
```sql
user_sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    access_token_jti VARCHAR(255) UNIQUE NOT NULL,
    refresh_token_jti VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
)
```

#### 4. OAuth Providers (Social Auth)
```sql
oauth_providers (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    provider VARCHAR(50) NOT NULL, -- google, microsoft, github
    provider_user_id VARCHAR(255) NOT NULL,
    access_token_encrypted TEXT,
    is_active BOOLEAN DEFAULT TRUE
)
```

#### 5. API Keys (Developer Access)
```sql
api_keys (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    permissions JSONB DEFAULT '{}',
    rate_limit_per_minute INTEGER DEFAULT 1000,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
)
```

#### 6. Authentication Audit Log
```sql
auth_audit_log (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    event_type VARCHAR(50) NOT NULL,
    event_details JSONB DEFAULT '{}',
    ip_address INET,
    success BOOLEAN DEFAULT TRUE,
    risk_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
)
```

#### 7. Security Settings
```sql
security_settings (
    id UUID PRIMARY KEY,
    organization_id UUID UNIQUE REFERENCES organizations(id),
    password_policy JSONB DEFAULT '{}',
    session_settings JSONB DEFAULT '{}',
    ip_whitelist JSONB DEFAULT '[]',
    api_security JSONB DEFAULT '{}'
)
```

## 🛠️ Database Management Commands

### Migration Commands

```bash
# Show current migration status
python manage_db.py current

# Run pending migrations
python manage_db.py migrate

# Create a new migration
python manage_db.py revision -m "Description of changes"

# Rollback one migration
python manage_db.py downgrade

# Show migration history
python manage_db.py history
```

### Development Commands

```bash
# Check database connection
python manage_db.py check

# Reset database (⚠️ DESTRUCTIVE - Development only)
python manage_db.py reset

# Seed with test data
python manage_db.py seed

# Validate migrations are current
python manage_db.py validate
```

## 🧪 Test Data

When seeding the database, the following test accounts are created:

| Role  | Email                    | Password   | Organization |
|-------|--------------------------|------------|--------------|
| Owner | admin@capplatform.dev    | admin123!  | Default Org  |
| Member| user@capplatform.dev     | user123!   | Default Org  |

## 🔒 Security Features

### Password Security
- **bcrypt hashing** with 12 salt rounds
- **Strength validation** with configurable policies
- **Breach detection** against common compromised passwords
- **Reset tokens** with time-limited expiration

### Account Security
- **Account lockout** after 5 failed login attempts
- **Email verification** required for activation
- **2FA support** with backup codes
- **Session management** with JWT token rotation

### Audit & Compliance
- **Complete audit trail** of all authentication events
- **Risk scoring** for security events
- **IP tracking** and geolocation
- **GDPR compliance** features

### Multi-tenant Security
- **Data isolation** between organizations
- **Role-based permissions** (Owner, Admin, Member, Viewer, Developer)
- **API key management** with rate limiting
- **Organization-level security policies**

## 🔧 Configuration

### Password Policy (Configurable per Organization)
```json
{
  "min_length": 8,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_special_chars": true,
  "max_age_days": 90,
  "prevent_reuse_count": 5
}
```

### Session Settings
```json
{
  "max_session_duration_hours": 24,
  "idle_timeout_minutes": 30,
  "require_2fa": false,
  "allow_concurrent_sessions": true,
  "max_concurrent_sessions": 5
}
```

## 📊 Performance Optimizations

### Indexes Created
- **Users**: email, organization_id, role, last_login, is_active
- **Sessions**: user_id, expires_at, JWT tokens
- **Audit Log**: user_id + created_at, event_type + created_at
- **Organizations**: slug, subscription_tier, domain

### Connection Pooling
- **Async Pool**: 20 base connections, 30 overflow
- **Sync Pool**: 10 base connections, 20 overflow
- **Connection recycling**: 1 hour intervals
- **Health checks**: Pre-ping enabled

## 🚨 Troubleshooting

### Common Issues

1. **Migration Fails**
   ```bash
   # Check current state
   python manage_db.py current
   
   # Validate database connection
   python manage_db.py check
   
   # Try manual upgrade
   python manage_db.py upgrade
   ```

2. **Connection Refused**
   - Verify PostgreSQL is running
   - Check credentials in .env file
   - Ensure database exists
   - Verify network connectivity

3. **Permission Denied**
   ```sql
   -- Grant permissions to user
   GRANT ALL PRIVILEGES ON DATABASE cap_platform TO cap_user;
   GRANT ALL ON SCHEMA public TO cap_user;
   ```

4. **Extension Not Found**
   ```sql
   -- Install required extensions
   CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
   CREATE EXTENSION IF NOT EXISTS "pgcrypto";
   ```

### Debug Mode

Set environment variable for detailed logging:
```bash
export DEBUG=true
export LOG_LEVEL=DEBUG
python manage_db.py check
```

## 🔄 Migration Best Practices

1. **Always backup** before running migrations in production
2. **Test migrations** in staging environment first
3. **Review generated SQL** before applying
4. **Use descriptive messages** for migration commits
5. **Avoid destructive operations** in production migrations

### Creating Safe Migrations

```bash
# Generate migration with review
python manage_db.py revision -m "Add user preferences column"

# Review the generated migration file
# Edit app/migrations/versions/xxx_add_user_preferences_column.py

# Test in development
python manage_db.py upgrade

# Verify changes
python manage_db.py current
```

## 📚 Next Steps

After successful database setup:

1. **Start FastAPI server**: `uvicorn app.main:app --reload`
2. **Implement authentication endpoints** in `app/api/v1/auth.py`
3. **Add business logic services** in `app/services/`
4. **Create Pydantic schemas** in `app/schemas/`
5. **Write tests** in `app/tests/`

## 🆘 Support

If you encounter issues:

1. Check this documentation first
2. Verify environment configuration
3. Review application logs
4. Test database connectivity
5. Validate migration state

For development questions, refer to the main project documentation.
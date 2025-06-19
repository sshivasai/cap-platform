# CAP Platform - Infrastructure Setup

This document provides complete instructions for setting up the CAP Platform infrastructure using Docker and Docker Compose.

## 🏗️ Architecture Overview

The CAP Platform uses a microservices architecture with the following components:

### Core Services
- **Frontend**: Next.js 14 application with TypeScript and Tailwind CSS
- **Backend**: FastAPI application with async Python
- **Nginx**: Reverse proxy and load balancer

### Databases
- **PostgreSQL**: Primary relational database for user data, organizations, agents
- **MongoDB**: Document storage for conversations, knowledge base, sessions
- **Qdrant**: Vector database for semantic search and embeddings
- **Redis**: Caching and pub/sub messaging

### Message Queue & Background Processing
- **RabbitMQ**: Primary message broker for task queues
- **Celery**: Distributed task queue system
- **Celery Beat**: Periodic task scheduler
- **Flower**: Celery monitoring dashboard

### Monitoring (Optional)
- **Prometheus**: Metrics collection
- **Grafana**: Metrics visualization
- **Alertmanager**: Alert management

## 📋 Prerequisites

### Required Software
- **Docker**: Version 20.10+ 
- **Docker Compose**: Version 2.0+
- **Make**: For using Makefile commands (optional)
- **Git**: For cloning the repository

### System Requirements
- **RAM**: Minimum 8GB (16GB recommended for full stack)
- **Storage**: At least 20GB free space
- **CPU**: 4+ cores recommended

## 🚀 Quick Start

### 1. Clone and Setup
```bash
# Clone the repository
git clone <repository-url> cap-platform
cd cap-platform

# Make scripts executable
chmod +x scripts/*.sh

# Copy environment files
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/.env.local.example frontend/.env.local

# Edit environment files with your configuration
nano .env
```

### 2. Start Infrastructure (Recommended Method)
```bash
# Using Make (recommended)
make setup
make start

# Or using scripts directly
./scripts/setup-dev.sh
./scripts/start-services.sh

# Or using Docker Compose directly
docker-compose up -d
```

### 3. Verify Installation
```bash
# Check service health
make health
# or
./scripts/health-check.sh

# View logs
make logs
# or
docker-compose logs -f

# Check running services
docker-compose ps
```

## 🔧 Configuration

### Environment Variables

#### Main Environment (.env)
```bash
# Core Settings
ENVIRONMENT=development
DEBUG=true

# Database URLs
DATABASE_URL=postgresql://cap_user:cap_password@postgres:5432/cap_platform
MONGODB_URL=mongodb://cap_user:cap_password@mongodb:27017/cap_conversations
QDRANT_URL=http://qdrant:6333
REDIS_URL=redis://redis:6379
RABBITMQ_URL=amqp://cap_user:cap_password@rabbitmq:5672/cap_vhost

# Security (CHANGE IN PRODUCTION!)
SECRET_KEY=your-super-secret-key-change-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-in-production

# External APIs
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key
```

#### Backend Environment (backend/.env)
```bash
# FastAPI Settings
API_V1_STR=/api/v1
PROJECT_NAME=CAP Platform
CORS_ORIGINS=["http://localhost:3000", "http://localhost:80"]

# Database Configuration
POSTGRES_SERVER=postgres
POSTGRES_USER=cap_user
POSTGRES_PASSWORD=cap_password
POSTGRES_DB=cap_platform
```

#### Frontend Environment (frontend/.env.local)
```bash
# API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000

# Feature Flags
NEXT_PUBLIC_ENABLE_ANALYTICS=true
NEXT_PUBLIC_ENABLE_VOICE=true
```

## 📊 Service URLs

After successful startup, access these services:

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | N/A |
| Backend API | http://localhost:8000 | N/A |
| API Docs | http://localhost:8000/docs | N/A |
| Flower (Celery) | http://localhost:5555 | N/A |
| RabbitMQ Management | http://localhost:15672 | cap_user / cap_password |
| Qdrant Dashboard | http://localhost:6333/dashboard | N/A |

## 🛠️ Development Commands

### Using Make (Recommended)
```bash
# Setup and start
make setup          # Initial setup
make start           # Start all services
make start-infra     # Start only infrastructure
make start-app       # Start only application services

# Management
make stop            # Stop all services
make restart         # Restart all services
make build           # Build all containers
make clean           # Clean up containers and volumes

# Development
make logs            # View all logs
make logs-backend    # View backend logs only
make logs-worker     # View worker logs only
make shell-backend   # Access backend shell
make shell-db        # Access PostgreSQL shell

# Testing and Quality
make test            # Run tests
make lint            # Run linters
make health          # Check service health
```

### Using Scripts Directly
```bash
# Service management
./scripts/start-services.sh    # Start all services
./scripts/stop-services.sh     # Stop all services
./scripts/health-check.sh      # Health check
./scripts/backup-databases.sh # Backup databases
./scripts/logs.sh [service]    # View logs

# Examples
./scripts/logs.sh backend      # Backend logs only
./scripts/logs.sh worker       # Worker logs only
./scripts/logs.sh all          # All logs
```

### Using Docker Compose Directly
```bash
# Basic operations
docker-compose up -d           # Start all services
docker-compose down            # Stop all services
docker-compose restart         # Restart all services
docker-compose ps              # Service status

# Individual services
docker-compose up -d postgres mongodb redis  # Start databases only
docker-compose restart backend               # Restart backend only
docker-compose logs -f backend              # Follow backend logs

# Build and clean
docker-compose build                         # Build all containers
docker-compose down -v                       # Stop and remove volumes
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Port Conflicts
```bash
# Check if ports are in use
netstat -tulpn | grep :5432  # PostgreSQL
netstat -tulpn | grep :27017 # MongoDB
netstat -tulpn | grep :6379  # Redis

# Solution: Change ports in docker-compose.yml or stop conflicting services
```

#### 2. Permission Issues
```bash
# Fix script permissions
chmod +x scripts/*.sh

# Fix Docker permissions (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

#### 3. Database Connection Issues
```bash
# Check database health
docker-compose exec postgres pg_isready -U cap_user -d cap_platform
docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')"
docker-compose exec redis redis-cli ping

# View database logs
docker-compose logs postgres
docker-compose logs mongodb
```

#### 4. Backend Not Starting
```bash
# Check backend logs
docker-compose logs backend

# Common issues:
# - Database not ready: Wait for databases to be healthy
# - Missing environment variables: Check .env files
# - Port conflicts: Change backend port in docker-compose.yml
```

#### 5. Celery Workers Not Processing Tasks
```bash
# Check worker status
docker-compose logs celery_worker

# Check RabbitMQ
docker-compose logs rabbitmq
curl -u cap_user:cap_password http://localhost:15672/api/queues

# Restart workers
docker-compose restart celery_worker celery_beat
```

### Debugging Commands

#### Check Service Status
```bash
# All services
docker-compose ps

# Specific service health
docker-compose exec backend curl http://localhost:8000/health
docker-compose exec qdrant curl http://localhost:6333/health
```

#### Access Service Shells
```bash
# Backend shell
docker-compose exec backend /bin/bash

# Database shells
docker-compose exec postgres psql -U cap_user -d cap_platform
docker-compose exec mongodb mongosh -u cap_user -p cap_password
docker-compose exec redis redis-cli
```

#### View Resource Usage
```bash
# Container resource usage
docker stats

# Disk usage
docker system df
docker volume ls
```

## 🏭 Production Deployment

### Using Production Compose File
```bash
# Build for production
make prod-build

# Start production environment
make prod-start

# Or directly
docker-compose -f docker-compose.prod.yml up -d
```

### Production Considerations

#### Security
- [ ] Change all default passwords
- [ ] Use strong secret keys
- [ ] Enable SSL/TLS
- [ ] Configure firewall rules
- [ ] Use secrets management

#### Performance
- [ ] Configure resource limits
- [ ] Set up horizontal scaling
- [ ] Optimize database settings
- [ ] Configure caching
- [ ] Enable compression

#### Monitoring
- [ ] Set up Prometheus and Grafana
- [ ] Configure alerts
- [ ] Set up log aggregation
- [ ] Monitor resource usage

## 📈 Monitoring Setup (Optional)

### Start Monitoring Stack
```bash
# Start monitoring services
docker-compose -f monitoring/docker-compose.monitoring.yml up -d

# Access monitoring
open http://localhost:9090  # Prometheus
open http://localhost:3001  # Grafana (admin/admin)
```

### Available Metrics
- Application metrics (FastAPI, Celery)
- Database metrics (PostgreSQL, MongoDB, Redis)
- System metrics (CPU, Memory, Disk)
- Queue metrics (RabbitMQ)
- Vector database metrics (Qdrant)

## 🔄 Backup and Restore

### Automated Backups
```bash
# Create backup
./scripts/backup-databases.sh

# Backups are stored in: backups/YYYYMMDD_HHMMSS/
```

### Manual Backups
```bash
# PostgreSQL
docker-compose exec postgres pg_dump -U cap_user cap_platform > backup.sql

# MongoDB
docker-compose exec mongodb mongodump --username cap_user --password cap_password --out /tmp/backup

# Qdrant
docker-compose exec qdrant curl -X POST "http://localhost:6333/collections/backup"
```

## 🧪 Testing

### Run Tests
```bash
# Backend tests
make test
# or
docker-compose exec backend python -m pytest tests/ -v

# With coverage
make test-coverage
# or
docker-compose exec backend python -m pytest tests/ -v --cov=app --cov-report=html
```

### Load Testing
```bash
# Install locust
pip install locust

# Run load tests
locust -f tests/load_test.py --host=http://localhost:8000
```

## 📚 Next Steps

After successful infrastructure setup:

1. **Database Migrations**: Set up database schemas
2. **Authentication System**: Implement user management
3. **API Development**: Build core API endpoints
4. **Frontend Development**: Create user interfaces
5. **AI Integration**: Connect LLM providers
6. **Testing**: Write comprehensive tests

## 🆘 Support

For infrastructure issues:
1. Check the troubleshooting section above
2. View service logs: `make logs`
3. Check service health: `make health`
4. Review Docker Compose configuration
5. Check environment variables

## 📖 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Redis Documentation](https://redis.io/documentation)
- [RabbitMQ Documentation](https://www.rabbitmq.com/documentation.html)
- [Celery Documentation](https://docs.celeryproject.org/)
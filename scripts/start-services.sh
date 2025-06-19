#!/bin/bash
# File: scripts/start-services.sh
# Script to start CAP Platform services in the correct order

set -e

echo "🚀 Starting CAP Platform Services..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Start infrastructure services first
echo -e "${YELLOW}Starting infrastructure services...${NC}"
docker-compose up -d postgres mongodb qdrant redis rabbitmq

# Wait for services to be healthy
echo -e "${YELLOW}Waiting for services to be healthy...${NC}"
timeout=60
counter=0

while [ $counter -lt $timeout ]; do
    if docker-compose ps | grep -E "(postgres|mongodb|qdrant|redis|rabbitmq)" | grep -q "healthy\|Up"; then
        echo -e "${GREEN}Infrastructure services are ready!${NC}"
        break
    fi
    echo "Waiting... ($counter/$timeout)"
    sleep 2
    counter=$((counter + 2))
done

if [ $counter -ge $timeout ]; then
    echo -e "${RED}Timeout waiting for infrastructure services${NC}"
    exit 1
fi

# Start application services
echo -e "${YELLOW}Starting application services...${NC}"
docker-compose up -d backend celery_worker celery_beat flower

# Start frontend and nginx
echo -e "${YELLOW}Starting frontend and load balancer...${NC}"
docker-compose up -d frontend nginx

echo -e "${GREEN}✅ All services started successfully!${NC}"
echo ""
echo "🔗 Access URLs:"
echo "  • Backend API: http://localhost:8000"
echo "  • Frontend: http://localhost:3000"
echo "  • Flower: http://localhost:5555"
echo "  • RabbitMQ: http://localhost:15672"

# ================================================
# File: scripts/stop-services.sh
# Script to stop CAP Platform services gracefully

#!/bin/bash
set -e

echo "🛑 Stopping CAP Platform Services..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Stop application services first
echo -e "${YELLOW}Stopping application services...${NC}"
docker-compose stop frontend nginx backend celery_worker celery_beat flower

# Stop infrastructure services
echo -e "${YELLOW}Stopping infrastructure services...${NC}"
docker-compose stop postgres mongodb qdrant redis rabbitmq

echo -e "${GREEN}✅ All services stopped successfully!${NC}"

# ================================================
# File: scripts/backup-databases.sh
# Database backup script

#!/bin/bash
set -e

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "💾 Creating database backups..."

# PostgreSQL backup
echo "Backing up PostgreSQL..."
docker-compose exec -T postgres pg_dump -U cap_user cap_platform > "$BACKUP_DIR/postgres_cap_platform.sql"
docker-compose exec -T postgres pg_dump -U cap_user cap_analytics > "$BACKUP_DIR/postgres_cap_analytics.sql"
docker-compose exec -T postgres pg_dump -U cap_user cap_billing > "$BACKUP_DIR/postgres_cap_billing.sql"

# MongoDB backup
echo "Backing up MongoDB..."
docker-compose exec -T mongodb mongodump --username cap_user --password cap_password --authenticationDatabase admin --out "/tmp/backup"
docker-compose cp mongodb:/tmp/backup "$BACKUP_DIR/mongodb"

# Qdrant backup
echo "Backing up Qdrant..."
docker-compose exec -T qdrant curl -X POST "http://localhost:6333/collections/backup" > "$BACKUP_DIR/qdrant_backup.json"

echo "✅ Backups created in $BACKUP_DIR"

# ================================================
# File: scripts/health-check.sh
# Health check script for all services

#!/bin/bash

echo "🏥 CAP Platform Health Check"
echo "=========================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_service() {
    local service=$1
    local url=$2
    local name=$3
    
    if curl -s -f "$url" > /dev/null; then
        echo -e "$name: ${GREEN}✅ Healthy${NC}"
        return 0
    else
        echo -e "$name: ${RED}❌ Unhealthy${NC}"
        return 1
    fi
}

echo "Checking services..."
echo ""

# Check each service
check_service "backend" "http://localhost:8000/health" "Backend API"
check_service "frontend" "http://localhost:3000/api/health" "Frontend"
check_service "flower" "http://localhost:5555" "Flower (Celery Monitor)"
check_service "rabbitmq" "http://localhost:15672" "RabbitMQ Management"
check_service "qdrant" "http://localhost:6333/health" "Qdrant Vector DB"

echo ""
echo "Database connections:"

# Test database connections
if docker-compose exec -T postgres pg_isready -U cap_user -d cap_platform > /dev/null 2>&1; then
    echo -e "PostgreSQL: ${GREEN}✅ Connected${NC}"
else
    echo -e "PostgreSQL: ${RED}❌ Connection failed${NC}"
fi

if docker-compose exec -T mongodb mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1; then
    echo -e "MongoDB: ${GREEN}✅ Connected${NC}"
else
    echo -e "MongoDB: ${RED}❌ Connection failed${NC}"
fi

if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    echo -e "Redis: ${GREEN}✅ Connected${NC}"
else
    echo -e "Redis: ${RED}❌ Connection failed${NC}"
fi

echo ""
echo "Docker container status:"
docker-compose ps

# ================================================
# File: scripts/logs.sh
# Log viewing script

#!/bin/bash

SERVICE=${1:-"all"}

case $SERVICE in
    "backend"|"api")
        echo "📋 Backend logs:"
        docker-compose logs -f backend
        ;;
    "worker"|"celery")
        echo "📋 Celery worker logs:"
        docker-compose logs -f celery_worker
        ;;
    "frontend"|"web")
        echo "📋 Frontend logs:"
        docker-compose logs -f frontend
        ;;
    "db"|"database")
        echo "📋 Database logs:"
        docker-compose logs -f postgres mongodb
        ;;
    "queue"|"rabbitmq")
        echo "📋 Message queue logs:"
        docker-compose logs -f rabbitmq
        ;;
    "all"|*)
        echo "📋 All service logs:"
        docker-compose logs -f
        ;;
esac
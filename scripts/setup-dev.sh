#!/bin/bash
# File: scripts/setup-dev.sh
# Development environment setup script

set -e

echo "🚀 Setting up CAP Platform development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
mkdir -p backend/app/logs
mkdir -p backend/uploads
mkdir -p frontend/public
mkdir -p config/nginx/sites-available
mkdir -p config/redis
mkdir -p config/rabbitmq
mkdir -p scripts
mkdir -p kubernetes
mkdir -p monitoring/grafana/dashboards
mkdir -p docs/infrastructure

# Make scripts executable
chmod +x scripts/*.sh

# Copy environment files if they don't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file from example...${NC}"
    cp .env.example .env
fi

if [ ! -f backend/.env ]; then
    echo -e "${YELLOW}Creating backend/.env file from example...${NC}"
    cp backend/.env.example backend/.env
fi

if [ ! -f frontend/.env.local ]; then
    echo -e "${YELLOW}Creating frontend/.env.local file from example...${NC}"
    cp frontend/.env.local.example frontend/.env.local
fi

# Pull Docker images
echo -e "${YELLOW}Pulling Docker images...${NC}"
docker-compose pull

# Build containers
echo -e "${YELLOW}Building containers...${NC}"
docker-compose build

# Start infrastructure services first
echo -e "${YELLOW}Starting infrastructure services...${NC}"
docker-compose up -d postgres mongodb qdrant redis rabbitmq

# Wait for services to be ready
echo -e "${YELLOW}Waiting for services to be ready...${NC}"

# Function to wait for service
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    echo -e "${YELLOW}Waiting for $service to be ready...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T $service sh -c "exit 0" 2>/dev/null; then
            echo -e "${GREEN}$service is ready!${NC}"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts - $service not ready yet..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}$service failed to start within expected time${NC}"
    return 1
}

# Wait for each service
wait_for_service postgres 5432
wait_for_service mongodb 27017
wait_for_service qdrant 6333
wait_for_service redis 6379
wait_for_service rabbitmq 5672

echo -e "${GREEN}All infrastructure services are ready!${NC}"

# Start application services
echo -e "${YELLOW}Starting application services...${NC}"
docker-compose up -d backend celery_worker celery_beat flower

# Wait for backend to be ready
echo -e "${YELLOW}Waiting for backend to be ready...${NC}"
sleep 10

# Check if backend is healthy
if curl -f http://localhost:8000/health &>/dev/null; then
    echo -e "${GREEN}Backend is ready!${NC}"
else
    echo -e "${YELLOW}Backend is still starting up...${NC}"
fi

# Start frontend (optional)
read -p "Do you want to start the frontend? (y/N): " start_frontend
if [[ $start_frontend =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Starting frontend...${NC}"
    docker-compose up -d frontend nginx
fi

echo -e "${GREEN}✅ Development environment setup complete!${NC}"
echo ""
echo "🔗 Service URLs:"
echo "  • Backend API: http://localhost:8000"
echo "  • Frontend: http://localhost:3000 (if started)"
echo "  • Flower (Celery monitoring): http://localhost:5555"
echo "  • RabbitMQ Management: http://localhost:15672 (cap_user/cap_password)"
echo "  • Qdrant Dashboard: http://localhost:6333/dashboard"
echo ""
echo "📊 Database Connections:"
echo "  • PostgreSQL: localhost:5432 (cap_user/cap_password)"
echo "  • MongoDB: localhost:27017 (cap_user/cap_password)"
echo "  • Redis: localhost:6379"
echo ""
echo "🛠️  Development Commands:"
echo "  • View logs: docker-compose logs -f [service_name]"
echo "  • Stop services: docker-compose down"
echo "  • Restart service: docker-compose restart [service_name]"
echo "  • Shell access: docker-compose exec [service_name] /bin/bash"
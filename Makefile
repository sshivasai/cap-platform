# Makefile for CAP Platform
.PHONY: help setup start stop restart logs clean build test

# Default target
help: ## Show this help message
	@echo "CAP Platform - Development Commands"
	@echo "=================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Initial setup of development environment
	@echo "🚀 Setting up CAP Platform..."
	@chmod +x scripts/*.sh
	@./scripts/setup-dev.sh

start: ## Start all services
	@echo "🟢 Starting all services..."
	@docker-compose up -d

start-infra: ## Start only infrastructure services (databases, queues)
	@echo "🔧 Starting infrastructure services..."
	@docker-compose up -d postgres mongodb qdrant redis rabbitmq

start-app: ## Start application services
	@echo "🚀 Starting application services..."
	@docker-compose up -d backend celery_worker celery_beat flower

start-frontend: ## Start frontend service
	@echo "🎨 Starting frontend..."
	@docker-compose up -d frontend nginx

stop: ## Stop all services
	@echo "🔴 Stopping all services..."
	@docker-compose down

stop-volumes: ## Stop all services and remove volumes
	@echo "🗑️  Stopping services and removing volumes..."
	@docker-compose down -v

restart: ## Restart all services
	@echo "🔄 Restarting all services..."
	@docker-compose restart

restart-backend: ## Restart backend service
	@echo "🔄 Restarting backend..."
	@docker-compose restart backend

restart-worker: ## Restart celery workers
	@echo "🔄 Restarting Celery workers..."
	@docker-compose restart celery_worker celery_beat

build: ## Build all containers
	@echo "🔨 Building containers..."
	@docker-compose build

build-backend: ## Build backend container
	@echo "🔨 Building backend..."
	@docker-compose build backend

build-frontend: ## Build frontend container
	@echo "🔨 Building frontend..."
	@docker-compose build frontend

logs: ## Show logs for all services
	@docker-compose logs -f

logs-backend: ## Show backend logs
	@docker-compose logs -f backend

logs-worker: ## Show celery worker logs
	@docker-compose logs -f celery_worker

logs-db: ## Show database logs
	@docker-compose logs -f postgres mongodb

shell-backend: ## Access backend container shell
	@docker-compose exec backend /bin/bash

shell-db: ## Access PostgreSQL shell
	@docker-compose exec postgres psql -U cap_user -d cap_platform

shell-mongo: ## Access MongoDB shell
	@docker-compose exec mongodb mongosh -u cap_user -p cap_password

shell-redis: ## Access Redis shell
	@docker-compose exec redis redis-cli

test: ## Run tests
	@echo "🧪 Running tests..."
	@docker-compose exec backend python -m pytest tests/ -v

test-coverage: ## Run tests with coverage
	@echo "🧪 Running tests with coverage..."
	@docker-compose exec backend python -m pytest tests/ -v --cov=app --cov-report=html

lint: ## Run code linting
	@echo "🔍 Running linters..."
	@docker-compose exec backend black app/ tests/
	@docker-compose exec backend isort app/ tests/
	@docker-compose exec backend flake8 app/ tests/

format: ## Format code
	@echo "✨ Formatting code..."
	@docker-compose exec backend black app/ tests/
	@docker-compose exec backend isort app/ tests/

clean: ## Clean up containers and volumes
	@echo "🧹 Cleaning up..."
	@docker-compose down -v --rmi all --remove-orphans
	@docker system prune -f

status: ## Show service status
	@echo "📊 Service Status:"
	@docker-compose ps

health: ## Check service health
	@echo "🏥 Checking service health..."
	@echo "Backend:" && curl -s http://localhost:8000/health || echo "❌ Backend not responding"
	@echo "Frontend:" && curl -s http://localhost:3000/api/health || echo "❌ Frontend not responding"
	@echo "Flower:" && curl -s http://localhost:5555 || echo "❌ Flower not responding"
	@echo "RabbitMQ:" && curl -s http://localhost:15672 || echo "❌ RabbitMQ not responding"

backup-db: ## Backup databases
	@echo "💾 Backing up databases..."
	@mkdir -p backups
	@docker-compose exec postgres pg_dump -U cap_user cap_platform > backups/postgres_$(shell date +%Y%m%d_%H%M%S).sql
	@docker-compose exec mongodb mongodump --username cap_user --password cap_password --out backups/mongodb_$(shell date +%Y%m%d_%H%M%S)

monitor: ## Open monitoring tools
	@echo "📊 Opening monitoring tools..."
	@echo "Flower: http://localhost:5555"
	@echo "RabbitMQ: http://localhost:15672"
	@echo "Qdrant: http://localhost:6333/dashboard"
	@open http://localhost:5555 2>/dev/null || true

dev: ## Start development environment with hot reload
	@echo "🔥 Starting development environment..."
	@docker-compose -f docker-compose.yml up --build backend celery_worker

prod-build: ## Build for production
	@echo "🏭 Building for production..."
	@docker-compose -f docker-compose.prod.yml build

prod-start: ## Start production environment
	@echo "🏭 Starting production environment..."
	@docker-compose -f docker-compose.prod.yml up -d
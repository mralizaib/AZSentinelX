.PHONY: setup build up down logs ps status clean

setup:
	@echo "Setting up AZ Sentinel X environment..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file from .env.example. Please update with your credentials."; \
	else \
		echo ".env file already exists."; \
	fi
	@mkdir -p instance logs
	@echo "Setup complete!"

build:
	@echo "Building Docker containers..."
	docker-compose build

up:
	@echo "Starting AZ Sentinel X..."
	docker-compose up -d
	@echo "AZ Sentinel X started at http://10.144.90.95:5000"

down:
	@echo "Stopping AZ Sentinel X..."
	docker-compose down

logs:
	@echo "Showing logs..."
	docker-compose logs -f

ps:
	@echo "Showing running containers..."
	docker-compose ps

status:
	@echo "Checking service status..."
	@if [ $$(docker-compose ps -q | wc -l) -gt 0 ]; then \
		echo "✅ AZ Sentinel X is running."; \
	else \
		echo "❌ AZ Sentinel X is not running."; \
	fi

clean:
	@echo "Cleaning up containers and volumes..."
	docker-compose down -v
	@echo "Cleanup complete!"

help:
	@echo "AZ Sentinel X Docker Commands:"
	@echo "  make setup   - Create initial configuration files"
	@echo "  make build   - Build Docker containers"
	@echo "  make up      - Start AZ Sentinel X"
	@echo "  make down    - Stop AZ Sentinel X"
	@echo "  make logs    - View logs in real-time"
	@echo "  make ps      - Show running containers"
	@echo "  make status  - Check if services are running"
	@echo "  make clean   - Remove containers and volumes"
	@echo "  make help    - Show this help message"
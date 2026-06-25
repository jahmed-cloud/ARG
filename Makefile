# Azure Resource Guardian — Makefile
# ====================================
# Convenience targets for local development and Docker Hub publishing.
#
# Usage:
#   make build        # build images locally (no push)
#   make push         # build multi-arch images and push to Docker Hub
#   make up           # start the stack using locally built images
#   make down         # stop the stack
#   make logs         # tail all container logs
#   make seed         # create the first admin user (run once after first 'make up')
#   make migrate      # run Alembic migrations manually
#   make clean        # remove stopped containers and dangling images

REGISTRY     := jahmed22
APP          := azure-resource-guardian
VERSION      := 0.1
COMPOSE_FILE := docker-compose.yml
HUB_FILE     := docker-compose.hub.yml

.PHONY: build push up down logs seed migrate clean pull help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build amd64 image locally (no push)
	./build-push.sh --no-push

push: ## Build amd64 images and push to Docker Hub (requires docker login)
	./build-push.sh

push-multiarch: ## Build amd64 + arm64 images and push (slow ~60 min, requires docker login)
	./build-push.sh --arm

up: ## Start the full stack using locally built images
	docker compose -f $(COMPOSE_FILE) up -d --build

up-hub: ## Start the stack using pre-built Docker Hub images (no source needed)
	docker compose -f $(HUB_FILE) up -d

down: ## Stop all containers (data volumes preserved)
	docker compose -f $(COMPOSE_FILE) down

down-v: ## Stop all containers AND delete data volumes (DESTRUCTIVE)
	docker compose -f $(COMPOSE_FILE) down -v

logs: ## Tail logs from all containers
	docker compose -f $(COMPOSE_FILE) logs -f

logs-backend: ## Tail backend logs only
	docker compose -f $(COMPOSE_FILE) logs -f backend

logs-worker: ## Tail worker logs only
	docker compose -f $(COMPOSE_FILE) logs -f worker

seed: ## Create the first admin user (run once after first startup)
	docker compose -f $(COMPOSE_FILE) exec backend python -m scripts.seed_admin

migrate: ## Run Alembic migrations manually
	docker compose -f $(COMPOSE_FILE) exec backend alembic upgrade head

pull: ## Pull latest images from Docker Hub
	docker compose -f $(HUB_FILE) pull

clean: ## Remove stopped containers and dangling images
	docker compose -f $(COMPOSE_FILE) down --remove-orphans
	docker image prune -f

ps: ## Show running containers
	docker compose -f $(COMPOSE_FILE) ps

snapshot: ## Manually trigger a score snapshot (populates the Score Trend chart)
	docker compose -f $(COMPOSE_FILE) exec worker python -c \
		"from workers.scan_worker import snapshot_scores; snapshot_scores()"

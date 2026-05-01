.PHONY: help up down logs build seed e2e bench fmt lint test clean

help:
	@echo "Cyberscan dev commands:"
	@echo "  make up      - build and start the full stack (frontend, backend, worker, db, queue, minio, juice-shop)"
	@echo "  make down    - stop and remove containers"
	@echo "  make logs    - tail logs from all services"
	@echo "  make build   - rebuild images"
	@echo "  make seed    - run migrations + ingest cached feed fixtures + create seed admin"
	@echo "  make e2e     - run Playwright end-to-end test"
	@echo "  make bench   - run scan 10x and print p50/p95"
	@echo "  make test    - run pytest + frontend tests"
	@echo "  make fmt     - format (ruff, prettier)"
	@echo "  make lint    - lint (ruff, mypy, eslint, hadolint)"
	@echo "  make clean   - remove volumes"

up:
	docker compose up -d --build
	@echo "Waiting for backend to be healthy..."
	@until curl -sf http://localhost:8000/healthz >/dev/null 2>&1; do sleep 2; done
	@echo "Stack ready: frontend http://localhost:3000  api http://localhost:8000  juice-shop http://localhost:3001"

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

build:
	docker compose build

seed:
	docker compose exec backend alembic upgrade head
	docker compose exec backend python -m cyberscan_api.scripts.seed
	docker compose exec worker python -m cyberscan_worker.feeds.seed_fixtures

e2e:
	cd tests/e2e && pnpm install && pnpm playwright test

bench:
	bash scripts/bench.sh

test:
	docker compose exec backend pytest -q
	cd apps/frontend && pnpm test --if-present

fmt:
	docker compose exec backend ruff format .
	docker compose exec worker  ruff format .
	cd apps/frontend && pnpm exec prettier --write .

lint:
	docker compose exec backend ruff check .
	docker compose exec backend mypy src
	docker compose exec worker  ruff check .
	cd apps/frontend && pnpm exec eslint .

clean:
	docker compose down -v
	rm -rf .scan-artifacts .feeds-cache

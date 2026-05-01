VENV       := .venv
PY         := $(VENV)/bin/python
PIP        := $(VENV)/bin/pip
PYTEST     := $(VENV)/bin/pytest

E2E_DIR    := tests/e2e

.PHONY: help up down logs build seed e2e e2e-deps bench fmt lint test test-stack venv clean

help:
	@echo "Cyberscan dev commands:"
	@echo "  make up         - build and start the full stack (frontend, backend, worker, db, queue, minio, juice-shop)"
	@echo "  make down       - stop and remove containers"
	@echo "  make logs       - tail logs from all services"
	@echo "  make build      - rebuild images"
	@echo "  make seed       - run migrations + ingest cached feed fixtures + create seed admin"
	@echo "  make venv       - create .venv with backend + worker dev deps"
	@echo "  make test       - run pytest in the host venv (no docker required)"
	@echo "  make test-stack - run pytest inside the running backend container"
	@echo "  make e2e        - run Playwright end-to-end test (uses npm; auto-installs deps + browsers)"
	@echo "  make bench      - run scan 10x and print p50/p95"
	@echo "  make fmt        - format (ruff, prettier)"
	@echo "  make lint       - lint (ruff, mypy, eslint, hadolint)"
	@echo "  make clean      - remove volumes, .venv, and Playwright deps"

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

bench:
	bash scripts/bench.sh

# ---- Python venv -----------------------------------------------------------

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e apps/backend[dev]
	$(PIP) install -e apps/worker[dev]

venv: $(VENV)/bin/activate
	@echo "venv ready: source $(VENV)/bin/activate"

test: $(VENV)/bin/activate
	$(PYTEST) -q tests/integration

test-stack:
	docker compose exec backend pytest -q

# ---- Playwright e2e --------------------------------------------------------

$(E2E_DIR)/node_modules/.installed: $(E2E_DIR)/package.json
	cd $(E2E_DIR) && npm install
	cd $(E2E_DIR) && npx --yes playwright install --with-deps chromium
	touch $@

e2e-deps: $(E2E_DIR)/node_modules/.installed

e2e: e2e-deps
	cd $(E2E_DIR) && npx playwright test

# ---- formatting / linting --------------------------------------------------

fmt:
	docker compose exec backend ruff format .
	docker compose exec worker  ruff format .
	cd apps/frontend && npx prettier --write .

lint:
	docker compose exec backend ruff check .
	docker compose exec backend mypy src
	docker compose exec worker  ruff check .
	cd apps/frontend && npx eslint .

clean:
	docker compose down -v
	rm -rf .scan-artifacts .feeds-cache $(VENV) $(E2E_DIR)/node_modules

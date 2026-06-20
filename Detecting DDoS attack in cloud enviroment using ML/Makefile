# =============================================================
# Makefile — Cloud DDoS Detection System
#
# Convenience wrapper so the whole project runs with single commands.
# Run `make help` to see everything available.
# =============================================================

# Default dataset path — override on the command line:
#   make train DATA=data/my_dataset.csv
DATA        ?= data/BCCC-cPacket-Cloud-DDoS-2024
SAMPLE      ?= 1.0
COMPOSE     := docker compose -f docker/docker-compose.yml

.PHONY: help install train test api dashboard simulate \
        up down logs rebuild clean synthetic

help:                ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---- local (no Docker) --------------------------------------------------
install:             ## Install all Python dependencies locally
	pip install -r requirements-train.txt
	pip install -r requirements-api.txt
	pip install -r requirements-dashboard.txt
	pip install -r requirements-sim.txt
	pip install pytest

synthetic:           ## Generate a synthetic test dataset (for smoke-testing)
	python tests/make_synthetic.py

train:               ## Train the ensemble model  (DATA=... SAMPLE=...)
	python -m ml_training.train --data $(DATA) --sample $(SAMPLE)

test:                ## Run the unit test suite
	python -m pytest tests/ -q

api:                 ## Run the FastAPI server locally (foreground)
	uvicorn api_server.app:app --host 0.0.0.0 --port 8000 --reload

dashboard:           ## Run the Streamlit dashboard locally (foreground)
	streamlit run dashboard/app.py

simulate:            ## Replay traffic to a running API  (DATA=... SAMPLE=...)
	python -m simulation.replayer --data $(DATA) --sample 0.1

# ---- Docker -------------------------------------------------------------
up:                  ## Build + start API and dashboard containers
	$(COMPOSE) up --build -d
	@echo ""
	@echo "  API       -> http://localhost:8000/docs"
	@echo "  Dashboard -> http://localhost:8501"

down:                ## Stop and remove all containers
	$(COMPOSE) down

logs:                ## Tail logs from all running containers
	$(COMPOSE) logs -f

rebuild:             ## Force a clean rebuild of all images
	$(COMPOSE) build --no-cache

sim-docker:          ## Run the traffic simulator as a one-off container
	$(COMPOSE) run --rm simulation

# ---- housekeeping -------------------------------------------------------
clean:               ## Remove generated artifacts (logs, results, __pycache__)
	rm -rf ddos_results/* logs/*.log logs/*.log.*
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned. (models/ and data/ left intact)"

.PHONY: help install dev test lint format clean coverage run-tests

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package
	uv venv
	uv pip install -e .

dev:  ## Install development dependencies
	uv venv
	uv pip install -e ".[dev]"
	pre-commit install

test:  ## Run all tests
	uv run pytest

test-unit:  ## Run unit tests only
	uv run pytest tests/unit -v

test-integration:  ## Run integration tests only
	uv run pytest tests/integration -v

test-watch:  ## Run tests in watch mode
	uv run pytest-watch

coverage:  ## Run tests with coverage report
	uv run pytest --cov --cov-report=html --cov-report=term

lint:  ## Run linters
	uv run ruff check src tests
	uv run mypy src

format:  ## Format code
	uv run black src tests
	uv run ruff check --fix src tests

security:  ## Run security checks
	uv run bandit -r src
	uv run safety check

clean:  ## Clean build artifacts
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	rm -rf htmlcov .coverage coverage.xml coverage.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build:  ## Build the package
	uv build

docs:  ## Build documentation
	uv run mkdocs build

docs-serve:  ## Serve documentation locally
	uv run mkdocs serve

validate-example:  ## Run CBOR validation example
	uv run python examples/validate_cbor.py

pre-commit:  ## Run pre-commit hooks
	pre-commit run --all-files

update-deps:  ## Update dependencies
	uv pip compile pyproject.toml -o requirements.txt
	uv pip sync requirements.txt
# OSINT Platform - Backend Test & Development Commands

.PHONY: help test test-unit test-integration test-e2e test-coverage install clean lint format

help:		## Show this help message
	@echo 'Usage: make [target] ...'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:	## Install dependencies
	pip install -r requirements.txt

test:		## Run all tests with coverage
	pytest --cov=. --cov-report=html --cov-report=term-missing

test-unit:	## Run unit tests only
	pytest tests/unit/ -v

test-integration:	## Run integration tests only
	pytest tests/integration/ -v

test-e2e:	## Run end-to-end tests only
	pytest tests/e2e/ -v

test-coverage:	## Generate detailed coverage report
	pytest --cov=. --cov-report=html --cov-report=term-missing --cov-fail-under=80

test-fast:	## Run unit tests only (fast feedback)
	pytest tests/unit/ -v --tb=short

test-watch:	## Run tests in watch mode (requires pytest-watch)
	pytest-watch --runner "pytest tests/unit/"

lint:		## Run linting (requires flake8)
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

format:		## Format code (requires black)
	black . --line-length=100

clean:		## Clean up test artifacts
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

dev-setup:	## Set up development environment
	pip install -r requirements.txt
	pip install black flake8 pytest-watch

# Test targets with specific markers
test-security:	## Run security-related tests
	pytest -m security -v

test-quick:	## Run quick unit tests only
	pytest tests/unit/ -v --tb=short --maxfail=3

# CI/CD targets
ci-test:	## Run tests suitable for CI environment
	pytest --cov=. --cov-report=xml --cov-fail-under=80 --junitxml=test-results.xml

# Development server targets
run-dev:	## Run development server
	export FLASK_ENV=development && flask run --host=0.0.0.0 --port=5001

run-prod:	## Run production server
	gunicorn -w 4 -b 0.0.0.0:5001 app:app
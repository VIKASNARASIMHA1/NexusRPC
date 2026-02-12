.PHONY: help setup certs test run-server run-client run-banking clean docker docker-compose-up benchmark

help:
	@echo "NexusRPC - Custom RPC Framework"
	@echo ""
	@echo "Available commands:"
	@echo "  make setup          - Install dependencies"
	@echo "  make certs          - Generate TLS certificates"
	@echo "  make test          - Run test suite"
	@echo "  make run-server    - Start RPC server"
	@echo "  make run-banking   - Start banking service"
	@echo "  make run-client    - Run banking client demo"
	@echo "  make benchmark     - Run performance benchmarks"
	@echo "  make docker-build  - Build Docker images"
	@echo "  make docker-up     - Start all services"
	@echo "  make clean         - Clean build artifacts"

setup:
	pip install -r requirements.txt
	pip install pytest pytest-cov black mypy

certs:
	@echo "Generating TLS certificates..."
	cd security/certs && chmod +x generate_certs.sh && ./generate_certs.sh
	@echo "✅ Certificates generated"

test:
	pytest tests/ -v --cov=rpc --cov=security --cov=discovery
	pytest tests/benchmarks/test_performance.py -v

run-server:
	python -m rpc.server_cli --host 0.0.0.0 --port 50051 --tls --registry etcd

run-banking:
	python -m examples.banking.service --port 50051 --tls

run-client:
	python -m examples.banking.client

benchmark:
	python benchmarks/benchmark.py --host localhost --port 50051 \
		--concurrency 10 25 50 100 --requests 1000
	python benchmarks/compare_grpc.py

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d
	docker-compose logs -f

docker-down:
	docker-compose down

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "build" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +

format:
	black rpc/ security/ discovery/ examples/ tests/
	isort rpc/ security/ discovery/ examples/ tests/

lint:
	flake8 rpc/ security/ discovery/ examples/ tests/
	mypy rpc/ security/ discovery/
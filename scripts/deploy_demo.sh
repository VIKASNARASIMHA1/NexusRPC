#!/bin/bash
# NexusRPC Demo Deployment Script

set -e

echo "🚀 NexusRPC Demo Deployment"
echo "=========================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "\n${BLUE}Checking prerequisites...${NC}"

command -v python3 >/dev/null 2>&1 || { echo -e "${RED}Python 3 required${NC}" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${YELLOW}Docker not found, using local deployment${NC}" >&2; }
command -v docker-compose >/dev/null 2>&1 || { echo -e "${YELLOW}Docker Compose not found${NC}" >&2; }

# Setup virtual environment
echo -e "\n${BLUE}Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo -e "\n${BLUE}Installing dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Generate certificates
echo -e "\n${BLUE}Generating TLS certificates...${NC}"
cd security/certs
chmod +x generate_certs.sh
./generate_certs.sh
cd ../..

# Run tests
echo -e "\n${BLUE}Running test suite...${NC}"
pytest tests/ -v --tb=short

# Start services with Docker Compose
if command -v docker-compose >/dev/null 2>&1; then
    echo -e "\n${BLUE}Starting services with Docker Compose...${NC}"
    docker-compose up -d
    
    echo -e "\n${BLUE}Waiting for services to be ready...${NC}"
    sleep 10
    
    # Check service health
    if curl -s http://localhost:50051/health >/dev/null; then
        echo -e "${GREEN}✓ RPC Server is running${NC}"
    else
        echo -e "${YELLOW}⚠️  RPC Server health check failed${NC}"
    fi
    
    if curl -s http://localhost:2379/version >/dev/null; then
        echo -e "${GREEN}✓ etcd is running${NC}"
    else
        echo -e "${YELLOW}⚠️  etcd health check failed${NC}"
    fi
    
    if curl -s http://localhost:9090 >/dev/null; then
        echo -e "${GREEN}✓ Prometheus is running${NC}"
    else
        echo -e "${YELLOW}⚠️  Prometheus health check failed${NC}"
    fi
    
    if curl -s http://localhost:16686 >/dev/null; then
        echo -e "${GREEN}✓ Jaeger is running${NC}"
    else
        echo -e "${YELLOW}⚠️  Jaeger health check failed${NC}"
    fi
else
    # Local deployment
    echo -e "\n${BLUE}Starting local services...${NC}"
    
    # Start RPC server in background
    python -m examples.banking.service --port 50051 --tls &
    BANKING_PID=$!
    
    python -m examples.user.service --port 50052 --tls &
    USER_PID=$!
    
    echo -e "${GREEN}✓ Banking Service started (PID: $BANKING_PID)${NC}"
    echo -e "${GREEN}✓ User Service started (PID: $USER_PID)${NC}"
fi

# Run demo clients
echo -e "\n${BLUE}Running Banking Service Demo...${NC}"
python -m examples.banking.client

echo -e "\n${BLUE}Running User Service Demo...${NC}"
python -m examples.user.client

# Display service endpoints
echo -e "\n${GREEN}✅ Deployment successful!${NC}"
echo -e "\n${BLUE}Service Endpoints:${NC}"
echo -e "  • RPC Server (Banking):   localhost:50051"
echo -e "  • RPC Server (User):      localhost:50052"
echo -e "  • etcd:                   localhost:2379"
echo -e "  • Prometheus:             http://localhost:9090"
echo -e "  • Grafana:                http://localhost:3000 (admin/admin)"
echo -e "  • Jaeger UI:              http://localhost:16686"
echo -e "  • Metrics:                http://localhost:9090/metrics"

echo -e "\n${BLUE}To stop services:${NC}"
echo -e "  • Docker:   docker-compose down"
echo -e "  • Local:    kill $BANKING_PID $USER_PID"

echo -e "\n${GREEN}✨ Demo deployment complete!${NC}"
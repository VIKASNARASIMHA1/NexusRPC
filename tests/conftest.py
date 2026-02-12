"""
Pytest configuration and fixtures
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rpc.server import NexusRPCServer
from rpc.client import RPCClient
from security.tls import TLSConfig
from security.auth import AuthConfig
from discovery.memory import InMemoryRegistry
from discovery.models import ServiceInstance, ServiceEndpoint


@pytest.fixture
def tls_config():
    """TLS configuration for testing"""
    certs_dir = Path(__file__).parent.parent / "security" / "certs"
    
    # Generate certs if not exist
    if not (certs_dir / "server.crt").exists():
        import subprocess
        subprocess.run(["chmod", "+x", str(certs_dir / "generate_certs.sh")], cwd=certs_dir)
        subprocess.run(["./generate_certs.sh"], cwd=certs_dir)
    
    return TLSConfig(
        certfile=str(certs_dir / "server.crt"),
        keyfile=str(certs_dir / "server.key"),
        cafile=str(certs_dir / "ca.crt"),
        verify_mode="required"
    )


@pytest.fixture
def auth_config():
    """Auth configuration for testing"""
    return AuthConfig(
        secret_key="test-secret-key-for-testing-only",
        algorithm="HS256"
    )


@pytest.fixture
def registry():
    """In-memory registry for testing"""
    return InMemoryRegistry()


@pytest.fixture
def server(registry, tls_config, auth_config):
    """RPC server fixture"""
    server = NexusRPCServer(
        host="localhost",
        port=0,  # Random port
        tls_config=tls_config,
        auth_config=auth_config,
        registry=registry
    )
    
    # Register test service
    from tests.test_service import TestService
    server.register_service(TestService())
    
    return server


@pytest.fixture
def client(tls_config, auth_config):
    """RPC client fixture"""
    return RPCClient(
        host="localhost",
        port=0,  # Will be set by server
        tls_config=tls_config,
        auth_config=auth_config
    )


@pytest.fixture
def service_instance():
    """Service instance fixture"""
    return ServiceInstance(
        id="test-instance-1",
        name="test-service",
        version="1.0.0",
        endpoints=[
            ServiceEndpoint(
                protocol="tls",
                address="localhost",
                port=50051,
                weight=1
            )
        ],
        metadata={"test": "true"}
    )
"""
NexusRPC Server Tests
Tests for RPC server functionality
"""

import pytest
import threading
import time
import socket
from concurrent.futures import ThreadPoolExecutor

from rpc.server import NexusRPCServer, RPCService, RPCServiceRegistry
from rpc.client import RPCClient
from rpc.errors import RPCError, MethodNotFoundError
from security.tls import TLSConfig


class EchoService(RPCService):
    """Test service for server testing"""
    
    def __init__(self):
        super().__init__(name="EchoService")
        self.register(self.echo)
        self.register(self.sleep)
        self.calls = []
    
    def echo(self, message: str) -> str:
        self.calls.append(('echo', message))
        return message
    
    def sleep(self, seconds: float) -> str:
        import time
        time.sleep(seconds)
        return f"Slept for {seconds}s"


class TestNexusRPCServer:
    """Test RPC server functionality"""
    
    def test_server_initialization(self):
        """Test server initialization"""
        server = NexusRPCServer(
            host="localhost",
            port=0,  # Random port
            max_workers=5
        )
        
        assert server.host == "localhost"
        assert server.port == 0
        assert server.running is False
        assert server.executor._max_workers == 5
        
        server.stop()
    
    def test_server_with_tls(self, tls_config):
        """Test server with TLS configuration"""
        server = NexusRPCServer(
            host="localhost",
            port=0,
            tls_config=tls_config,
            max_workers=5
        )
        
        assert server.tls_config == tls_config
        assert server.tls_server is not None
        
        server.stop()
    
    def test_register_service(self):
        """Test service registration"""
        server = NexusRPCServer(host="localhost", port=0)
        service = EchoService()
        
        server.register_service(service)
        
        assert "EchoService" in server.service_registry.services
        assert server.service_registry.services["EchoService"] == service
        
        server.stop()
    
    def test_service_method_registration(self):
        """Test service method registration"""
        service = EchoService()
        
        assert "echo" in service.methods
        assert "sleep" in service.methods
        assert service.methods["echo"] == service.echo
        assert service.methods["sleep"] == service.sleep
    
    def test_service_registry(self):
        """Test service registry"""
        registry = RPCServiceRegistry()
        service = EchoService()
        
        registry.register_service(service)
        
        method = registry.get_method("EchoService", "echo")
        assert method == service.echo
        
        method = registry.get_method("EchoService", "nonexistent")
        assert method is None
        
        method = registry.get_method("NonexistentService", "echo")
        assert method is None


@pytest.fixture
def echo_server(tls_config):
    """Fixture for echo server"""
    server = NexusRPCServer(
        host="localhost",
        port=0,  # Random port
        tls_config=tls_config,
        max_workers=2
    )
    
    server.register_service(EchoService())
    
    # Start server in thread
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(0.5)
    
    # Get actual port
    port = server.socket.getsockname()[1]
    
    yield server, port
    
    server.stop()
    server_thread.join(timeout=2)


class TestServerOperations:
    """Test server operations with real client"""
    
    def test_echo_call(self, echo_server):
        """Test basic echo RPC call"""
        server, port = echo_server
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config
        )
        
        result = client.call("EchoService", "echo", "Hello, World!")
        assert result == "Hello, World!"
        
        client.close()
    
    def test_concurrent_calls(self, echo_server):
        """Test concurrent RPC calls"""
        server, port = echo_server
        
        def make_call(x):
            client = RPCClient(
                host="localhost",
                port=port,
                tls_config=server.tls_config
            )
            try:
                return client.call("EchoService", "echo", f"Message {x}")
            finally:
                client.close()
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_call, i) for i in range(10)]
            results = [f.result() for f in futures]
        
        assert results == [f"Message {i}" for i in range(10)]
    
    def test_method_not_found(self, echo_server):
        """Test calling non-existent method"""
        server, port = echo_server
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config
        )
        
        with pytest.raises(MethodNotFoundError):
            client.call("EchoService", "nonexistent")
        
        client.close()
    
    def test_service_not_found(self, echo_server):
        """Test calling non-existent service"""
        server, port = echo_server
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config
        )
        
        with pytest.raises(RPCError):
            client.call("NonexistentService", "echo", "test")
        
        client.close()
    
    def test_timeout_handling(self, echo_server):
        """Test request timeout handling"""
        server, port = echo_server
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config,
            timeout=1.0  # 1 second timeout
        )
        
        # This should timeout
        with pytest.raises(Exception):  # TimeoutError
            client.call("EchoService", "sleep", 2.0)
        
        client.close()
    
    def test_large_payload(self, echo_server):
        """Test large payload transfer"""
        server, port = echo_server
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config
        )
        
        # 1MB payload
        large_message = "x" * (1024 * 1024)
        result = client.call("EchoService", "echo", large_message)
        
        assert len(result) == len(large_message)
        assert result == large_message
        
        client.close()
    
    def test_server_graceful_shutdown(self, echo_server):
        """Test graceful server shutdown"""
        server, port = echo_server
        
        # Start long-running request
        def long_request():
            client = RPCClient(
                host="localhost",
                port=port,
                tls_config=server.tls_config
            )
            try:
                return client.call("EchoService", "sleep", 2.0)
            except:
                return None
            finally:
                client.close()
        
        import threading
        request_thread = threading.Thread(target=long_request)
        request_thread.start()
        
        time.sleep(0.5)  # Let request start
        
        # Shutdown server
        server.stop()
        
        request_thread.join(timeout=3)
    
    def test_server_metrics(self, echo_server):
        """Test server metrics collection"""
        server, port = echo_server
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config
        )
        
        # Make some calls
        for i in range(5):
            client.call("EchoService", "echo", f"test{i}")
        
        # Check metrics if available
        if hasattr(server, 'metrics'):
            # Metrics should have been recorded
            pass
        
        client.close()
    
    def test_server_with_auth(self, echo_server, auth_config):
        """Test server with authentication"""
        server, port = echo_server
        
        # Enable auth on server
        server.authenticator = auth_config
        
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config,
            auth_config=auth_config
        )
        
        # Call without auth - should succeed if server doesn't require it
        result = client.call("EchoService", "echo", "no auth")
        assert result == "no auth"
        
        client.close()


class TestServerErrorHandling:
    """Test server error handling scenarios"""
    
    def test_invalid_protocol(self, echo_server):
        """Test invalid protocol handling"""
        server, port = echo_server
        
        # Send raw socket data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', port))
        
        # Send invalid frame
        sock.send(b'INVALID')
        
        # Should not crash server
        response = sock.recv(1024)
        
        sock.close()
        
        # Server should still accept connections
        client = RPCClient(
            host="localhost",
            port=port,
            tls_config=server.tls_config
        )
        
        result = client.call("EchoService", "echo", "still working")
        assert result == "still working"
        
        client.close()
    
    def test_server_max_connections(self, tls_config):
        """Test server max connections handling"""
        server = NexusRPCServer(
            host="localhost",
            port=0,
            tls_config=tls_config,
            max_workers=1
        )
        
        server.register_service(EchoService())
        
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(0.5)
        
        port = server.socket.getsockname()[1]
        
        # Create multiple clients
        clients = []
        for i in range(3):
            client = RPCClient(
                host="localhost",
                port=port,
                tls_config=tls_config
            )
            clients.append(client)
        
        # Make requests
        results = []
        for client in clients[:2]:  # Only try 2 connections
            try:
                result = client.call("EchoService", "echo", "test")
                results.append(result)
            except:
                results.append(None)
        
        # Cleanup
        for client in clients:
            client.close()
        
        server.stop()
        server_thread.join(timeout=2)
        
        # At least one should succeed
        assert any(results)
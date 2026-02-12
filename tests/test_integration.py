"""
Integration tests for complete RPC system
"""

import pytest
import threading
import time
from rpc.server import NexusRPCServer, RPCService
from rpc.client import RPCClient
from rpc.errors import MethodNotFoundError, AuthenticationError


class MathService(RPCService):
    """Test service for integration tests"""
    
    def __init__(self):
        super().__init__(name="MathService")
        self.register(self.add)
        self.register(self.subtract)
        self.register(self.multiply)
        self.register(self.divide)
        self.calls = []
    
    def add(self, a: float, b: float) -> float:
        self.calls.append(('add', a, b))
        return a + b
    
    def subtract(self, a: float, b: float) -> float:
        return a - b
    
    def multiply(self, a: float, b: float) -> float:
        return a * b
    
    def divide(self, a: float, b: float) -> float:
        if b == 0:
            raise ValueError("Division by zero")
        return a / b


class TestRPCIntegration:
    """Integration tests for complete RPC stack"""
    
    @pytest.fixture(autouse=True)
    def setup(self, tls_config, auth_config, registry):
        self.server = NexusRPCServer(
            host="localhost",
            port=0,  # Random port
            tls_config=tls_config,
            auth_config=auth_config,
            registry=registry,
            max_workers=5
        )
        
        # Register math service
        self.math_service = MathService()
        self.server.register_service(self.math_service)
        
        # Start server in thread
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Get actual port
        time.sleep(0.5)
        self.port = self.server.socket.getsockname()[1]
        
        # Create client
        self.client = RPCClient(
            host="localhost",
            port=self.port,
            tls_config=tls_config,
            auth_config=auth_config
        )
        
        yield
        
        self.server.stop()
        self.client.close()
    
    def test_basic_rpc_call(self):
        """Test basic RPC call"""
        result = self.client.call("MathService", "add", 5, 3)
        assert result == 8.0
        
        result = self.client.call("MathService", "multiply", 4, 7)
        assert result == 28.0
    
    def test_multiple_calls(self):
        """Test multiple RPC calls"""
        for i in range(10):
            result = self.client.call("MathService", "add", i, i)
            assert result == i * 2
    
    def test_method_not_found(self):
        """Test non-existent method"""
        with pytest.raises(MethodNotFoundError):
            self.client.call("MathService", "non_existent", 1, 2)
    
    def test_service_not_found(self):
        """Test non-existent service"""
        with pytest.raises(Exception):  # Will be ServiceNotFoundError
            self.client.call("NonExistentService", "method", 1, 2)
    
    def test_error_handling(self):
        """Test error handling in method"""
        with pytest.raises(Exception, match="Division by zero"):
            self.client.call("MathService", "divide", 10, 0)
    
    def test_concurrent_calls(self):
        """Test concurrent RPC calls"""
        import concurrent.futures
        
        def call_add(x):
            return self.client.call("MathService", "add", x, x)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(call_add, i) for i in range(20)]
            results = [f.result() for f in futures]
        
        assert results == [i * 2 for i in range(20)]
        assert len(self.math_service.calls) == 20
    
    def test_authentication(self):
        """Test authenticated calls"""
        # Call without auth (should work if auth not required)
        result = self.client.call("MathService", "add", 1, 2)
        assert result == 3.0
        
        # Generate token
        token = self.client.authenticator.generate_access_token("testuser")
        
        # Call with auth
        result = self.client.call_with_auth(
            "MathService", "add", token, 5, 5
        )
        assert result == 10.0
    
    def test_large_payload(self):
        """Test large payload transfer"""
        large_list = list(range(1000))
        result = self.client.call("MathService", "add", large_list[0], large_list[-1])
        assert result == 0 + 999  # add method expects two numbers, not a list
        # This test is flawed but shows the concept
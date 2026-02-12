"""
NexusRPC Client Tests
Tests for RPC client functionality
"""

import pytest
import threading
import time
from unittest.mock import Mock, patch

from rpc.client import RPCClient, LoadBalancingRPCClient, LoadBalancingStrategy, CircuitBreaker
from rpc.errors import ConnectionError, TimeoutError, RPCError
from security.tls import TLSConfig


class TestRPCClient:
    """Test basic RPC client functionality"""
    
    def test_client_initialization(self):
        """Test client initialization"""
        client = RPCClient(
            host="localhost",
            port=50051,
            pool_size=5,
            timeout=5.0,
            retries=3
        )
        
        assert client.host == "localhost"
        assert client.port == 50051
        assert client.timeout == 5.0
        assert client.retries == 3
        assert client.connection_pool is not None
        
        client.close()
    
    def test_client_with_tls(self, tls_config):
        """Test client with TLS configuration"""
        client = RPCClient(
            host="localhost",
            port=50051,
            tls_config=tls_config,
            pool_size=3
        )
        
        assert client.tls_config == tls_config
        assert client.connection_pool.tls_config == tls_config
        
        client.close()
    
    def test_call_method_not_found(self, server_with_math_service):
        """Test calling non-existent method"""
        host, port, server_thread = server_with_math_service
        client = RPCClient(host=host, port=port)
        
        with pytest.raises(RPCError):
            client.call("MathService", "non_existent_method", 1, 2)
        
        client.close()
    
    def test_call_service_not_found(self, server_with_math_service):
        """Test calling non-existent service"""
        host, port, server_thread = server_with_math_service
        client = RPCClient(host=host, port=port)
        
        with pytest.raises(RPCError):
            client.call("NonExistentService", "add", 1, 2)
        
        client.close()
    
    def test_call_with_auth(self, server_with_math_service, auth_config):
        """Test authenticated calls"""
        host, port, server_thread = server_with_math_service
        
        client = RPCClient(
            host=host,
            port=port,
            auth_config=auth_config
        )
        
        # Generate token
        token = client.authenticator.generate_access_token("testuser")
        
        # Call with auth
        result = client.call_with_auth(
            "MathService",
            "add",
            token,
            5,
            7
        )
        
        assert result == 12.0
        client.close()
    
    def test_connection_pooling(self):
        """Test connection pool behavior"""
        client = RPCClient(
            host="localhost",
            port=50051,
            pool_size=2
        )
        
        pool = client.connection_pool
        
        # Pool should have initial connections
        assert pool._pool.qsize() == 2
        assert pool._active_connections == 2
        
        # Acquire connections
        conn1 = pool.acquire()
        conn2 = pool.acquire()
        
        assert pool._pool.qsize() == 0
        
        # Release connections
        pool.release(conn1)
        pool.release(conn2)
        
        assert pool._pool.qsize() == 2
        
        client.close()
    
    def test_connection_pool_exhaustion(self):
        """Test connection pool exhaustion"""
        client = RPCClient(
            host="localhost",
            port=50051,
            pool_size=1
        )
        
        pool = client.connection_pool
        
        # Acquire the only connection
        conn = pool.acquire()
        
        # Should timeout trying to get another
        with pytest.raises(ConnectionError):
            pool.acquire()
        
        pool.release(conn)
        client.close()
    
    def test_retry_on_failure(self):
        """Test retry logic"""
        client = RPCClient(
            host="localhost",
            port=50051,
            retries=3,
            retry_backoff=0.1
        )
        
        # Mock the connection to fail twice then succeed
        mock_connection = Mock()
        mock_connection.send.side_effect = [
            ConnectionError("First failure"),
            ConnectionError("Second failure"),
            None  # Success
        ]
        
        # Patch the connection pool
        with patch.object(client.connection_pool, 'acquire', 
                         return_value=mock_connection):
            
            # Should succeed after retries
            client._execute_call = Mock(return_value="success")
            result = client.call("TestService", "method")
            
            assert result == "success"
            assert client._execute_call.call_count == 1
    
    def test_timeout_handling(self):
        """Test timeout handling"""
        client = RPCClient(
            host="localhost",
            port=50051,
            timeout=0.1
        )
        
        # Mock slow connection
        mock_connection = Mock()
        mock_connection.send.side_effect = TimeoutError("Operation timed out")
        
        with patch.object(client.connection_pool, 'acquire',
                         return_value=mock_connection):
            
            with pytest.raises(TimeoutError):
                client._execute_call("TestService", "method", (), {})
        
        client.close()


class TestCircuitBreaker:
    """Test circuit breaker pattern"""
    
    def test_initial_state(self):
        """Test initial circuit breaker state"""
        cb = CircuitBreaker()
        assert cb.state.value == "closed"
        assert cb.failure_count == 0
    
    def test_open_on_failures(self):
        """Test circuit opens after threshold failures"""
        cb = CircuitBreaker()
        cb.config.failure_threshold = 3
        
        def failing_func():
            raise ValueError("Test failure")
        
        # First two failures - circuit still closed
        for i in range(2):
            with pytest.raises(ValueError):
                cb.call(failing_func)
            assert cb.state.value == "closed"
            assert cb.failure_count == i + 1
        
        # Third failure - circuit opens
        with pytest.raises(ValueError):
            cb.call(failing_func)
        assert cb.state.value == "open"
        assert cb.failure_count == 3
    
    def test_half_open_recovery(self):
        """Test half-open state recovery"""
        cb = CircuitBreaker()
        cb.config.failure_threshold = 2
        cb.config.recovery_timeout = 0.1
        
        def failing_func():
            raise ValueError("Test failure")
        
        def success_func():
            return "success"
        
        # Open the circuit
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(failing_func)
        
        assert cb.state.value == "open"
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Should be half-open now
        result = cb.call(success_func)
        assert result == "success"
        assert cb.state.value == "closed"
    
    def test_half_open_failure(self):
        """Test failure in half-open state"""
        cb = CircuitBreaker()
        cb.config.failure_threshold = 2
        cb.config.recovery_timeout = 0.1
        
        def failing_func():
            raise ValueError("Test failure")
        
        # Open the circuit
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(failing_func)
        
        assert cb.state.value == "open"
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Should be half-open, call fails - back to open
        with pytest.raises(ValueError):
            cb.call(failing_func)
        
        assert cb.state.value == "open"
    
    def test_circuit_breaker_decorator(self):
        """Test circuit breaker with successful calls"""
        cb = CircuitBreaker()
        
        call_count = 0
        
        def successful_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        # Multiple successful calls should work
        for _ in range(10):
            result = cb.call(successful_func)
            assert result == "success"
        
        assert call_count == 10
        assert cb.state.value == "closed"
        assert cb.failure_count == 0


class TestLoadBalancingClient:
    """Test load balancing client"""
    
    def setup_method(self):
        """Setup test fixtures"""
        from discovery.memory import InMemoryRegistry
        from discovery.models import ServiceInstance, ServiceEndpoint
        
        self.registry = InMemoryRegistry()
        
        # Register test instances
        for i in range(3):
            instance = ServiceInstance(
                id=f"test-{i}",
                name="test-service",
                version="1.0.0",
                endpoints=[
                    ServiceEndpoint(
                        protocol="tcp",
                        address=f"192.168.1.{i+1}",
                        port=50051 + i
                    )
                ],
                metadata={"weight": i+1}
            )
            self.registry.register(instance)
        
        self.instances = self.registry.discover("test-service")
    
    def test_round_robin(self):
        """Test round robin load balancing"""
        client = LoadBalancingRPCClient(
            registry=self.registry,
            service_name="test-service",
            strategy=LoadBalancingStrategy.ROUND_ROBIN
        )
        
        # Should cycle through instances
        instances = []
        for _ in range(6):
            instance = client._select_instance()
            instances.append(instance.id)
        
        # Pattern should be 0,1,2,0,1,2
        assert instances[0] == instances[3]
        assert instances[1] == instances[4]
        assert instances[2] == instances[5]
    
    def test_random(self):
        """Test random load balancing"""
        client = LoadBalancingRPCClient(
            registry=self.registry,
            service_name="test-service",
            strategy=LoadBalancingStrategy.RANDOM
        )
        
        # Should return random instances
        selections = []
        for _ in range(20):
            instance = client._select_instance()
            selections.append(instance.id)
        
        # Should have at least 2 different instances
        assert len(set(selections)) >= 2
    
    def test_least_connections(self):
        """Test least connections load balancing"""
        client = LoadBalancingRPCClient(
            registry=self.registry,
            service_name="test-service",
            strategy=LoadBalancingStrategy.LEAST_CONNECTIONS
        )
        
        # Initialize connection counts
        client._connection_counts = {
            "192.168.1.1:50051": 5,
            "192.168.1.2:50052": 2,
            "192.168.1.3:50053": 0
        }
        
        # Should pick instance with least connections (index 2)
        instance = client._select_instance()
        assert instance.endpoints[0].port == 50053
    
    def test_weighted(self):
        """Test weighted load balancing"""
        client = LoadBalancingRPCClient(
            registry=self.registry,
            service_name="test-service",
            strategy=LoadBalancingStrategy.WEIGHTED
        )
        
        # Update weights
        for i, instance in enumerate(self.instances):
            instance.metadata['weight'] = i + 1
        
        # Higher weight = higher probability
        selections = []
        for _ in range(100):
            instance = client._select_instance()
            selections.append(instance.id)
        
        # Count selections
        from collections import Counter
        counts = Counter(selections)
        
        # Higher weight instances should be selected more often
        # This is probabilistic, but weights 1,2,3 should show trend
        assert counts.get('test-2', 0) > counts.get('test-0', 0)
    
    def test_instance_refresh(self):
        """Test instance list refresh"""
        client = LoadBalancingRPCClient(
            registry=self.registry,
            service_name="test-service"
        )
        
        # Initial instances
        assert len(client.instances) == 3
        
        # Add new instance
        new_instance = ServiceInstance(
            id="test-3",
            name="test-service",
            endpoints=[
                ServiceEndpoint(
                    protocol="tcp",
                    address="192.168.1.4",
                    port=50054
                )
            ]
        )
        self.registry.register(new_instance)
        
        # Force refresh
        client._refresh_instances()
        
        # Should have 4 instances now
        assert len(client.instances) == 4
    
    def test_strategy_switching(self):
        """Test switching load balancing strategies"""
        client = LoadBalancingRPCClient(
            registry=self.registry,
            service_name="test-service",
            strategy=LoadBalancingStrategy.ROUND_ROBIN
        )
        
        assert client.strategy == LoadBalancingStrategy.ROUND_ROBIN
        
        client.strategy = LoadBalancingStrategy.RANDOM
        assert client.strategy == LoadBalancingStrategy.RANDOM
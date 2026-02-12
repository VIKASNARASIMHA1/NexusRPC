"""
NexusRPC Client Implementation
Features: Connection pooling, load balancing, retries, circuit breaking
"""

import socket
import threading
import queue
import time
import random
from typing import Dict, Any, Optional, Callable, List, Tuple
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
import logging

from .protocol import RPCProtocol, RPCRequest, RPCResponse, MessageType, SerializationType
from .transport import Transport, TransportFactory
from .errors import (
    RPCError, ConnectionError, TimeoutError, 
    ServiceNotFoundError, MethodNotFoundError,
    AuthenticationError, CircuitBreakerError
)
from security.auth import JWTAuthenticator, AuthConfig
from discovery import ServiceRegistry, ServiceInstance
from monitoring.metrics import MetricsCollector
from monitoring.tracing import Tracer, Span

logger = logging.getLogger(__name__)


class LoadBalancingStrategy(Enum):
    """Load balancing algorithms"""
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_CONNECTIONS = "least_connections"
    CONSISTENT_HASH = "consistent_hash"
    WEIGHTED = "weighted"


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open" # Testing if recovered


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    timeout_duration: float = 10.0


class CircuitBreaker:
    """Circuit breaker for fault tolerance"""
    
    def __init__(self, config: CircuitBreakerConfig = None):
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0
        self.half_open_calls = 0
        self.lock = threading.RLock()
    
    def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == CircuitBreakerState.OPEN:
                if time.time() - self.last_failure_time > self.config.recovery_timeout:
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_calls = 0
                    logger.info("Circuit breaker transitioned to HALF_OPEN")
                else:
                    raise CircuitBreakerError("Circuit breaker is OPEN")
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                if self.half_open_calls >= self.config.half_open_max_calls:
                    raise CircuitBreakerError("Half-open max calls exceeded")
                self.half_open_calls += 1
        
        try:
            result = func(*args, **kwargs)
            
            with self.lock:
                if self.state == CircuitBreakerState.HALF_OPEN:
                    self.state = CircuitBreakerState.CLOSED
                    self.failure_count = 0
                    logger.info("Circuit breaker recovered, transitioned to CLOSED")
            
            return result
            
        except Exception as e:
            with self.lock:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.state == CircuitBreakerState.CLOSED:
                    if self.failure_count >= self.config.failure_threshold:
                        self.state = CircuitBreakerState.OPEN
                        logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
                elif self.state == CircuitBreakerState.HALF_OPEN:
                    self.state = CircuitBreakerState.OPEN
                    logger.warning("Circuit breaker re-opened from half-open state")
            
            raise e


class ConnectionPool:
    """Connection pool for reusing connections"""
    
    def __init__(self, host: str, port: int, pool_size: int = 10, 
                 tls_config=None, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.pool_size = pool_size
        self.tls_config = tls_config
        self.timeout = timeout
        
        self._pool = queue.Queue(maxsize=pool_size)
        self._active_connections = 0
        self._lock = threading.Lock()
        self._closed = False
        
        # Initialize pool
        for _ in range(pool_size):
            self._create_connection()
    
    def _create_connection(self):
        """Create new connection"""
        try:
            transport = TransportFactory.create_transport(
                self.host, self.port, 
                tls_config=self.tls_config,
                timeout=self.timeout
            )
            self._pool.put(transport)
            with self._lock:
                self._active_connections += 1
        except Exception as e:
            logger.error(f"Failed to create connection: {e}")
    
    def acquire(self) -> Transport:
        """Acquire connection from pool"""
        if self._closed:
            raise ConnectionError("Connection pool is closed")
        
        try:
            transport = self._pool.get(timeout=self.timeout)
            return transport
        except queue.Empty:
            # Pool exhausted, create new connection if under limit
            with self._lock:
                if self._active_connections < self.pool_size * 2:  # Allow burst
                    self._create_connection()
                    return self._pool.get(timeout=self.timeout)
            raise ConnectionError("No available connections")
    
    def release(self, transport: Transport):
        """Release connection back to pool"""
        if self._closed:
            transport.close()
            return
        
        if transport.is_connected():
            try:
                self._pool.put(transport, timeout=1)
            except queue.Full:
                transport.close()
                with self._lock:
                    self._active_connections -= 1
        else:
            with self._lock:
                self._active_connections -= 1
            # Create replacement
            self._create_connection()
    
    def close(self):
        """Close all connections"""
        self._closed = True
        while not self._pool.empty():
            try:
                transport = self._pool.get_nowait()
                transport.close()
                with self._lock:
                    self._active_connections -= 1
            except queue.Empty:
                break
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


class RPCClient:
    """
    Base RPC Client with connection pooling and circuit breaker
    """
    
    def __init__(self, host: str, port: int, 
                 tls_config=None,
                 auth_config=None,
                 pool_size: int = 10,
                 timeout: float = 5.0,
                 retries: int = 3,
                 service_name: str = None):
        
        self.host = host
        self.port = port
        self.tls_config = tls_config
        self.timeout = timeout
        self.retries = retries
        self.service_name = service_name
        
        # Connection management
        self.connection_pool = ConnectionPool(
            host, port, pool_size, tls_config, timeout
        )
        
        # Circuit breaker
        self.circuit_breaker = CircuitBreaker()
        
        # Authentication
        self.auth_config = auth_config or AuthConfig()
        self.authenticator = JWTAuthenticator(self.auth_config)
        self.access_token = None
        
        # Serialization
        self.serialization_type = SerializationType.JSON
        
        # Monitoring
        self.metrics = MetricsCollector(f'rpc_client_{host}_{port}')
        self.tracer = Tracer.get_instance()
        
        # Request tracking
        self._request_id = 0
        self._lock = threading.Lock()
        
        logger.info(f"RPC Client initialized for {host}:{port}")
    
    def call(self, service_name: str, method_name: str, 
            *args, **kwargs) -> Any:
        """
        Synchronous RPC call with retries and circuit breaker
        """
        with self.tracer.span(f"rpc.call.{service_name}.{method_name}") as span:
            span.set_tag('service', service_name)
            span.set_tag('method', method_name)
            
            start_time = time.time()
            
            def _execute():
                return self._execute_call(service_name, method_name, args, kwargs)
            
            try:
                # Apply circuit breaker
                result = self.circuit_breaker.call(_execute)
                
                # Record metrics
                duration = time.time() - start_time
                self.metrics.timing('rpc.call.duration', duration)
                self.metrics.increment('rpc.call.success')
                self.metrics.histogram('rpc.call.size', len(str(args) + str(kwargs)))
                
                span.set_tag('success', True)
                return result
                
            except Exception as e:
                self.metrics.increment('rpc.call.error')
                span.set_tag('success', False)
                span.set_tag('error', str(e))
                raise e
    
    def _execute_call(self, service_name: str, method_name: str,
                     args: tuple, kwargs: dict) -> Any:
        """Execute single RPC call"""
        transport = None
        
        for attempt in range(self.retries):
            try:
                # Acquire connection
                transport = self.connection_pool.acquire()
                
                # Generate request ID
                with self._lock:
                    self._request_id += 1
                    request_id = f"{self._request_id}_{time.time()}"
                
                # Create request
                request = RPCRequest.create(
                    service_name,
                    method_name,
                    *args,
                    **kwargs
                )
                request.request_id = request_id
                
                # Add authentication
                if self.access_token:
                    request.metadata['authorization'] = f'Bearer {self.access_token}'
                
                # Serialize request
                payload = RPCProtocol.serialize(
                    request.__dict__, 
                    self.serialization_type
                )
                
                # Encode frame
                frame = RPCProtocol.encode_message(
                    MessageType.REQUEST,
                    payload,
                    self.serialization_type
                )
                
                # Send request
                transport.send(frame)
                
                # Receive response
                response_frame = transport.recv()
                
                # Decode response
                msg_type, payload, metadata = RPCProtocol.decode_frame(response_frame)
                
                if msg_type == MessageType.ERROR:
                    # Deserialize error
                    error_dict = RPCProtocol.deserialize(
                        payload, 
                        SerializationType(metadata.get('serialization', 1))
                    )
                    raise RPCError(error_dict.get('message', 'Unknown error'))
                
                # Deserialize response
                response_dict = RPCProtocol.deserialize(
                    payload,
                    SerializationType(metadata.get('serialization', 1))
                )
                
                response = RPCResponse(**response_dict)
                
                if response.error:
                    raise RPCError(response.error)
                
                return response.result
                
            except (socket.error, ConnectionError) as e:
                logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt == self.retries - 1:
                    raise ConnectionError(f"Failed after {self.retries} attempts")
                time.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                
            except Exception as e:
                logger.error(f"RPC call failed: {e}")
                raise
                
            finally:
                if transport:
                    self.connection_pool.release(transport)
    
    def call_async(self, service_name: str, method_name: str,
                  *args, **kwargs) -> Future:
        """Asynchronous RPC call"""
        future = Future()
        
        def _async_call():
            try:
                result = self.call(service_name, method_name, *args, **kwargs)
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)
        
        thread = threading.Thread(target=_async_call, daemon=True)
        thread.start()
        
        return future
    
    def call_with_auth(self, service_name: str, method_name: str,
                      token: str = None, *args, **kwargs) -> Any:
        """RPC call with authentication token"""
        if token:
            self.access_token = token
        return self.call(service_name, method_name, *args, **kwargs)
    
    def authenticate(self, username: str, password: str) -> str:
        """Authenticate and get JWT token"""
        response = self.call(
            'AuthService', 
            'authenticate',
            username=username,
            password=password
        )
        
        self.access_token = response['token']
        return self.access_token
    
    def close(self):
        """Close client connections"""
        self.connection_pool.close()
        logger.info("RPC Client closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


class LoadBalancingRPCClient(RPCClient):
    """
    RPC Client with client-side load balancing and service discovery
    """
    
    def __init__(self, 
                 registry: ServiceRegistry,
                 service_name: str,
                 strategy: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN,
                 **kwargs):
        
        self.registry = registry
        self.service_name = service_name
        self.strategy = strategy
        self.strategy_handlers = {
            LoadBalancingStrategy.ROUND_ROBIN: self._round_robin,
            LoadBalancingStrategy.RANDOM: self._random,
            LoadBalancingStrategy.LEAST_CONNECTIONS: self._least_connections,
            LoadBalancingStrategy.CONSISTENT_HASH: self._consistent_hash,
            LoadBalancingStrategy.WEIGHTED: self._weighted
        }
        
        self._current_index = 0
        self._connection_counts = {}
        self._lock = threading.Lock()
        
        # Initialize without host/port - will discover
        super().__init__(None, None, **kwargs)
        
        # Start background refresh
        self._start_refresh_thread()
    
    def _start_refresh_thread(self):
        """Background thread to refresh service instances"""
        def refresh_loop():
            while True:
                self._refresh_instances()
                time.sleep(30)  # Refresh every 30 seconds
        
        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()
    
    def _refresh_instances(self):
        """Refresh service instances from registry"""
        try:
            instances = self.registry.discover(self.service_name)
            with self._lock:
                self.instances = instances
                # Reset connection counts for new instances
                for instance in instances:
                    instance_id = f"{instance.address}:{instance.port}"
                    if instance_id not in self._connection_counts:
                        self._connection_counts[instance_id] = 0
            logger.debug(f"Refreshed {len(instances)} instances for {self.service_name}")
        except Exception as e:
            logger.error(f"Failed to refresh instances: {e}")
    
    def _select_instance(self) -> ServiceInstance:
        """Select instance based on load balancing strategy"""
        with self._lock:
            if not hasattr(self, 'instances') or not self.instances:
                raise ServiceNotFoundError(f"No instances found for {self.service_name}")
            
            handler = self.strategy_handlers.get(self.strategy)
            if not handler:
                raise ValueError(f"Unknown strategy: {self.strategy}")
            
            return handler()
    
    def _round_robin(self) -> ServiceInstance:
        """Round robin selection"""
        instance = self.instances[self._current_index % len(self.instances)]
        self._current_index += 1
        return instance
    
    def _random(self) -> ServiceInstance:
        """Random selection"""
        return random.choice(self.instances)
    
    def _least_connections(self) -> ServiceInstance:
        """Least connections selection"""
        if not self.instances:
            return None
        
        min_conn = float('inf')
        selected = self.instances[0]
        
        for instance in self.instances:
            instance_id = f"{instance.address}:{instance.port}"
            conn_count = self._connection_counts.get(instance_id, 0)
            if conn_count < min_conn:
                min_conn = conn_count
                selected = instance
        
        # Increment connection count
        instance_id = f"{selected.address}:{selected.port}"
        self._connection_counts[instance_id] = self._connection_counts.get(instance_id, 0) + 1
        
        return selected
    
    def _consistent_hash(self) -> ServiceInstance:
        """Consistent hashing (simplified)"""
        # In production, use ketama or similar
        import hashlib
        key = str(time.time())  # Should be based on request
        hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
        return self.instances[hash_val % len(self.instances)]
    
    def _weighted(self) -> ServiceInstance:
        """Weighted round robin"""
        # Simple weighted selection based on instance metadata
        total_weight = sum(i.metadata.get('weight', 1) for i in self.instances)
        if total_weight == 0:
            return self._round_robin()
        
        r = random.randint(0, total_weight - 1)
        for instance in self.instances:
            weight = instance.metadata.get('weight', 1)
            if r < weight:
                return instance
            r -= weight
        
        return self.instances[0]
    
    def call(self, method_name: str, *args, **kwargs) -> Any:
        """Make RPC call to discovered instance"""
        instance = self._select_instance()
        
        # Update connection parameters
        self.host = instance.address
        self.port = instance.port
        
        try:
            result = super().call(self.service_name, method_name, *args, **kwargs)
            
            # Decrement connection count
            instance_id = f"{instance.address}:{instance.port}"
            with self._lock:
                self._connection_counts[instance_id] = max(
                    0, self._connection_counts.get(instance_id, 1) - 1
                )
            
            return result
            
        except Exception as e:
            # Mark instance as potentially unhealthy
            instance_id = f"{instance.address}:{instance.port}"
            with self._lock:
                self._connection_counts[instance_id] = max(
                    0, self._connection_counts.get(instance_id, 1) - 1
                )
            
            # Remove unhealthy instance
            if isinstance(e, ConnectionError):
                logger.warning(f"Removing unhealthy instance {instance_id}")
                with self._lock:
                    self.instances = [
                        i for i in self.instances 
                        if f"{i.address}:{i.port}" != instance_id
                    ]
            
            raise e
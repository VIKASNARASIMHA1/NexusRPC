"""
NexusRPC Server Implementation
Handles concurrent client connections with TLS and authentication
"""

import socket
import threading
import ssl
import queue
import logging
from typing import Dict, Any, Callable, Optional
import inspect
from concurrent.futures import ThreadPoolExecutor

from .protocol import RPCProtocol, RPCRequest, RPCResponse, MessageType, SerializationType
from .transport import Transport
from .errors import RPCError, MethodNotFoundError, AuthenticationError
from security.tls import TLSServer, TLSConfig
from security.auth import JWTAuthenticator, AuthConfig
from discovery.etcd import EtcdServiceRegistry
from discovery.models import ServiceInstance
from monitoring.metrics import MetricsCollector
from monitoring.logger import setup_logging

logger = logging.getLogger(__name__)


class RPCService:
    """RPC service decorator"""
    
    def __init__(self, name=None, version='1.0.0'):
        self.name = name
        self.version = version
        self.methods = {}
    
    def register(self, func: Callable, name: Optional[str] = None):
        """Register a method with the service"""
        method_name = name or func.__name__
        self.methods[method_name] = func
        return func


class RPCServiceRegistry:
    """Registry for RPC services"""
    
    def __init__(self):
        self.services = {}
    
    def register_service(self, service: RPCService):
        """Register a service"""
        service_name = service.name or service.__class__.__name__
        self.services[service_name] = service
        logger.info(f"Registered service: {service_name}")
    
    def get_method(self, service_name: str, method_name: str) -> Optional[Callable]:
        """Get a method from a registered service"""
        if service_name not in self.services:
            return None
        
        service = self.services[service_name]
        return service.methods.get(method_name)


class NexusRPCServer:
    """
    Main RPC Server implementation
    Features: TLS, Authentication, Service Discovery, Concurrency
    """
    
    def __init__(self, 
                 host='0.0.0.0',
                 port=50051,
                 tls_config: Optional[TLSConfig] = None,
                 auth_config: Optional[AuthConfig] = None,
                 registry: Optional[EtcdServiceRegistry] = None,
                 max_workers=10):
        
        self.host = host
        self.port = port
        self.running = False
        
        # Components
        self.tls_config = tls_config
        self.auth_config = auth_config or AuthConfig()
        self.registry = registry
        self.service_registry = RPCServiceRegistry()
        
        # Security
        self.tls_server = TLSServer(tls_config) if tls_config else None
        self.authenticator = JWTAuthenticator(self.auth_config) if auth_config else None
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.socket = None
        self.client_threads = []
        
        # Monitoring
        self.metrics = MetricsCollector('nexusrpc_server')
        
        logger.info(f"NexusRPC Server initialized on {host}:{port}")
    
    def register_service(self, service: RPCService):
        """Register a service with the server"""
        self.service_registry.register_service(service)
    
    def start(self):
        """Start the RPC server"""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(128)
            
            self.running = True
            logger.info(f"NexusRPC Server listening on {self.host}:{self.port}")
            
            # Register with service discovery
            if self.registry:
                instance = ServiceInstance(
                    name="NexusRPCServer",
                    id=f"{self.host}:{self.port}",
                    address=self.host,
                    port=self.port,
                    metadata={'version': '1.0.0'}
                )
                self.registry.register(instance)
            
            # Accept connections
            while self.running:
                try:
                    client_sock, addr = self.socket.accept()
                    logger.debug(f"New connection from {addr}")
                    
                    # Wrap with TLS if configured
                    if self.tls_server:
                        client_sock = self.tls_server.wrap_socket(client_sock)
                    
                    # Handle client in thread pool
                    future = self.executor.submit(
                        self.handle_client, 
                        client_sock, 
                        addr
                    )
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the RPC server"""
        self.running = False
        
        # Deregister from service discovery
        if self.registry:
            self.registry.deregister("NexusRPCServer", f"{self.host}:{self.port}")
        
        # Clean up sockets
        if self.socket:
            self.socket.close()
        
        self.executor.shutdown(wait=True)
        logger.info("NexusRPC Server stopped")
    
    def handle_client(self, client_sock: socket.socket, addr: tuple):
        """Handle individual client connection"""
        transport = Transport(client_sock)
        
        try:
            while self.running:
                # Read message
                data = transport.recv()
                if not data:
                    break
                
                # Decode frame
                msg_type, payload, metadata = RPCProtocol.decode_frame(data)
                
                if msg_type == MessageType.REQUEST:
                    # Handle RPC request
                    response = self.handle_request(payload, metadata, client_sock)
                    
                    # Send response
                    response_data = RPCProtocol.encode_message(
                        MessageType.RESPONSE,
                        response
                    )
                    transport.send(response_data)
                    
                elif msg_type == MessageType.HEARTBEAT:
                    # Respond to heartbeat
                    transport.send(data)  # Echo back
                    
        except ssl.SSLError as e:
            logger.error(f"TLS error with {addr}: {e}")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            transport.close()
            logger.debug(f"Connection closed: {addr}")
    
    def handle_request(self, payload: bytes, metadata: Dict, 
                      client_sock: socket.socket) -> bytes:
        """Handle RPC request and return response"""
        self.metrics.increment('requests_total')
        
        try:
            # Deserialize request
            ser_type = SerializationType(metadata.get('serialization', 1))
            request_dict = RPCProtocol.deserialize(payload, ser_type)
            
            # Create request object
            request = RPCRequest(
                request_id=request_dict['request_id'],
                service_name=request_dict['service_name'],
                method_name=request_dict['method_name'],
                args=tuple(request_dict['args']),
                kwargs=request_dict['kwargs'],
                metadata=request_dict.get('metadata', {}),
                timestamp=request_dict['timestamp']
            )
            
            # Authenticate request
            if self.authenticator:
                auth_token = request.metadata.get('authorization', '')
                if auth_token.startswith('Bearer '):
                    token = auth_token[7:]
                    try:
                        claims = self.authenticator.verify_token(token)
                        request.metadata['user_id'] = claims.get('sub')
                    except Exception as e:
                        raise AuthenticationError(str(e))
            
            # Find and execute method
            method = self.service_registry.get_method(
                request.service_name,
                request.method_name
            )
            
            if not method:
                raise MethodNotFoundError(
                    f"Method {request.service_name}.{request.method_name} not found"
                )
            
            # Execute method
            self.metrics.increment(f'methods.{request.method_name}')
            start_time = datetime.utcnow().timestamp()
            
            result = method(*request.args, **request.kwargs)
            
            execution_time = datetime.utcnow().timestamp() - start_time
            self.metrics.timing(f'method.{request.method_name}.duration', execution_time)
            
            # Create response
            response = RPCResponse(
                request_id=request.request_id,
                result=result,
                metadata={'execution_time': str(execution_time)}
            )
            
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            response = RPCResponse(
                request_id=request.request_id if 'request' in locals() else 'unknown',
                result=None,
                error=str(e)
            )
            self.metrics.increment('errors_total')
        
        # Serialize response
        return RPCProtocol.serialize(response, ser_type)
    
    def start_background_tasks(self):
        """Start background tasks like heartbeats"""
        if self.registry:
            def heartbeat_loop():
                instance = ServiceInstance(
                    name="NexusRPCServer",
                    id=f"{self.host}:{self.port}",
                    address=self.host,
                    port=self.port,
                    metadata={}
                )
                
                while self.running:
                    self.registry.heartbeat(instance)
                    time.sleep(25)  # Heartbeat every 25 seconds
            
            thread = threading.Thread(target=heartbeat_loop, daemon=True)
            thread.start()
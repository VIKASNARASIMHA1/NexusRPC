"""
NexusRPC Transport Layer
TCP/TLS transport with non-blocking I/O and frame handling
"""

import socket
import ssl
import select
import struct
import time
from typing import Optional, Tuple, Callable
from enum import Enum
import threading
import queue
import logging

from .errors import ConnectionError, TimeoutError, ProtocolError
from security.tls import TLSClient, TLSServer, TLSConfig

logger = logging.getLogger(__name__)


class TransportState(Enum):
    """Transport connection states"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    CLOSED = 3


class Transport:
    """
    Base transport class for RPC communication
    Handles frame-based message transfer
    """
    
    HEADER_SIZE = 16  # 16-byte header
    MAX_FRAME_SIZE = 10 * 1024 * 1024  # 10MB max frame
    
    def __init__(self, sock: socket.socket = None, timeout: float = 5.0):
        self.sock = sock
        self.timeout = timeout
        self.state = TransportState.CONNECTED if sock else TransportState.DISCONNECTED
        self._recv_buffer = b''
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        
        if self.sock:
            self.sock.settimeout(timeout)
    
    def connect(self, host: str, port: int) -> bool:
        """Establish connection"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((host, port))
            self.state = TransportState.CONNECTED
            logger.debug(f"Connected to {host}:{port}")
            return True
        except Exception as e:
            self.state = TransportState.DISCONNECTED
            raise ConnectionError(f"Failed to connect: {e}")
    
    def send(self, data: bytes) -> int:
        """Send complete frame"""
        if self.state != TransportState.CONNECTED:
            raise ConnectionError("Transport not connected")
        
        with self._send_lock:
            try:
                # Prefix with length
                length = len(data)
                if length > self.MAX_FRAME_SIZE:
                    raise ProtocolError(f"Frame too large: {length} > {self.MAX_FRAME_SIZE}")
                
                header = struct.pack('!I', length)
                self.sock.sendall(header + data)
                return length
                
            except socket.timeout:
                raise TimeoutError("Send timeout")
            except Exception as e:
                self.state = TransportState.DISCONNECTED
                raise ConnectionError(f"Send failed: {e}")
    
    def recv(self) -> bytes:
        """Receive complete frame"""
        if self.state != TransportState.CONNECTED:
            raise ConnectionError("Transport not connected")
        
        with self._recv_lock:
            try:
                # Read header
                header = self._recv_exact(4)
                if not header:
                    raise ConnectionError("Connection closed")
                
                length = struct.unpack('!I', header)[0]
                
                if length > self.MAX_FRAME_SIZE:
                    raise ProtocolError(f"Frame too large: {length}")
                
                # Read payload
                data = self._recv_exact(length)
                return data
                
            except socket.timeout:
                raise TimeoutError("Receive timeout")
            except Exception as e:
                self.state = TransportState.DISCONNECTED
                raise ConnectionError(f"Receive failed: {e}")
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data
    
    def close(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.state = TransportState.CLOSED
        logger.debug("Transport closed")
    
    def is_connected(self) -> bool:
        """Check if connection is active"""
        return self.state == TransportState.CONNECTED and self.sock is not None
    
    def getpeername(self) -> Tuple[str, int]:
        """Get remote address"""
        if self.sock:
            return self.sock.getpeername()
        return (None, None)
    
    def getsockname(self) -> Tuple[str, int]:
        """Get local address"""
        if self.sock:
            return self.sock.getsockname()
        return (None, None)


class TLSTransport(Transport):
    """TLS-encrypted transport"""
    
    def __init__(self, tls_config: TLSConfig, server_side: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.tls_config = tls_config
        self.server_side = server_side
        
        if server_side:
            from security.tls import TLSServer
            self.tls_context = TLSServer(tls_config)
        else:
            from security.tls import TLSClient
            self.tls_context = TLSClient(tls_config)
    
    def connect(self, host: str, port: int, server_hostname: str = None) -> bool:
        """Establish TLS connection"""
        # Create TCP connection first
        if not super().connect(host, port):
            return False
        
        try:
            # Upgrade to TLS
            if self.server_side:
                self.sock = self.tls_context.wrap_socket(self.sock)
            else:
                self.sock = self.tls_context.wrap_socket(
                    self.sock, 
                    server_hostname or host
                )
            
            self.state = TransportState.CONNECTED
            logger.info(f"TLS connection established to {host}:{port}")
            return True
            
        except ssl.SSLError as e:
            self.state = TransportState.DISCONNECTED
            raise ConnectionError(f"TLS handshake failed: {e}")
    
    def get_cipher_info(self) -> dict:
        """Get TLS cipher information"""
        if isinstance(self.sock, ssl.SSLSocket):
            return {
                'version': self.sock.version(),
                'cipher': self.sock.cipher(),
                'peercert': self.sock.getpeercert()
            }
        return {}


class AsyncTransport(Transport):
    """Non-blocking transport with select"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._read_buffer = queue.Queue()
        self._write_buffer = queue.Queue()
        self._running = False
        self._thread = None
    
    def start(self):
        """Start async processing"""
        self._running = True
        self._thread = threading.Thread(target=self._process_io, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop async processing"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
    
    def _process_io(self):
        """Process I/O asynchronously"""
        while self._running and self.is_connected():
            try:
                # Check for readable/writable
                rlist, wlist, _ = select.select(
                    [self.sock], 
                    [self.sock] if not self._write_buffer.empty() else [], 
                    [], 
                    0.1
                )
                
                # Handle reads
                if rlist:
                    try:
                        header = self.sock.recv(4)
                        if header:
                            length = struct.unpack('!I', header)[0]
                            data = self._recv_exact(length)
                            self._read_buffer.put(data)
                    except socket.error:
                        break
                
                # Handle writes
                if wlist and not self._write_buffer.empty():
                    data = self._write_buffer.get_nowait()
                    self.sock.sendall(data)
                    
            except Exception as e:
                logger.error(f"Async I/O error: {e}")
                break
    
    async def send_async(self, data: bytes):
        """Queue data for sending"""
        self._write_buffer.put(data)
    
    async def recv_async(self) -> bytes:
        """Receive data asynchronously"""
        try:
            return self._read_buffer.get(timeout=self.timeout)
        except queue.Empty:
            raise TimeoutError("No data received")


class TransportFactory:
    """Factory for creating transports"""
    
    @staticmethod
    def create_transport(host: str, port: int, 
                        tls_config: Optional[TLSConfig] = None,
                        async_mode: bool = False,
                        timeout: float = 5.0) -> Transport:
        """Create appropriate transport"""
        
        if tls_config:
            transport = TLSTransport(tls_config, server_side=False)
            transport.connect(host, port, host)
        else:
            transport = Transport()
            transport.connect(host, port)
        
        transport.timeout = timeout
        
        if async_mode:
            async_transport = AsyncTransport(sock=transport.sock)
            async_transport.timeout = timeout
            async_transport.start()
            return async_transport
        
        return transport
    
    @staticmethod
    def create_server_transport(host: str, port: int,
                               tls_config: Optional[TLSConfig] = None) -> 'ServerTransport':
        """Create server transport"""
        return ServerTransport(host, port, tls_config)


class ServerTransport:
    """Server-side transport for accepting connections"""
    
    def __init__(self, host: str, port: int, tls_config: Optional[TLSConfig] = None):
        self.host = host
        self.port = port
        self.tls_config = tls_config
        self.sock = None
        self.running = False
        
    def listen(self, backlog: int = 128):
        """Start listening"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(backlog)
            self.sock.settimeout(1.0)
            self.running = True
            
            logger.info(f"Server listening on {self.host}:{self.port}")
            
        except Exception as e:
            raise ConnectionError(f"Failed to start server: {e}")
    
    def accept(self) -> Optional[Transport]:
        """Accept new connection"""
        if not self.running or not self.sock:
            return None
        
        try:
            client_sock, addr = self.sock.accept()
            
            if self.tls_config:
                from security.tls import TLSServer
                tls_server = TLSServer(self.tls_config)
                client_sock = tls_server.wrap_socket(client_sock)
                transport = TLSTransport(self.tls_config, server_side=True, sock=client_sock)
            else:
                transport = Transport(sock=client_sock)
            
            logger.debug(f"Accepted connection from {addr}")
            return transport
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Accept failed: {e}")
            return None
    
    def close(self):
        """Stop listening"""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            logger.info("Server transport closed")
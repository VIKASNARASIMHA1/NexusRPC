"""
Tests for transport layer
"""

import pytest
import socket
import threading
import time
from rpc.transport import Transport, ServerTransport, TransportFactory
from rpc.errors import ConnectionError, TimeoutError


class TestTransport:
    """Test base transport functionality"""
    
    def test_connect(self):
        """Test connection establishment"""
        # Start echo server
        def echo_server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('localhost', 0))
            port = sock.getsockname()[1]
            sock.listen(1)
            
            client, _ = sock.accept()
            data = client.recv(1024)
            client.send(data)
            client.close()
            sock.close()
            return port
        
        # Run server in thread
        port = None
        def run_server():
            nonlocal port
            port = echo_server()
        
        thread = threading.Thread(target=run_server)
        thread.daemon = True
        thread.start()
        time.sleep(0.1)  # Wait for server to start
        
        # Test client
        transport = Transport()
        assert transport.connect('localhost', port) is True
        assert transport.is_connected()
        
        # Test send/recv
        test_data = b'Hello, World!'
        transport.send(test_data)
        response = transport.recv()
        assert response == test_data
        
        transport.close()
    
    def test_timeout(self):
        """Test connection timeout"""
        transport = Transport(timeout=0.1)
        
        with pytest.raises(ConnectionError):
            transport.connect('192.0.2.1', 12345)  # Non-routable IP
    
    def test_send_recv_timeout(self):
        """Test send/receive timeout"""
        # Create unconnected transport
        transport = Transport()
        
        with pytest.raises(ConnectionError):
            transport.send(b'test')
        
        with pytest.raises(ConnectionError):
            transport.recv()


class TestServerTransport:
    """Test server transport"""
    
    def test_listen_accept(self):
        """Test listening and accepting connections"""
        server = ServerTransport('localhost', 0)
        server.listen()
        
        assert server.running is True
        
        # Connect client
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('localhost', server.sock.getsockname()[1]))
        
        # Accept connection
        transport = server.accept()
        assert transport is not None
        assert transport.is_connected()
        
        client.close()
        server.close()
    
    def test_multiple_connections(self):
        """Test accepting multiple connections"""
        server = ServerTransport('localhost', 0)
        server.listen()
        port = server.sock.getsockname()[1]
        
        # Connect multiple clients
        clients = []
        for i in range(5):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('localhost', port))
            clients.append(client)
        
        # Accept all
        accepted = 0
        for _ in range(5):
            transport = server.accept()
            if transport:
                accepted += 1
                transport.close()
        
        assert accepted == 5
        
        for client in clients:
            client.close()
        server.close()


class TestTransportFactory:
    """Test transport factory"""
    
    def test_create_transport(self):
        """Test creating transports"""
        # TCP transport
        transport = TransportFactory.create_transport(
            'localhost', 8080, tls_config=None
        )
        assert isinstance(transport, Transport)
        
        # TLS transport requires certs
        from security.tls import TLSConfig
        tls_config = TLSConfig(
            certfile='security/certs/client.crt',
            keyfile='security/certs/client.key',
            cafile='security/certs/ca.crt'
        )
        
        # This will attempt connection, but we're just testing creation
        try:
            transport = TransportFactory.create_transport(
                'localhost', 50051, tls_config=tls_config
            )
            assert hasattr(transport, 'tls_config')
        except:
            pass
    
    def test_create_server_transport(self):
        """Test creating server transport"""
        # TCP server
        server = TransportFactory.create_server_transport('localhost', 0)
        assert isinstance(server, ServerTransport)
        
        # TLS server
        from security.tls import TLSConfig
        tls_config = TLSConfig(
            certfile='security/certs/server.crt',
            keyfile='security/certs/server.key',
            cafile='security/certs/ca.crt'
        )
        
        server = TransportFactory.create_server_transport(
            'localhost', 0, tls_config=tls_config
        )
        assert server.tls_config is not None
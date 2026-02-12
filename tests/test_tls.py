"""
NexusRPC TLS Security Tests
Tests for TLS 1.3 configuration and certificate management
"""

import pytest
import socket
import ssl
import threading
import time
from pathlib import Path

from security.tls import TLSConfig, TLSServer, TLSClient
from rpc.errors import ConnectionError


class TestTLSConfig:
    """Test TLS configuration"""
    
    def test_tls_config_validation(self):
        """Test TLS configuration validation"""
        # Valid config
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            cafile="security/certs/ca.crt"
        )
        
        assert config.certfile == "security/certs/server.crt"
        assert config.keyfile == "security/certs/server.key"
        assert config.cafile == "security/certs/ca.crt"
        assert config.verify_mode == "required"
        assert config.min_version == ssl.TLSVersion.TLSv1_2
    
    def test_missing_certificate_files(self):
        """Test missing certificate files"""
        with pytest.raises(FileNotFoundError):
            TLSConfig(
                certfile="nonexistent.crt",
                keyfile="security/certs/server.key"
            )
        
        with pytest.raises(FileNotFoundError):
            TLSConfig(
                certfile="security/certs/server.crt",
                keyfile="nonexistent.key"
            )
        
        with pytest.raises(FileNotFoundError):
            TLSConfig(
                certfile="security/certs/server.crt",
                keyfile="security/certs/server.key",
                cafile="nonexistent.crt"
            )
    
    def test_tls_version_validation(self):
        """Test TLS version validation"""
        # TLS 1.2 is minimum
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            min_version=ssl.TLSVersion.TLSv1_2
        )
        assert config.min_version == ssl.TLSVersion.TLSv1_2
        
        # TLS 1.0 should be rejected
        with pytest.raises(ValueError, match="TLS version below 1.2"):
            TLSConfig(
                certfile="security/certs/server.crt",
                keyfile="security/certs/server.key",
                min_version=ssl.TLSVersion.TLSv1
            )
    
    def test_cipher_suites(self):
        """Test cipher suite configuration"""
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            cipher_suites="TLS_AES_256_GCM_SHA384"
        )
        
        assert config.cipher_suites == "TLS_AES_256_GCM_SHA384"


class TestTLSServer:
    """Test TLS server functionality"""
    
    @pytest.fixture
    def tls_server(self):
        """Fixture for TLS server"""
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            cafile="security/certs/ca.crt"
        )
        
        server = TLSServer(config)
        return server
    
    def test_server_context_creation(self, tls_server):
        """Test SSL context creation"""
        context = tls_server._create_ssl_context()
        
        assert isinstance(context, ssl.SSLContext)
        assert context.protocol == ssl.PROTOCOL_TLS_SERVER
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert context.maximum_version == ssl.TLSVersion.TLSv1_3
        assert context.verify_mode == ssl.CERT_REQUIRED
    
    def test_server_wrap_socket(self, tls_server):
        """Test wrapping socket with TLS"""
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 0))
        port = sock.getsockname()[1]
        sock.listen(1)
        
        # Wrap with TLS
        ssl_sock = tls_server.wrap_socket(sock)
        
        assert isinstance(ssl_sock, ssl.SSLSocket)
        assert ssl_sock.context.minimum_version == ssl.TLSVersion.TLSv1_2
        
        ssl_sock.close()
    
    def test_server_with_different_verify_modes(self):
        """Test server with different verification modes"""
        # Optional verification
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            verify_mode="optional"
        )
        server = TLSServer(config)
        context = server._create_ssl_context()
        assert context.verify_mode == ssl.CERT_OPTIONAL
        
        # No verification (not recommended)
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            verify_mode="none"
        )
        server = TLSServer(config)
        context = server._create_ssl_context()
        assert context.verify_mode == ssl.CERT_NONE
    
    def test_certificate_info(self, tls_server):
        """Test certificate information extraction"""
        # Create a connected socket for testing
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(('localhost', 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)
        
        # Accept connection in background
        def accept():
            client, addr = server_sock.accept()
            return tls_server.wrap_socket(client)
        
        import threading
        accept_thread = threading.Thread(target=accept)
        accept_thread.daemon = True
        accept_thread.start()
        
        # Connect client
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('localhost', port))
        
        # Wrap server socket
        time.sleep(0.1)
        
        server_sock.close()
        client_sock.close()
        
        # Just verify the method exists
        assert hasattr(tls_server, 'get_certificate_info')


class TestTLSClient:
    """Test TLS client functionality"""
    
    @pytest.fixture
    def tls_client(self):
        """Fixture for TLS client"""
        config = TLSConfig(
            certfile="security/certs/client.crt",
            keyfile="security/certs/client.key",
            cafile="security/certs/ca.crt"
        )
        
        client = TLSClient(config)
        return client
    
    def test_client_context_creation(self, tls_client):
        """Test client SSL context creation"""
        context = tls_client._create_ssl_context()
        
        assert isinstance(context, ssl.SSLContext)
        assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
    
    def test_client_with_client_cert(self, tls_client):
        """Test client with client certificate"""
        context = tls_client._create_ssl_context()
        
        # Should have client certificate loaded
        # Can't easily verify, but should not raise exception
    
    def test_client_without_client_cert(self):
        """Test client without client certificate"""
        config = TLSConfig(
            cafile="security/certs/ca.crt"
        )
        client = TLSClient(config)
        context = client._create_ssl_context()
        
        assert context.verify_mode == ssl.CERT_REQUIRED
        # No client certificate loaded


class TestTLSConnection:
    """Test complete TLS connection"""
    
    @pytest.fixture
    def tls_echo_server(self):
        """Fixture for TLS echo server"""
        config = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            cafile="security/certs/ca.crt"
        )
        
        server = TLSServer(config)
        
        # Create listening socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 0))
        port = sock.getsockname()[1]
        sock.listen(1)
        
        def echo_handler():
            try:
                client_sock, addr = sock.accept()
                ssl_sock = server.wrap_socket(client_sock)
                
                data = ssl_sock.recv(1024)
                ssl_sock.send(data)
                
                ssl_sock.close()
            except:
                pass
        
        thread = threading.Thread(target=echo_handler, daemon=True)
        thread.start()
        
        yield port
        
        sock.close()
    
    def test_tls_handshake(self, tls_echo_server):
        """Test TLS handshake"""
        port = tls_echo_server
        
        # Client with valid certificate
        client_config = TLSConfig(
            certfile="security/certs/client.crt",
            keyfile="security/certs/client.key",
            cafile="security/certs/ca.crt"
        )
        client = TLSClient(client_config)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = client.wrap_socket(sock, 'localhost')
        ssl_sock.connect(('localhost', port))
        
        assert ssl_sock.version() in ['TLSv1.2', 'TLSv1.3']
        
        ssl_sock.close()
    
    def test_tls_echo(self, tls_echo_server):
        """Test TLS echo"""
        port = tls_echo_server
        
        client_config = TLSConfig(
            certfile="security/certs/client.crt",
            keyfile="security/certs/client.key",
            cafile="security/certs/ca.crt"
        )
        client = TLSClient(client_config)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = client.wrap_socket(sock, 'localhost')
        ssl_sock.connect(('localhost', port))
        
        test_data = b"Hello TLS!"
        ssl_sock.send(test_data)
        response = ssl_sock.recv(1024)
        
        assert response == test_data
        
        ssl_sock.close()
    
    def test_tls_with_invalid_ca(self, tls_echo_server):
        """Test TLS with invalid CA"""
        port = tls_echo_server
        
        # Client with wrong CA
        client_config = TLSConfig(
            certfile="security/certs/client.crt",
            keyfile="security/certs/client.key",
            cafile="security/certs/server.crt"  # Wrong CA!
        )
        client = TLSClient(client_config)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        with pytest.raises(ssl.SSLError):
            ssl_sock = client.wrap_socket(sock, 'localhost')
            ssl_sock.connect(('localhost', port))
    
    def test_tls_without_client_cert(self, tls_echo_server):
        """Test TLS without client certificate"""
        port = tls_echo_server
        
        # Client without certificate (server requires mTLS)
        client_config = TLSConfig(
            cafile="security/certs/ca.crt"
        )
        client = TLSClient(client_config)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Should fail if server requires client certificate
        with pytest.raises(ssl.SSLError):
            ssl_sock = client.wrap_socket(sock, 'localhost')
            ssl_sock.connect(('localhost', port))
    
    def test_tls_protocol_versions(self):
        """Test TLS protocol version negotiation"""
        # Test TLS 1.2
        config_tls12 = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2
        )
        server_tls12 = TLSServer(config_tls12)
        context = server_tls12._create_ssl_context()
        assert context.maximum_version == ssl.TLSVersion.TLSv1_2
        
        # Test TLS 1.3
        config_tls13 = TLSConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3
        )
        server_tls13 = TLSServer(config_tls13)
        context = server_tls13._create_ssl_context()
        assert context.minimum_version == ssl.TLSVersion.TLSv1_3
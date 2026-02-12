"""
NexusRPC TLS 1.3 Security Layer
Complete TLS implementation with mutual authentication
"""

import ssl
import socket
import certifi
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class TLSConfig:
    """TLS configuration with secure defaults"""
    certfile: str
    keyfile: str
    cafile: Optional[str] = None
    verify_mode: str = 'required'  # none, optional, required
    cipher_suites: str = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
    min_version: int = ssl.TLSVersion.TLSv1_2  # TLS 1.2 minimum, prefer 1.3
    max_version: int = ssl.TLSVersion.TLSv1_3
    
    def __post_init__(self):
        if self.min_version < ssl.TLSVersion.TLSv1_2:
            raise ValueError("TLS version below 1.2 is insecure")
        
        # Verify files exist
        for f in [self.certfile, self.keyfile]:
            if not Path(f).exists():
                raise FileNotFoundError(f"TLS file not found: {f}")
        
        if self.cafile and not Path(self.cafile).exists():
            raise FileNotFoundError(f"CA file not found: {self.cafile}")


class TLSServer:
    """TLS 1.3 Server implementation"""
    
    def __init__(self, config: TLSConfig):
        self.config = config
        self.context = self._create_ssl_context()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with secure defaults"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Set minimum/maximum TLS versions
        context.minimum_version = self.config.min_version
        context.maximum_version = self.config.max_version
        
        # Load certificate and private key
        context.load_cert_chain(
            self.config.certfile,
            self.config.keyfile
        )
        
        # Configure verification
        if self.config.verify_mode == 'required':
            context.verify_mode = ssl.CERT_REQUIRED
            if self.config.cafile:
                context.load_verify_locations(self.config.cafile)
            else:
                context.load_verify_locations(certifi.where())
        elif self.config.verify_mode == 'optional':
            context.verify_mode = ssl.CERT_OPTIONAL
        
        # Set secure cipher suites
        context.set_ciphers(self.config.cipher_suites)
        
        # Enable ALPN for protocol negotiation
        context.set_alpn_protocols(['nexusrpc/1', 'http/1.1'])
        
        return context
    
    def wrap_socket(self, sock: socket.socket) -> ssl.SSLSocket:
        """Wrap socket with TLS"""
        return self.context.wrap_socket(sock, server_side=True)
    
    def get_certificate_info(self, ssl_sock: ssl.SSLSocket) -> dict:
        """Extract certificate information"""
        cert = ssl_sock.getpeercert()
        if cert:
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'serial_number': cert['serialNumber'],
                'version': cert.get('version', 'N/A'),
                'tls_version': ssl_sock.version(),
                'cipher': ssl_sock.cipher()
            }
        return {}


class TLSClient:
    """TLS 1.3 Client implementation with mutual authentication"""
    
    def __init__(self, config: TLSConfig):
        self.config = config
        self.context = self._create_ssl_context()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for client"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Set minimum/maximum TLS versions
        context.minimum_version = self.config.min_version
        context.maximum_version = self.config.max_version
        
        # Load client certificate for mTLS
        if self.config.certfile and self.config.keyfile:
            context.load_cert_chain(
                self.config.certfile,
                self.config.keyfile
            )
        
        # Load CA certificates
        if self.config.cafile:
            context.load_verify_locations(self.config.cafile)
        else:
            context.load_verify_locations(certifi.where())
        
        # Require server certificate verification
        if self.config.verify_mode == 'required':
            context.verify_mode = ssl.CERT_REQUIRED
        elif self.config.verify_mode == 'optional':
            context.verify_mode = ssl.CERT_OPTIONAL
        
        # Set secure cipher suites
        context.set_ciphers(self.config.cipher_suites)
        
        # Enable ALPN
        context.set_alpn_protocols(['nexusrpc/1', 'http/1.1'])
        
        # Check hostname
        context.check_hostname = True
        
        return context
    
    def wrap_socket(self, sock: socket.socket, 
                   server_hostname: str) -> ssl.SSLSocket:
        """Wrap socket with TLS"""
        return self.context.wrap_socket(
            sock, 
            server_side=False,
            server_hostname=server_hostname
        )



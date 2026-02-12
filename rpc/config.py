"""
NexusRPC Configuration Management
YAML/JSON/Env configuration with validation
"""

import os
import yaml
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging

from .errors import ConfigurationError, InvalidConfigurationError

logger = logging.getLogger(__name__)


class Environment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


@dataclass
class ServerConfig:
    """Server configuration"""
    host: str = "0.0.0.0"
    port: int = 50051
    max_workers: int = 10
    backlog: int = 128
    socket_timeout: float = 30.0
    shutdown_timeout: float = 10.0
    enable_metrics: bool = True
    enable_tracing: bool = False
    
    def validate(self):
        """Validate server configuration"""
        if self.port < 1 or self.port > 65535:
            raise InvalidConfigurationError(f"Invalid port: {self.port}")
        if self.max_workers < 1:
            raise InvalidConfigurationError(f"Invalid max_workers: {self.max_workers}")
        if self.socket_timeout < 0:
            raise InvalidConfigurationError(f"Invalid timeout: {self.socket_timeout}")


@dataclass
class ClientConfig:
    """Client configuration"""
    pool_size: int = 10
    connection_timeout: float = 5.0
    request_timeout: float = 10.0
    retry_count: int = 3
    retry_backoff: float = 0.1
    max_retry_backoff: float = 2.0
    enable_keepalive: bool = True
    keepalive_interval: float = 30.0
    
    def validate(self):
        """Validate client configuration"""
        if self.pool_size < 1:
            raise InvalidConfigurationError(f"Invalid pool_size: {self.pool_size}")
        if self.retry_count < 0:
            raise InvalidConfigurationError(f"Invalid retry_count: {self.retry_count}")


@dataclass
class TLSConfig:
    """TLS/SSL configuration"""
    enabled: bool = False
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    cafile: Optional[str] = None
    verify_mode: str = "required"
    min_version: str = "TLSv1_2"
    cipher_suites: str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    
    def validate(self):
        """Validate TLS configuration"""
        if self.enabled:
            if not self.certfile or not Path(self.certfile).exists():
                raise InvalidConfigurationError(f"Certificate not found: {self.certfile}")
            if not self.keyfile or not Path(self.keyfile).exists():
                raise InvalidConfigurationError(f"Key file not found: {self.keyfile}")


@dataclass
class AuthConfig:
    """Authentication configuration"""
    enabled: bool = True
    secret_key: Optional[str] = None
    algorithm: str = "HS256"
    access_token_expiry: int = 3600
    refresh_token_expiry: int = 604800
    issuer: str = "nexusrpc"
    audience: str = "nexusrpc-clients"
    
    def __post_init__(self):
        if self.enabled and not self.secret_key:
            self.secret_key = os.environ.get('NEXUSRPC_SECRET_KEY')
            if not self.secret_key:
                logger.warning("No secret key provided, generating random key")
                import secrets
                self.secret_key = secrets.token_urlsafe(32)
    
    def validate(self):
        """Validate auth configuration"""
        if self.enabled and not self.secret_key:
            raise InvalidConfigurationError("Secret key required for authentication")


@dataclass
class DiscoveryConfig:
    """Service discovery configuration"""
    enabled: bool = False
    provider: str = "etcd"  # etcd, consul, memory
    host: str = "localhost"
    port: int = 2379
    ttl: int = 30
    heartbeat_interval: int = 25
    prefix: str = "/nexusrpc/services/"
    
    def validate(self):
        """Validate discovery configuration"""
        if self.enabled:
            if self.provider not in ["etcd", "consul", "memory"]:
                raise InvalidConfigurationError(f"Unknown provider: {self.provider}")


@dataclass
class MonitoringConfig:
    """Monitoring configuration"""
    enable_metrics: bool = True
    metrics_port: int = 9090
    metrics_path: str = "/metrics"
    enable_tracing: bool = False
    tracing_endpoint: Optional[str] = None
    tracing_sample_rate: float = 0.1
    log_level: str = "INFO"
    log_format: str = "json"
    
    def validate(self):
        """Validate monitoring configuration"""
        if self.tracing_sample_rate < 0 or self.tracing_sample_rate > 1:
            raise InvalidConfigurationError(f"Invalid sample rate: {self.tracing_sample_rate}")


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    timeout_duration: float = 10.0
    
    def validate(self):
        """Validate circuit breaker configuration"""
        if self.failure_threshold < 1:
            raise InvalidConfigurationError(f"Invalid failure_threshold: {self.failure_threshold}")
        if self.recovery_timeout < 0:
            raise InvalidConfigurationError(f"Invalid recovery_timeout: {self.recovery_timeout}")


@dataclass
class NexusRPCConfig:
    """Complete NexusRPC configuration"""
    environment: Environment = Environment.DEVELOPMENT
    service_name: str = "nexusrpc"
    service_version: str = "1.0.0"
    
    server: ServerConfig = field(default_factory=ServerConfig)
    client: ClientConfig = field(default_factory=ClientConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    
    def __post_init__(self):
        if isinstance(self.environment, str):
            self.environment = Environment(self.environment)
    
    def validate(self):
        """Validate complete configuration"""
        self.server.validate()
        self.client.validate()
        self.tls.validate()
        self.auth.validate()
        self.discovery.validate()
        self.monitoring.validate()
        self.circuit_breaker.validate()
    
    @classmethod
    def from_file(cls, path: Union[str, Path]) -> 'NexusRPCConfig':
        """Load configuration from YAML/JSON file"""
        path = Path(path)
        
        if not path.exists():
            raise ConfigurationError(f"Config file not found: {path}")
        
        with open(path, 'r') as f:
            if path.suffix in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            elif path.suffix == '.json':
                data = json.load(f)
            else:
                raise ConfigurationError(f"Unsupported file format: {path.suffix}")
        
        return cls.from_dict(data)
    
    @classmethod
    def from_env(cls) -> 'NexusRPCConfig':
        """Load configuration from environment variables"""
        config = cls()
        
        # Server config
        config.server.host = os.environ.get('NEXUSRPC_HOST', config.server.host)
        config.server.port = int(os.environ.get('NEXUSRPC_PORT', config.server.port))
        
        # TLS config
        config.tls.enabled = os.environ.get('NEXUSRPC_TLS_ENABLED', 'false').lower() == 'true'
        config.tls.certfile = os.environ.get('NEXUSRPC_TLS_CERTFILE')
        config.tls.keyfile = os.environ.get('NEXUSRPC_TLS_KEYFILE')
        config.tls.cafile = os.environ.get('NEXUSRPC_TLS_CAFILE')
        
        # Auth config
        config.auth.enabled = os.environ.get('NEXUSRPC_AUTH_ENABLED', 'true').lower() == 'true'
        config.auth.secret_key = os.environ.get('NEXUSRPC_SECRET_KEY')
        
        # Discovery config
        config.discovery.enabled = os.environ.get('NEXUSRPC_DISCOVERY_ENABLED', 'false').lower() == 'true'
        config.discovery.provider = os.environ.get('NEXUSRPC_DISCOVERY_PROVIDER', config.discovery.provider)
        config.discovery.host = os.environ.get('NEXUSRPC_DISCOVERY_HOST', config.discovery.host)
        config.discovery.port = int(os.environ.get('NEXUSRPC_DISCOVERY_PORT', config.discovery.port))
        
        # Environment
        env = os.environ.get('NEXUSRPC_ENVIRONMENT', 'development')
        config.environment = Environment(env)
        
        return config
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NexusRPCConfig':
        """Load configuration from dictionary"""
        config = cls()
        
        if 'environment' in data:
            config.environment = Environment(data['environment'])
        if 'service_name' in data:
            config.service_name = data['service_name']
        if 'service_version' in data:
            config.service_version = data['service_version']
        
        # Load subsections
        if 'server' in data:
            for key, value in data['server'].items():
                if hasattr(config.server, key):
                    setattr(config.server, key, value)
        
        if 'client' in data:
            for key, value in data['client'].items():
                if hasattr(config.client, key):
                    setattr(config.client, key, value)
        
        if 'tls' in data:
            for key, value in data['tls'].items():
                if hasattr(config.tls, key):
                    setattr(config.tls, key, value)
        
        if 'auth' in data:
            for key, value in data['auth'].items():
                if hasattr(config.auth, key):
                    setattr(config.auth, key, value)
        
        if 'discovery' in data:
            for key, value in data['discovery'].items():
                if hasattr(config.discovery, key):
                    setattr(config.discovery, key, value)
        
        if 'monitoring' in data:
            for key, value in data['monitoring'].items():
                if hasattr(config.monitoring, key):
                    setattr(config.monitoring, key, value)
        
        if 'circuit_breaker' in data:
            for key, value in data['circuit_breaker'].items():
                if hasattr(config.circuit_breaker, key):
                    setattr(config.circuit_breaker, key, value)
        
        config.validate()
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'environment': self.environment.value,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'server': asdict(self.server),
            'client': asdict(self.client),
            'tls': asdict(self.tls),
            'auth': asdict(self.auth),
            'discovery': asdict(self.discovery),
            'monitoring': asdict(self.monitoring),
            'circuit_breaker': asdict(self.circuit_breaker)
        }
    
    def to_yaml(self, path: Union[str, Path]):
        """Save configuration to YAML file"""
        with open(path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
    
    def to_json(self, path: Union[str, Path]):
        """Save configuration to JSON file"""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Default configuration YAML template
DEFAULT_CONFIG_YAML = """
# NexusRPC Default Configuration
environment: development
service_name: nexusrpc
service_version: 1.0.0

server:
  host: 0.0.0.0
  port: 50051
  max_workers: 10
  backlog: 128
  socket_timeout: 30.0
  shutdown_timeout: 10.0
  enable_metrics: true
  enable_tracing: false

client:
  pool_size: 10
  connection_timeout: 5.0
  request_timeout: 10.0
  retry_count: 3
  retry_backoff: 0.1
  max_retry_backoff: 2.0
  enable_keepalive: true
  keepalive_interval: 30.0

tls:
  enabled: false
  certfile: null
  keyfile: null
  cafile: null
  verify_mode: required
  min_version: TLSv1_2
  cipher_suites: TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

auth:
  enabled: true
  secret_key: null
  algorithm: HS256
  access_token_expiry: 3600
  refresh_token_expiry: 604800
  issuer: nexusrpc
  audience: nexusrpc-clients

discovery:
  enabled: false
  provider: etcd
  host: localhost
  port: 2379
  ttl: 30
  heartbeat_interval: 25
  prefix: /nexusrpc/services/

monitoring:
  enable_metrics: true
  metrics_port: 9090
  metrics_path: /metrics
  enable_tracing: false
  tracing_endpoint: null
  tracing_sample_rate: 0.1
  log_level: INFO
  log_format: json

circuit_breaker:
  enabled: true
  failure_threshold: 5
  recovery_timeout: 30.0
  half_open_max_calls: 3
  timeout_duration: 10.0
"""
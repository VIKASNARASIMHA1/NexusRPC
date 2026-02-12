"""
NexusRPC Service Discovery - Factory Module
Unified interface for all registry implementations
"""

from typing import Optional
import logging

from .registry import ServiceRegistry
from .etcd import EtcdServiceRegistry
from .consul import ConsulServiceRegistry
from .memory import InMemoryRegistry
from ..rpc.config import DiscoveryConfig
from ..rpc.errors import ConfigurationError

logger = logging.getLogger(__name__)


class RegistryFactory:
    """Factory for creating service registry instances"""
    
    @staticmethod
    def create_registry(config: DiscoveryConfig) -> Optional[ServiceRegistry]:
        """
        Create registry instance based on configuration
        
        Args:
            config: Discovery configuration
            
        Returns:
            ServiceRegistry instance or None if disabled
        """
        if not config.enabled:
            logger.info("Service discovery disabled")
            return None
        
        provider = config.provider.lower()
        
        if provider == 'etcd':
            try:
                registry = EtcdServiceRegistry(
                    host=config.host,
                    port=config.port,
                    timeout=5
                )
                logger.info(f"Created etcd registry at {config.host}:{config.port}")
                return registry
                
            except Exception as e:
                logger.error(f"Failed to create etcd registry: {e}")
                raise ConfigurationError(f"etcd registry creation failed: {e}")
        
        elif provider == 'consul':
            try:
                registry = ConsulServiceRegistry(
                    host=config.host,
                    port=config.port or 8500
                )
                logger.info(f"Created Consul registry at {config.host}:{config.port}")
                return registry
                
            except Exception as e:
                logger.error(f"Failed to create Consul registry: {e}")
                raise ConfigurationError(f"Consul registry creation failed: {e}")
        
        elif provider == 'memory':
            registry = InMemoryRegistry()
            logger.info("Created in-memory registry (development only)")
            return registry
        
        else:
            raise ConfigurationError(f"Unknown registry provider: {provider}")


# Export main classes
__all__ = [
    'ServiceRegistry',
    'EtcdServiceRegistry', 
    'ConsulServiceRegistry',
    'InMemoryRegistry',
    'RegistryFactory'
]
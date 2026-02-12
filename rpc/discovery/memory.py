"""
NexusRPC Service Discovery Module

This module provides service discovery capabilities for NexusRPC,
supporting multiple registry backends:

- etcd: Distributed key-value store for production
- Consul: HashiCorp's service mesh solution
- In-Memory: Development and testing

The module follows the abstract factory pattern, allowing easy
switching between different registry implementations.
"""

from .registry import (
    ServiceRegistry,
    ServiceRegistryError,
    RegistryUnavailableError,
    RegistrationFailedError,
    DeregistrationFailedError,
    InstanceNotFoundError,
    ServiceNotFoundError,
    HeartbeatFailedError,
    WatchError
)

from .models import (
    ServiceInstance,
    ServiceEndpoint,
    ServiceHealth,
    ServiceRegistration,
    ServiceQuery
)

from .etcd import EtcdServiceRegistry
from .consul import ConsulServiceRegistry
from .memory import InMemoryRegistry


class RegistryFactory:
    """
    Factory for creating service registry instances.
    
    This factory abstracts the creation of different registry backends,
    allowing the application to switch between implementations without
    changing code.
    
    Example:
        >>> config = DiscoveryConfig(
        ...     enabled=True,
        ...     provider="etcd",
        ...     host="localhost",
        ...     port=2379
        ... )
        >>> registry = RegistryFactory.create_registry(config)
        >>> registry.register(instance)
    """
    
    @staticmethod
    def create_registry(config) -> ServiceRegistry:
        """
        Create a registry instance based on configuration.
        
        Args:
            config: DiscoveryConfig object with provider settings
            
        Returns:
            ServiceRegistry: Configured registry instance
            
        Raises:
            ConfigurationError: If provider is unknown or configuration invalid
            
        Example:
            >>> from rpc.config import DiscoveryConfig
            >>> config = DiscoveryConfig(
            ...     enabled=True,
            ...     provider="memory"
            ... )
            >>> registry = RegistryFactory.create_registry(config)
        """
        if not config.enabled:
            logger.info("Service discovery disabled")
            return None
        
        provider = config.provider.lower()
        
        if provider == 'etcd':
            return EtcdServiceRegistry(
                host=config.host,
                port=config.port,
                timeout=5
            )
        elif provider == 'consul':
            return ConsulServiceRegistry(
                host=config.host,
                port=config.port or 8500
            )
        elif provider == 'memory':
            return InMemoryRegistry(
                cleanup_interval=config.ttl
            )
        else:
            raise ConfigurationError(f"Unknown registry provider: {provider}")


__all__ = [
    # Abstract interfaces
    'ServiceRegistry',
    'ServiceRegistryError',
    'RegistryUnavailableError',
    'RegistrationFailedError',
    'DeregistrationFailedError',
    'InstanceNotFoundError',
    'ServiceNotFoundError',
    'HeartbeatFailedError',
    'WatchError',
    
    # Data models
    'ServiceInstance',
    'ServiceEndpoint',
    'ServiceHealth',
    'ServiceRegistration',
    'ServiceQuery',
    
    # Implementations
    'EtcdServiceRegistry',
    'ConsulServiceRegistry',
    'InMemoryRegistry',
    
    # Factory
    'RegistryFactory'
]

import logging
logger = logging.getLogger(__name__)
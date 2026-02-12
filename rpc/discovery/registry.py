"""
NexusRPC Service Discovery - Abstract Registry Interface
Defines the contract for all service registry implementations

This module provides the abstract base class that all service registry
implementations (etcd, Consul, memory, etc.) must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime
import logging

from .models import ServiceInstance, ServiceHealth, ServiceEndpoint

logger = logging.getLogger(__name__)


class ServiceRegistry(ABC):
    """
    Abstract base class for service registries.
    
    All registry implementations must inherit from this class and implement
    all abstract methods. This ensures consistent behavior across different
    registry backends (etcd, Consul, in-memory, etc.).
    
    Features:
    - Service registration/deregistration
    - Health checking via heartbeats
    - Service discovery with filtering
    - Watch notifications for service changes
    - Service listing
    """
    
    @abstractmethod
    def register(self, instance: ServiceInstance) -> bool:
        """
        Register a service instance with the registry.
        
        Args:
            instance: ServiceInstance object containing service metadata,
                     endpoints, and health status
                     
        Returns:
            bool: True if registration successful, False otherwise
            
        Example:
            >>> instance = ServiceInstance(
            ...     id="auth-service-1",
            ...     name="auth-service",
            ...     version="1.0.0",
            ...     endpoints=[ServiceEndpoint("tcp", "192.168.1.10", 50051)]
            ... )
            >>> registry.register(instance)
            True
        """
        pass
    
    @abstractmethod
    def deregister(self, service_name: str, instance_id: str) -> bool:
        """
        Deregister a service instance.
        
        Args:
            service_name: Name of the service
            instance_id: Unique identifier of the instance to deregister
            
        Returns:
            bool: True if deregistration successful, False otherwise
            
        Example:
            >>> registry.deregister("auth-service", "auth-service-1")
            True
        """
        pass
    
    @abstractmethod
    def heartbeat(self, instance: ServiceInstance) -> bool:
        """
        Send heartbeat for a service instance.
        
        This method should be called periodically by registered services
        to indicate they are still healthy. If a heartbeat is not received
        within the TTL window, the instance may be marked as unhealthy.
        
        Args:
            instance: ServiceInstance to send heartbeat for
            
        Returns:
            bool: True if heartbeat successful, False otherwise
            
        Example:
            >>> while True:
            ...     registry.heartbeat(instance)
            ...     time.sleep(25)  # Heartbeat every 25 seconds
        """
        pass
    
    @abstractmethod
    def discover(self, service_name: str, healthy_only: bool = True) -> List[ServiceInstance]:
        """
        Discover all instances of a service.
        
        Args:
            service_name: Name of the service to discover
            healthy_only: If True, only return healthy instances (default: True)
            
        Returns:
            List[ServiceInstance]: List of service instances, empty list if none found
            
        Example:
            >>> instances = registry.discover("auth-service")
            >>> for instance in instances:
            ...     print(f"{instance.id} at {instance.endpoints[0].address}")
        """
        pass
    
    @abstractmethod
    def watch(self, service_name: str, callback: Callable[[str, List[ServiceInstance]], None]):
        """
        Watch for changes to a service.
        
        The callback will be invoked whenever the service's instances change
        (registration, deregistration, health status changes).
        
        Args:
            service_name: Name of the service to watch
            callback: Function to call when service changes.
                     Signature: callback(service_name: str, instances: List[ServiceInstance])
                     
        Example:
            >>> def on_change(service, instances):
            ...     print(f"Service {service} has {len(instances)} instances")
            >>> registry.watch("auth-service", on_change)
        """
        pass
    
    @abstractmethod
    def list_services(self) -> List[str]:
        """
        List all registered service names.
        
        Returns:
            List[str]: Names of all registered services
            
        Example:
            >>> services = registry.list_services()
            >>> print(f"Registered services: {services}")
            Registered services: ['auth-service', 'user-service', 'payment-service']
        """
        pass
    
    def get_instance(self, service_name: str, instance_id: str) -> Optional[ServiceInstance]:
        """
        Get a specific service instance by ID.
        
        Default implementation uses discover() and filters. Override for
        optimized implementation.
        
        Args:
            service_name: Name of the service
            instance_id: ID of the instance to retrieve
            
        Returns:
            Optional[ServiceInstance]: The service instance or None if not found
        """
        instances = self.discover(service_name, healthy_only=False)
        for instance in instances:
            if instance.id == instance_id:
                return instance
        return None
    
    def get_healthy_instances(self, service_name: str) -> List[ServiceInstance]:
        """
        Get only healthy instances of a service.
        
        Convenience method equivalent to discover(service_name, healthy_only=True).
        
        Args:
            service_name: Name of the service
            
        Returns:
            List[ServiceInstance]: List of healthy instances
        """
        return self.discover(service_name, healthy_only=True)
    
    def get_instance_count(self, service_name: str, healthy_only: bool = True) -> int:
        """
        Get the number of instances for a service.
        
        Args:
            service_name: Name of the service
            healthy_only: If True, only count healthy instances
            
        Returns:
            int: Number of instances
        """
        return len(self.discover(service_name, healthy_only))
    
    def is_healthy(self, service_name: str, instance_id: str) -> bool:
        """
        Check if a specific instance is healthy.
        
        Args:
            service_name: Name of the service
            instance_id: ID of the instance
            
        Returns:
            bool: True if instance exists and is healthy
        """
        instance = self.get_instance(service_name, instance_id)
        return instance is not None and instance.is_healthy()


class ServiceRegistryError(Exception):
    """Base exception for all service registry errors."""
    pass


class RegistryUnavailableError(ServiceRegistryError):
    """
    Raised when the registry backend is unavailable.
    
    This can happen if etcd/Consul is down, network issues, or
    connection refused.
    """
    def __init__(self, message: str = "Registry service unavailable"):
        self.message = message
        super().__init__(self.message)


class RegistrationFailedError(ServiceRegistryError):
    """
    Raised when service registration fails.
    
    This can happen due to invalid parameters, permission issues,
    or backend-specific errors.
    """
    def __init__(self, message: str = "Service registration failed"):
        self.message = message
        super().__init__(self.message)


class DeregistrationFailedError(ServiceRegistryError):
    """
    Raised when service deregistration fails.
    """
    def __init__(self, message: str = "Service deregistration failed"):
        self.message = message
        super().__init__(self.message)


class InstanceNotFoundError(ServiceRegistryError):
    """
    Raised when a requested service instance cannot be found.
    """
    def __init__(self, service_name: str, instance_id: str):
        self.service_name = service_name
        self.instance_id = instance_id
        self.message = f"Instance {instance_id} not found for service {service_name}"
        super().__init__(self.message)


class ServiceNotFoundError(ServiceRegistryError):
    """
    Raised when a requested service cannot be found.
    """
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.message = f"Service {service_name} not found"
        super().__init__(self.message)


class HeartbeatFailedError(ServiceRegistryError):
    """
    Raised when sending a heartbeat fails.
    """
    def __init__(self, message: str = "Heartbeat failed"):
        self.message = message
        super().__init__(self.message)


class WatchError(ServiceRegistryError):
    """
    Raised when watching for service changes fails.
    """
    def __init__(self, message: str = "Watch operation failed"):
        self.message = message
        super().__init__(self.message)
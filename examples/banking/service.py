"""
NexusRPC Service Discovery - In-Memory Registry
Development-only registry with TTL-based health checking
"""

import threading
import time
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
import logging

from .registry import ServiceRegistry
from .models import ServiceInstance

logger = logging.getLogger(__name__)


class InMemoryRegistry(ServiceRegistry):
    """
    In-memory service registry for development and testing
    
    Features:
    - Thread-safe operations
    - TTL-based health checking
    - Watch notifications
    - No external dependencies
    """
    
    def __init__(self, cleanup_interval: int = 30):
        """
        Initialize in-memory registry
        
        Args:
            cleanup_interval: Seconds between cleanup of expired instances
        """
        self.services: Dict[str, Dict[str, ServiceInstance]] = {}
        self.heartbeats: Dict[str, datetime] = {}
        self.watchers: Dict[str, List[Callable]] = {}
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.cleanup_interval = cleanup_interval
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("InMemoryRegistry initialized (development only)")
    
    def register(self, instance: ServiceInstance) -> bool:
        """
        Register a service instance
        
        Args:
            instance: Service instance to register
            
        Returns:
            True if registration successful
        """
        with self.lock:
            # Create service entry if not exists
            if instance.name not in self.services:
                self.services[instance.name] = {}
            
            # Store instance
            self.services[instance.name][instance.id] = instance
            
            # Initialize heartbeat
            self.heartbeats[instance.id] = datetime.utcnow()
            
            logger.debug(f"Registered {instance.name}/{instance.id}")
            
            # Notify watchers
            self._notify_watchers(instance.name)
            
            return True
    
    def deregister(self, service_name: str, instance_id: str) -> bool:
        """
        Deregister a service instance
        
        Args:
            service_name: Name of the service
            instance_id: ID of the instance to deregister
            
        Returns:
            True if deregistration successful
        """
        with self.lock:
            if service_name in self.services:
                if instance_id in self.services[service_name]:
                    del self.services[service_name][instance_id]
                    
                    # Clean up empty service
                    if not self.services[service_name]:
                        del self.services[service_name]
                    
                    # Remove heartbeat
                    if instance_id in self.heartbeats:
                        del self.heartbeats[instance_id]
                    
                    logger.debug(f"Deregistered {service_name}/{instance_id}")
                    
                    # Notify watchers
                    self._notify_watchers(service_name)
                    
                    return True
        return False
    
    def heartbeat(self, instance: ServiceInstance) -> bool:
        """
        Send heartbeat for service instance
        
        Args:
            instance: Service instance to heartbeat
            
        Returns:
            True if heartbeat successful
        """
        with self.lock:
            instance_id = instance.id
            self.heartbeats[instance_id] = datetime.utcnow()
            
            # Update instance if it exists
            if instance.name in self.services and instance_id in self.services[instance.name]:
                self.services[instance.name][instance_id] = instance
            
            return True
    
    def discover(self, service_name: str, healthy_only: bool = True) -> List[ServiceInstance]:
        """
        Discover service instances
        
        Args:
            service_name: Name of the service to discover
            healthy_only: If True, only return healthy instances
            
        Returns:
            List of service instances
        """
        with self.lock:
            if service_name not in self.services:
                return []
            
            instances = []
            now = datetime.utcnow()
            
            for instance_id, instance in self.services[service_name].items():
                if healthy_only:
                    # Check if instance is healthy
                    last_heartbeat = self.heartbeats.get(instance_id)
                    if last_heartbeat:
                        # Consider unhealthy if no heartbeat for 60 seconds
                        if (now - last_heartbeat).total_seconds() > 60:
                            continue
                    
                    # Check instance status
                    if instance.status != 'healthy':
                        continue
                
                instances.append(instance)
            
            return instances
    
    def watch(self, service_name: str, callback: Callable):
        """
        Watch for service changes
        
        Args:
            service_name: Name of the service to watch
            callback: Function to call when service changes
                     Signature: callback(service_name, instances)
        """
        with self.lock:
            if service_name not in self.watchers:
                self.watchers[service_name] = []
            
            self.watchers[service_name].append(callback)
            logger.debug(f"Added watcher for {service_name}")
    
    def list_services(self) -> List[str]:
        """
        List all registered services
        
        Returns:
            List of service names
        """
        with self.lock:
            return list(self.services.keys())
    
    def get_instance(self, service_name: str, instance_id: str) -> Optional[ServiceInstance]:
        """
        Get specific service instance
        
        Args:
            service_name: Name of the service
            instance_id: ID of the instance
            
        Returns:
            Service instance or None if not found
        """
        with self.lock:
            if service_name in self.services:
                return self.services[service_name].get(instance_id)
            return None
    
    def _cleanup_loop(self):
        """Background thread to clean up expired instances"""
        while self.running:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_expired()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    def _cleanup_expired(self):
        """Remove expired service instances"""
        with self.lock:
            now = datetime.utcnow()
            expired = []
            
            # Find expired instances
            for instance_id, last_heartbeat in self.heartbeats.items():
                if (now - last_heartbeat).total_seconds() > 60:
                    expired.append(instance_id)
            
            # Remove expired instances
            for instance_id in expired:
                for service_name in list(self.services.keys()):
                    if instance_id in self.services[service_name]:
                        logger.info(f"Removing expired instance {instance_id} from {service_name}")
                        del self.services[service_name][instance_id]
                        
                        # Clean up empty service
                        if not self.services[service_name]:
                            del self.services[service_name]
                        
                        # Remove heartbeat
                        del self.heartbeats[instance_id]
                        
                        # Notify watchers
                        self._notify_watchers(service_name)
    
    def _notify_watchers(self, service_name: str):
        """
        Notify all watchers of service change
        
        Args:
            service_name: Name of the changed service
        """
        if service_name in self.watchers:
            instances = self.discover(service_name)
            for callback in self.watchers[service_name]:
                try:
                    callback(service_name, instances)
                except Exception as e:
                    logger.error(f"Watcher callback failed: {e}")
    
    def clear(self):
        """Clear all registrations (for testing)"""
        with self.lock:
            self.services.clear()
            self.heartbeats.clear()
            logger.debug("Registry cleared")
    
    def stop(self):
        """Stop the registry"""
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        logger.info("InMemoryRegistry stopped")
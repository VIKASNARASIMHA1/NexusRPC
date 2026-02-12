"""
NexusRPC Service Discovery - etcd Implementation
High-availability service registry using etcd
"""

import etcd3
import json
import asyncio
from typing import Dict, List, Optional, Callable
from datetime import datetime
import threading
import logging
from .models import ServiceInstance, ServiceHealth

logger = logging.getLogger(__name__)


class EtcdServiceRegistry:
    """
    etcd-based service registry with TTL-based health checking
    """
    
    def __init__(self, host='localhost', port=2379, timeout=5):
        self.client = etcd3.client(host=host, port=port, timeout=timeout)
        self.prefix = '/nexusrpc/services/'
        self.lease_ttl = 30  # 30 seconds TTL
        self._watch_threads = []
        self._watchers = {}
    
    def register(self, instance: ServiceInstance) -> bool:
        """Register a service instance with TTL lease"""
        try:
            # Create lease
            lease = self.client.lease(self.lease_ttl, instance.id)
            
            # Store instance metadata
            key = f"{self.prefix}{instance.name}/{instance.id}"
            value = json.dumps(instance.to_dict())
            
            # Put with lease
            self.client.put(key, value, lease=lease)
            
            # Store lease ID for heartbeating
            instance.metadata['lease_id'] = lease.id
            
            logger.info(f"Registered {instance.name} at {instance.address}:{instance.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register {instance.name}: {e}")
            return False
    
    def deregister(self, service_name: str, instance_id: str) -> bool:
        """Deregister a service instance"""
        try:
            key = f"{self.prefix}{service_name}/{instance_id}"
            self.client.delete(key)
            logger.info(f"Deregistered {service_name}/{instance_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to deregister: {e}")
            return False
    
    def heartbeat(self, instance: ServiceInstance) -> bool:
        """Send heartbeat to maintain lease"""
        try:
            lease_id = instance.metadata.get('lease_id')
            if lease_id:
                self.client.lease_refresh(lease_id)
                return True
        except Exception as e:
            logger.warning(f"Heartbeat failed for {instance.id}: {e}")
        return False
    
    def discover(self, service_name: str) -> List[ServiceInstance]:
        """Discover all healthy instances of a service"""
        instances = []
        key = f"{self.prefix}{service_name}/"
        
        try:
            # Get all instances under service key
            for value, metadata in self.client.get_prefix(key):
                data = json.loads(value)
                instance = ServiceInstance.from_dict(data)
                
                # Check if still alive (lease exists)
                if self._is_alive(metadata.lease_id):
                    instances.append(instance)
            
            return instances
            
        except Exception as e:
            logger.error(f"Discovery failed for {service_name}: {e}")
            return []
    
    def _is_alive(self, lease_id) -> bool:
        """Check if lease is still active"""
        try:
            # Try to refresh lease to check if it exists
            self.client.lease_refresh(lease_id)
            return True
        except:
            return False
    
    def watch(self, service_name: str, callback: Callable):
        """Watch for service changes"""
        key = f"{self.prefix}{service_name}/"
        
        def watch_callback(event):
            if event.events:
                instances = self.discover(service_name)
                callback(service_name, instances)
        
        watch_id = self.client.add_watch_prefix_callback(key, watch_callback)
        self._watchers[service_name] = watch_id
        
        return watch_id
    
    def stop_watch(self, service_name: str):
        """Stop watching a service"""
        if service_name in self._watchers:
            self.client.cancel_watch(self._watchers[service_name])
            del self._watchers[service_name]
    
    def list_services(self) -> List[str]:
        """List all registered services"""
        services = set()
        
        try:
            for value, metadata in self.client.get_prefix(self.prefix):
                # Extract service name from key
                key = metadata.key.decode()
                parts = key[len(self.prefix):].split('/')
                if len(parts) >= 1:
                    services.add(parts[0])
            
            return list(services)
            
        except Exception as e:
            logger.error(f"Failed to list services: {e}")
            return []


class InMemoryRegistry:
    """In-memory registry for development"""
    
    def __init__(self):
        self.services = {}  # service_name -> {instance_id -> instance}
        self.health_status = {}  # instance_id -> timestamp
        self.lock = threading.Lock()
    
    def register(self, instance: ServiceInstance) -> bool:
        with self.lock:
            if instance.name not in self.services:
                self.services[instance.name] = {}
            
            self.services[instance.name][instance.id] = instance
            self.health_status[instance.id] = datetime.utcnow()
            
            logger.info(f"[DEV] Registered {instance.name} at {instance.address}:{instance.port}")
            return True
    
    def deregister(self, service_name: str, instance_id: str) -> bool:
        with self.lock:
            if service_name in self.services:
                if instance_id in self.services[service_name]:
                    del self.services[service_name][instance_id]
                    del self.health_status[instance_id]
                    return True
        return False
    
    def discover(self, service_name: str) -> List[ServiceInstance]:
        with self.lock:
            if service_name not in self.services:
                return []
            
            # Filter instances that have heartbeat in last 60 seconds
            now = datetime.utcnow()
            instances = []
            
            for instance in self.services[service_name].values():
                last_heartbeat = self.health_status.get(instance.id)
                if last_heartbeat:
                    delta = (now - last_heartbeat).total_seconds()
                    if delta < 60:  # 60 seconds TTL
                        instances.append(instance)
            
            return instances
    
    def heartbeat(self, instance: ServiceInstance) -> bool:
        with self.lock:
            self.health_status[instance.id] = datetime.utcnow()
            return True
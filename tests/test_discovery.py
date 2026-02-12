"""
Tests for service discovery
"""

import pytest
import time
from discovery.memory import InMemoryRegistry
from discovery.models import ServiceInstance, ServiceEndpoint


class TestInMemoryRegistry:
    """Test in-memory service registry"""
    
    def setup_method(self):
        self.registry = InMemoryRegistry()
        
        self.instance = ServiceInstance(
            id="test-1",
            name="test-service",
            version="1.0.0",
            endpoints=[
                ServiceEndpoint(
                    protocol="tcp",
                    address="localhost",
                    port=8080
                )
            ]
        )
    
    def test_register_discover(self):
        """Test registration and discovery"""
        # Register
        assert self.registry.register(self.instance) is True
        
        # Discover
        instances = self.registry.discover("test-service")
        assert len(instances) == 1
        assert instances[0].id == self.instance.id
        assert instances[0].name == self.instance.name
    
    def test_heartbeat(self):
        """Test heartbeat mechanism"""
        self.registry.register(self.instance)
        
        # Initial discovery
        instances = self.registry.discover("test-service")
        assert len(instances) == 1
        
        # Wait for TTL
        time.sleep(65)
        
        # Should be removed
        instances = self.registry.discover("test-service")
        assert len(instances) == 0
        
        # Send heartbeat
        self.registry.heartbeat(self.instance)
        
        # Should be available again
        instances = self.registry.discover("test-service")
        assert len(instances) == 1
    
    def test_deregister(self):
        """Test deregistration"""
        self.registry.register(self.instance)
        
        instances = self.registry.discover("test-service")
        assert len(instances) == 1
        
        self.registry.deregister("test-service", self.instance.id)
        
        instances = self.registry.discover("test-service")
        assert len(instances) == 0
    
    def test_list_services(self):
        """Test listing services"""
        # Register multiple services
        service_names = ["service1", "service2", "service3"]
        
        for name in service_names:
            instance = ServiceInstance(
                id=f"{name}-1",
                name=name,
                endpoints=[ServiceEndpoint(protocol="tcp", address="localhost", port=8080)]
            )
            self.registry.register(instance)
        
        services = self.registry.list_services()
        assert set(services) == set(service_names)
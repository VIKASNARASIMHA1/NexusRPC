"""
NexusRPC Service Discovery - Consul Implementation
Hashicorp Consul integration for service registry
"""

import json
import socket
import requests
from typing import Dict, List, Optional, Callable
from datetime import datetime
import threading
import logging

from .models import ServiceInstance, ServiceEndpoint, ServiceHealth
from .registry import ServiceRegistry
from ..rpc.errors import DiscoveryError, RegistryUnavailableError

logger = logging.getLogger(__name__)


class ConsulServiceRegistry(ServiceRegistry):
    """
    Consul-based service registry
    Implements ServiceRegistry interface for Hashicorp Consul
    """
    
    def __init__(self, host='localhost', port=8500, datacenter=None, token=None):
        self.host = host
        self.port = port
        self.datacenter = datacenter
        self.token = token
        self.base_url = f"http://{host}:{port}/v1"
        self.session_id = None
        self._watch_callbacks = {}
        self._watch_threads = []
        
        # Test connection
        self._check_connection()
    
    def _check_connection(self):
        """Check Consul connectivity"""
        try:
            response = requests.get(f"{self.base_url}/status/leader", timeout=2)
            if response.status_code != 200:
                raise RegistryUnavailableError(f"Consul not available: {response.status_code}")
            logger.info(f"Connected to Consul at {self.host}:{self.port}")
        except requests.exceptions.RequestException as e:
            raise RegistryUnavailableError(f"Cannot connect to Consul: {e}")
    
    def _headers(self) -> Dict:
        """Get request headers"""
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['X-Consul-Token'] = self.token
        return headers
    
    def register(self, instance: ServiceInstance) -> bool:
        """
        Register service with Consul
        https://www.consul.io/api-docs/agent/service#register-service
        """
        try:
            # Get primary endpoint
            endpoint = instance.get_primary_endpoint()
            if not endpoint:
                raise DiscoveryError("No endpoints configured")
            
            # Build Consul service registration
            registration = {
                'ID': instance.id,
                'Name': instance.name,
                'Address': endpoint.address,
                'Port': endpoint.port,
                'Meta': {
                    'version': instance.version,
                    **instance.metadata
                },
                'Tags': [f"version-{instance.version}"],
                'Check': {
                    'Name': 'Service Health Check',
                    'TCP': f"{endpoint.address}:{endpoint.port}",
                    'Interval': '30s',
                    'Timeout': '5s',
                    'DeregisterCriticalServiceAfter': '1m'
                }
            }
            
            # Add additional endpoints as checks
            for i, ep in enumerate(instance.endpoints[1:], 1):
                check_id = f"{instance.id}-{ep.protocol}-{i}"
                registration[f'Check{i}'] = {
                    'ID': check_id,
                    'Name': f'{ep.protocol} endpoint',
                    'TCP': f"{ep.address}:{ep.port}",
                    'Interval': '30s',
                    'Timeout': '5s'
                }
            
            response = requests.put(
                f"{self.base_url}/agent/service/register",
                headers=self._headers(),
                json=registration
            )
            
            if response.status_code == 200:
                instance.last_heartbeat = datetime.utcnow()
                logger.info(f"Registered {instance.name} ({instance.id}) with Consul")
                return True
            else:
                raise DiscoveryError(f"Registration failed: {response.text}")
                
        except Exception as e:
            logger.error(f"Failed to register with Consul: {e}")
            return False
    
    def deregister(self, service_name: str, instance_id: str) -> bool:
        """Deregister service from Consul"""
        try:
            response = requests.put(
                f"{self.base_url}/agent/service/deregister/{instance_id}",
                headers=self._headers()
            )
            
            if response.status_code == 200:
                logger.info(f"Deregistered {instance_id} from Consul")
                return True
            else:
                logger.error(f"Deregistration failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to deregister from Consul: {e}")
            return False
    
    def heartbeat(self, instance: ServiceInstance) -> bool:
        """Send TTL heartbeat (Consul handles via TCP checks)"""
        instance.last_heartbeat = datetime.utcnow()
        return True
    
    def discover(self, service_name: str, healthy_only: bool = True) -> List[ServiceInstance]:
        """Discover service instances from Consul"""
        instances = []
        
        try:
            # Query Consul catalog
            url = f"{self.base_url}/catalog/service/{service_name}"
            if self.datacenter:
                url += f"?dc={self.datacenter}"
            
            response = requests.get(url, headers=self._headers())
            
            if response.status_code != 200:
                logger.error(f"Discovery failed: {response.status_code}")
                return []
            
            services = response.json()
            
            for service in services:
                # Check health if requested
                if healthy_only:
                    health_url = f"{self.base_url}/health/checks/{service_name}"
                    health_response = requests.get(health_url, headers=self._headers())
                    
                    if health_response.status_code == 200:
                        checks = health_response.json()
                        service_checks = [c for c in checks if c['ServiceID'] == service['ServiceID']]
                        
                        # Check if all checks passing
                        all_healthy = all(c['Status'] == 'passing' for c in service_checks)
                        if not all_healthy:
                            continue
                
                # Convert to ServiceInstance
                instance = ServiceInstance(
                    id=service['ServiceID'],
                    name=service['ServiceName'],
                    version=service.get('ServiceMeta', {}).get('version', '1.0.0'),
                    endpoints=[
                        ServiceEndpoint(
                            protocol='tcp',
                            address=service['ServiceAddress'] or service['Address'],
                            port=service['ServicePort']
                        )
                    ],
                    status='healthy',
                    metadata=service.get('ServiceMeta', {}),
                    registered_at=datetime.utcnow()  # Consul doesn't provide registration time
                )
                
                instances.append(instance)
            
            logger.debug(f"Discovered {len(instances)} instances for {service_name}")
            
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
        
        return instances
    
    def watch(self, service_name: str, callback: Callable):
        """Watch for service changes using Consul blocking queries"""
        
        def watch_loop():
            index = 0
            while True:
                try:
                    # Blocking query
                    url = f"{self.base_url}/health/service/{service_name}?passing&index={index}&wait=30s"
                    response = requests.get(url, headers=self._headers(), timeout=35)
                    
                    if response.status_code == 200:
                        index = int(response.headers.get('X-Consul-Index', index))
                        instances = self.discover(service_name)
                        callback(service_name, instances)
                        
                except requests.Timeout:
                    # Expected timeout, continue watching
                    continue
                except Exception as e:
                    logger.error(f"Watch error: {e}")
                    time.sleep(5)  # Backoff
        
        thread = threading.Thread(target=watch_loop, daemon=True)
        thread.start()
        self._watch_threads.append(thread)
        
        logger.info(f"Started watching {service_name}")
    
    def list_services(self) -> List[str]:
        """List all registered services from Consul"""
        try:
            response = requests.get(f"{self.base_url}/catalog/services", headers=self._headers())
            
            if response.status_code == 200:
                services = response.json()
                return list(services.keys())
            else:
                logger.error(f"Failed to list services: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to list services: {e}")
            return []
    
    def get_service_health(self, service_name: str) -> List[ServiceHealth]:
        """Get health status for all instances of a service"""
        health_status = []
        
        try:
            url = f"{self.base_url}/health/service/{service_name}"
            response = requests.get(url, headers=self._headers())
            
            if response.status_code == 200:
                entries = response.json()
                
                for entry in entries:
                    service = entry['Service']
                    checks = entry['Checks']
                    
                    # Calculate aggregate health
                    all_passing = all(c['Status'] == 'passing' for c in checks)
                    status = 'healthy' if all_passing else 'unhealthy'
                    
                    health_status.append(ServiceHealth(
                        instance_id=service['ID'],
                        service_name=service['Service'],
                        status=status,
                        latency_ms=0,  # Consul doesn't provide latency
                        error_rate=0.0,
                        connections=0,
                        details={'checks': checks}
                    ))
            
        except Exception as e:
            logger.error(f"Failed to get health: {e}")
        
        return health_status
    
    def create_session(self, ttl: int = 30) -> str:
        """Create Consul session for locking"""
        try:
            payload = {
                'Name': 'nexusrpc-session',
                'TTL': f'{ttl}s',
                'Behavior': 'delete',
                'LockDelay': '15s'
            }
            
            response = requests.put(
                f"{self.base_url}/session/create",
                headers=self._headers(),
                json=payload
            )
            
            if response.status_code == 200:
                self.session_id = response.json()['ID']
                logger.info(f"Created Consul session: {self.session_id}")
                return self.session_id
            else:
                raise DiscoveryError(f"Session creation failed: {response.text}")
                
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None
    
    def acquire_lock(self, key: str, session_id: str = None) -> bool:
        """Acquire distributed lock"""
        session = session_id or self.session_id
        if not session:
            session = self.create_session()
        
        try:
            url = f"{self.base_url}/kv/{key}?acquire={session}"
            response = requests.put(url, headers=self._headers(), json={'lock': 'true'})
            
            if response.status_code == 200:
                return response.json() is True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Failed to acquire lock: {e}")
            return False
    
    def release_lock(self, key: str, session_id: str = None) -> bool:
        """Release distributed lock"""
        session = session_id or self.session_id
        if not session:
            return False
        
        try:
            url = f"{self.base_url}/kv/{key}?release={session}"
            response = requests.put(url, headers=self._headers())
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Failed to release lock: {e}")
            return False
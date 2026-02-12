"""
NexusRPC Service Discovery Models
Data structures for service registration and discovery
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import uuid


@dataclass
class ServiceEndpoint:
    """Service endpoint information"""
    protocol: str  # tcp, tls, http, grpc
    address: str
    port: int
    weight: int = 1
    metadata: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'protocol': self.protocol,
            'address': self.address,
            'port': self.port,
            'weight': self.weight,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ServiceEndpoint':
        return cls(
            protocol=data['protocol'],
            address=data['address'],
            port=data['port'],
            weight=data.get('weight', 1),
            metadata=data.get('metadata', {})
        )


@dataclass
class ServiceInstance:
    """Service instance information"""
    id: str
    name: str
    version: str = "1.0.0"
    endpoints: List[ServiceEndpoint] = field(default_factory=list)
    status: str = "healthy"  # healthy, unhealthy, draining
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: Optional[datetime] = None
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
    
    def is_healthy(self) -> bool:
        """Check if instance is healthy"""
        if self.status != "healthy":
            return False
        
        if self.last_heartbeat:
            # Consider unhealthy if no heartbeat for 60 seconds
            delta = (datetime.utcnow() - self.last_heartbeat).total_seconds()
            if delta > 60:
                return False
        
        return True
    
    def add_endpoint(self, endpoint: ServiceEndpoint):
        """Add endpoint to instance"""
        self.endpoints.append(endpoint)
    
    def get_primary_endpoint(self) -> Optional[ServiceEndpoint]:
        """Get primary endpoint"""
        for ep in self.endpoints:
            if ep.protocol in ['tls', 'tcp']:
                return ep
        return self.endpoints[0] if self.endpoints else None
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'endpoints': [ep.to_dict() for ep in self.endpoints],
            'status': self.status,
            'metadata': self.metadata,
            'registered_at': self.registered_at.isoformat(),
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ServiceInstance':
        instance = cls(
            id=data['id'],
            name=data['name'],
            version=data.get('version', '1.0.0'),
            endpoints=[ServiceEndpoint.from_dict(ep) for ep in data.get('endpoints', [])],
            status=data.get('status', 'healthy'),
            metadata=data.get('metadata', {}),
            registered_at=datetime.fromisoformat(data['registered_at']) if 'registered_at' in data else datetime.utcnow()
        )
        
        if 'last_heartbeat' in data and data['last_heartbeat']:
            instance.last_heartbeat = datetime.fromisoformat(data['last_heartbeat'])
        
        return instance


@dataclass
class ServiceHealth:
    """Service health status"""
    instance_id: str
    service_name: str
    status: str  # healthy, unhealthy, degraded
    latency_ms: float
    error_rate: float
    connections: int
    last_check: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'instance_id': self.instance_id,
            'service_name': self.service_name,
            'status': self.status,
            'latency_ms': self.latency_ms,
            'error_rate': self.error_rate,
            'connections': self.connections,
            'last_check': self.last_check.isoformat(),
            'details': self.details
        }


@dataclass
class ServiceRegistration:
    """Service registration request"""
    instance: ServiceInstance
    ttl: int = 30  # seconds
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'instance': self.instance.to_dict(),
            'ttl': self.ttl,
            'tags': self.tags
        }


@dataclass 
class ServiceQuery:
    """Service discovery query"""
    name: str
    version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    healthy_only: bool = True
    limit: int = 100
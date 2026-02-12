"""
NexusRPC Metrics Collection
Prometheus integration with custom collectors
"""

import time
import threading
from typing import Dict, List, Optional, Callable
from collections import defaultdict
from functools import wraps
import logging

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, 
        CollectorRegistry, generate_latest, REGISTRY
    )
    from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("prometheus_client not installed, metrics disabled")

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Metrics collector for RPC operations
    Provides counters, gauges, histograms with labels
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, namespace: str = 'nexusrpc'):
        if not hasattr(self, 'initialized'):
            self.namespace = namespace
            self.registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None
            self._metrics = {}
            self._labels = {}
            self.initialized = True
            
            if PROMETHEUS_AVAILABLE:
                self._init_metrics()
    
    def _init_metrics(self):
        """Initialize Prometheus metrics"""
        # RPC call counters
        self._metrics['calls_total'] = Counter(
            'rpc_calls_total',
            'Total number of RPC calls',
            ['service', 'method', 'status'],
            registry=self.registry
        )
        
        self._metrics['calls_in_flight'] = Gauge(
            'rpc_calls_in_flight',
            'Current number of in-flight RPC calls',
            ['service'],
            registry=self.registry
        )
        
        # Latency histograms
        self._metrics['call_duration_seconds'] = Histogram(
            'rpc_call_duration_seconds',
            'RPC call latency in seconds',
            ['service', 'method'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry
        )
        
        # Request size
        self._metrics['request_size_bytes'] = Histogram(
            'rpc_request_size_bytes',
            'RPC request size in bytes',
            ['service'],
            buckets=(64, 256, 1024, 4096, 16384, 65536, 262144, 1048576),
            registry=self.registry
        )
        
        # Response size
        self._metrics['response_size_bytes'] = Histogram(
            'rpc_response_size_bytes',
            'RPC response size in bytes',
            ['service'],
            buckets=(64, 256, 1024, 4096, 16384, 65536, 262144, 1048576),
            registry=self.registry
        )
        
        # Error counters
        self._metrics['errors_total'] = Counter(
            'rpc_errors_total',
            'Total number of RPC errors',
            ['service', 'method', 'error_type'],
            registry=self.registry
        )
        
        # Connection metrics
        self._metrics['connections_active'] = Gauge(
            'rpc_connections_active',
            'Number of active connections',
            ['peer'],
            registry=self.registry
        )
        
        self._metrics['connections_total'] = Counter(
            'rpc_connections_total',
            'Total number of connections',
            ['peer'],
            registry=self.registry
        )
        
        # Service discovery metrics
        self._metrics['service_instances'] = Gauge(
            'rpc_service_instances',
            'Number of service instances',
            ['service_name', 'status'],
            registry=self.registry
        )
        
        # Pool metrics
        self._metrics['pool_size'] = Gauge(
            'rpc_connection_pool_size',
            'Connection pool size',
            ['pool_name'],
            registry=self.registry
        )
        
        self._metrics['pool_available'] = Gauge(
            'rpc_connection_pool_available',
            'Available connections in pool',
            ['pool_name'],
            registry=self.registry
        )
        
        # Circuit breaker metrics
        self._metrics['circuit_breaker_state'] = Gauge(
            'rpc_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['breaker_name'],
            registry=self.registry
        )
        
        # System metrics
        self._metrics['uptime_seconds'] = Gauge(
            'rpc_uptime_seconds',
            'Service uptime in seconds',
            [],
            registry=self.registry
        )
        
        self._start_time = time.time()
    
    def increment(self, name: str, labels: Dict = None, value: int = 1):
        """Increment a counter metric"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        metric = self._metrics.get(name)
        if metric and isinstance(metric, Counter):
            if labels:
                metric.labels(**labels).inc(value)
            else:
                metric.inc(value)
    
    def gauge(self, name: str, value: float, labels: Dict = None):
        """Set a gauge metric"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        metric = self._metrics.get(name)
        if metric and isinstance(metric, Gauge):
            if labels:
                metric.labels(**labels).set(value)
            else:
                metric.set(value)
    
    def timing(self, name: str, duration: float, labels: Dict = None):
        """Record a timing/histogram metric"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        metric = self._metrics.get(name)
        if metric and isinstance(metric, Histogram):
            if labels:
                metric.labels(**labels).observe(duration)
            else:
                metric.observe(duration)
    
    def histogram(self, name: str, value: float, labels: Dict = None):
        """Record a histogram observation"""
        self.timing(name, value, labels)
    
    def update_service_instances(self, service_name: str, count: int, status: str = 'healthy'):
        """Update service instance count"""
        self.gauge('service_instances', count, {
            'service_name': service_name,
            'status': status
        })
    
    def update_pool_stats(self, pool_name: str, size: int, available: int):
        """Update connection pool statistics"""
        self.gauge('pool_size', size, {'pool_name': pool_name})
        self.gauge('pool_available', available, {'pool_name': pool_name})
    
    def update_circuit_breaker(self, name: str, state: str):
        """Update circuit breaker state"""
        state_map = {'closed': 0, 'open': 1, 'half_open': 2}
        self.gauge('circuit_breaker_state', state_map.get(state, 0), {
            'breaker_name': name
        })
    
    def record_call(self, service: str, method: str, duration: float, 
                   status: str = 'success', request_size: int = 0, 
                   response_size: int = 0):
        """Record complete RPC call metrics"""
        self.increment('calls_total', {
            'service': service,
            'method': method,
            'status': status
        })
        
        self.timing('call_duration_seconds', duration, {
            'service': service,
            'method': method
        })
        
        if request_size > 0:
            self.histogram('request_size_bytes', request_size, {
                'service': service
            })
        
        if response_size > 0:
            self.histogram('response_size_bytes', response_size, {
                'service': service
            })
    
    def record_error(self, service: str, method: str, error_type: str):
        """Record RPC error"""
        self.increment('errors_total', {
            'service': service,
            'method': method,
            'error_type': error_type
        })
    
    def start_in_flight(self, service: str):
        """Start tracking an in-flight request"""
        self.gauge('calls_in_flight', 1, {'service': service}, inc=True)
    
    def end_in_flight(self, service: str):
        """End tracking an in-flight request"""
        self.gauge('calls_in_flight', -1, {'service': service}, inc=True)
    
    def record_connection(self, peer: str, direction: str = 'inbound'):
        """Record new connection"""
        peer_label = f"{peer}_{direction}"
        self.increment('connections_total', {'peer': peer_label})
        self.gauge('connections_active', 1, {'peer': peer_label}, inc=True)
    
    def record_disconnection(self, peer: str, direction: str = 'inbound'):
        """Record connection close"""
        peer_label = f"{peer}_{direction}"
        self.gauge('connections_active', -1, {'peer': peer_label}, inc=True)
    
    def get_uptime(self) -> float:
        """Get service uptime in seconds"""
        return time.time() - self._start_time
    
    def update_uptime(self):
        """Update uptime metric"""
        self.gauge('uptime_seconds', self.get_uptime())
    
    def generate_latest(self) -> bytes:
        """Generate Prometheus metrics output"""
        if PROMETHEUS_AVAILABLE and self.registry:
            self.update_uptime()
            return generate_latest(self.registry)
        return b'# Metrics disabled\n'


def timed_metric(metric_name: str, labels: Dict = None):
    """Decorator for timing function execution"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            collector = MetricsCollector()
            start = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start
                collector.timing(metric_name, duration, labels)
        return wrapper
    return decorator


def count_calls(metric_name: str, labels: Dict = None):
    """Decorator for counting function calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            collector = MetricsCollector()
            collector.increment(metric_name, labels)
            return func(*args, **kwargs)
        return wrapper
    return decorator


class MetricsMiddleware:
    """Middleware for automatic metrics collection"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.collector = MetricsCollector()
    
    def before_call(self, method: str, request_size: int = 0):
        """Called before RPC call"""
        self.collector.start_in_flight(self.service_name)
        self.collector.histogram('request_size_bytes', request_size, {
            'service': self.service_name
        })
    
    def after_call(self, method: str, duration: float, 
                  status: str = 'success', response_size: int = 0):
        """Called after RPC call"""
        self.collector.end_in_flight(self.service_name)
        self.collector.record_call(
            service=self.service_name,
            method=method,
            duration=duration,
            status=status,
            response_size=response_size
        )
    
    def on_error(self, method: str, error_type: str):
        """Called on RPC error"""
        self.collector.record_error(
            service=self.service_name,
            method=method,
            error_type=error_type
        )
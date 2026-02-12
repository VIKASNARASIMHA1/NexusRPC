"""
NexusRPC Distributed Tracing
Jaeger/OpenTelemetry integration for request tracing
"""

import time
import uuid
import threading
from contextlib import contextmanager
from typing import Dict, Optional, List, Any
from collections import defaultdict
import json
import logging

try:
    from opentelemetry import trace, context
    from opentelemetry.trace import Span, SpanKind, Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("opentelemetry not installed, tracing disabled")

logger = logging.getLogger(__name__)


class Tracer:
    """
    Distributed tracer with Jaeger/OpenTelemetry integration
    Falls back to in-memory tracing if OT not available
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, service_name: str = 'nexusrpc', 
                 jaeger_host: str = 'localhost',
                 jaeger_port: int = 6831,
                 sample_rate: float = 0.1):
        
        if not hasattr(self, 'initialized'):
            self.service_name = service_name
            self.sample_rate = sample_rate
            self.jaeger_host = jaeger_host
            self.jaeger_port = jaeger_port
            
            self.spans = []  # In-memory fallback
            self.trace_context = {}
            
            if OPENTELEMETRY_AVAILABLE:
                self._init_opentelemetry()
            else:
                self._init_fallback()
            
            self.initialized = True
    
    def _init_opentelemetry(self):
        """Initialize OpenTelemetry with Jaeger exporter"""
        try:
            # Create resource
            resource = Resource(attributes={
                SERVICE_NAME: self.service_name,
                'service.version': '1.0.0',
                'deployment.environment': 'production'
            })
            
            # Create tracer provider
            provider = TracerProvider(resource=resource)
            
            # Create Jaeger exporter
            jaeger_exporter = JaegerExporter(
                agent_host_name=self.jaeger_host,
                agent_port=self.jaeger_port,
            )
            
            # Add span processor
            provider.add_span_processor(
                BatchSpanProcessor(jaeger_exporter)
            )
            
            # Set global tracer provider
            trace.set_tracer_provider(provider)
            
            # Create tracer
            self.tracer = trace.get_tracer(self.service_name)
            self.enabled = True
            logger.info(f"OpenTelemetry tracer initialized, exporting to {self.jaeger_host}:{self.jaeger_port}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry: {e}")
            self._init_fallback()
    
    def _init_fallback(self):
        """Initialize in-memory fallback tracer"""
        self.tracer = None
        self.enabled = False
        logger.warning("Using in-memory fallback tracer")
    
    @contextmanager
    def span(self, name: str, kind: str = 'internal', 
             parent: Optional['Span'] = None,
             attributes: Dict = None):
        """
        Create a new tracing span
        
        Args:
            name: Span name
            kind: Span kind (internal, server, client, producer, consumer)
            parent: Parent span
            attributes: Span attributes
        """
        if self.enabled and self.tracer:
            # Map to OpenTelemetry span kind
            kind_map = {
                'internal': SpanKind.INTERNAL,
                'server': SpanKind.SERVER,
                'client': SpanKind.CLIENT,
                'producer': SpanKind.PRODUCER,
                'consumer': SpanKind.CONSUMER
            }
            
            with self.tracer.start_as_current_span(
                name,
                kind=kind_map.get(kind, SpanKind.INTERNAL)
            ) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, str(value))
                
                try:
                    yield span
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
        else:
            # Fallback: in-memory span
            span_id = str(uuid.uuid4())
            start_time = time.time()
            
            class FakeSpan:
                def set_attribute(self, key, value):
                    pass
                def set_status(self, status):
                    pass
                def record_exception(self, e):
                    pass
                def end(self):
                    pass
            
            span = FakeSpan()
            
            # Record span
            self.spans.append({
                'name': name,
                'id': span_id,
                'start_time': start_time,
                'attributes': attributes or {}
            })
            
            try:
                yield span
            finally:
                # Update span with end time
                for s in self.spans:
                    if s['id'] == span_id:
                        s['end_time'] = time.time()
                        s['duration'] = s['end_time'] - s['start_time']
                        break
    
    def inject_context(self, headers: Dict) -> Dict:
        """
        Inject trace context into headers for propagation
        """
        if self.enabled and OPENTELEMETRY_AVAILABLE:
            carrier = {}
            propagator = TraceContextTextMapPropagator()
            propagator.inject(carrier)
            headers.update(carrier)
        else:
            # Fallback: generate trace ID
            headers['x-trace-id'] = str(uuid.uuid4())
            headers['x-span-id'] = str(uuid.uuid4())
        
        return headers
    
    def extract_context(self, headers: Dict) -> Optional[object]:
        """
        Extract trace context from headers
        """
        if self.enabled and OPENTELEMETRY_AVAILABLE:
            propagator = TraceContextTextMapPropagator()
            return propagator.extract(carrier=headers)
        return None
    
    def get_spans(self, limit: int = 100) -> List[Dict]:
        """Get recorded spans (fallback only)"""
        return self.spans[-limit:]
    
    def clear_spans(self):
        """Clear recorded spans"""
        self.spans.clear()


class TraceMiddleware:
    """Middleware for automatic trace propagation"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.tracer = Tracer.get_instance()
    
    def before_request(self, method: str, headers: Dict) -> Dict:
        """Inject trace context before request"""
        span_name = f"{self.service_name}.{method}"
        
        with self.tracer.span(span_name, kind='client') as span:
            # Inject context into headers
            headers = self.tracer.inject_context(headers)
            headers['x-span-name'] = span_name
        
        return headers
    
    def after_request(self, response):
        """Process response"""
        pass
    
    def before_handler(self, method: str, headers: Dict):
        """Extract context before handling request"""
        # Extract trace context
        context = self.tracer.extract_context(headers)
        
        span_name = headers.get('x-span-name', f"{self.service_name}.{method}")
        
        return self.tracer.span(
            span_name,
            kind='server',
            attributes={
                'method': method,
                'service': self.service_name
            }
        )


def trace_call(func):
    """Decorator for tracing function calls"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        tracer = Tracer.get_instance()
        with tracer.span(func.__name__):
            return func(*args, **kwargs)
    return wrapper
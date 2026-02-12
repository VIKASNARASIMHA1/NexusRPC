"""
NexusRPC Structured Logging
JSON-formatted logging with correlation IDs
"""

import json
import logging
import logging.config
import socket
import threading
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from contextvars import ContextVar
import traceback

# Context variable for correlation ID
correlation_id: ContextVar[str] = ContextVar('correlation_id', default='')


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging
    Outputs logs as JSON objects for easy ingestion
    """
    
    def __init__(self, **kwargs):
        super().__init__()
        self.static_fields = kwargs
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
            'correlation_id': correlation_id.get() or record.__dict__.get('correlation_id', ''),
            'hostname': socket.gethostname(),
            'pid': record.process,
            'thread': record.threadName,
            **self.static_fields
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': ''.join(traceback.format_tb(record.exc_info[2]))
            }
        
        # Add extra fields from record
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        return json.dumps(log_data)


class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to log records"""
    
    def filter(self, record):
        record.correlation_id = correlation_id.get()
        return True


class RequestContext:
    """
    Context manager for request correlation IDs
    """
    
    def __init__(self, cid: Optional[str] = None):
        self.cid = cid or str(uuid.uuid4())
        self.token = None
    
    def __enter__(self):
        self.token = correlation_id.set(self.cid)
        return self.cid
    
    def __exit__(self, *args):
        correlation_id.reset(self.token)
    
    @staticmethod
    def get_current() -> str:
        """Get current correlation ID"""
        return correlation_id.get()


def setup_logging(service_name: str = 'nexusrpc',
                 log_level: str = 'INFO',
                 log_format: str = 'json',
                 log_file: Optional[str] = None):
    """
    Configure logging for the application
    
    Args:
        service_name: Name of the service
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: 'json' or 'console'
        log_file: Optional file path for logs
    """
    
    # Get numeric log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Base configuration
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'filters': {
            'correlation_id': {
                '()': CorrelationIdFilter
            }
        },
        'formatters': {
            'json': {
                '()': JSONFormatter,
                'service': service_name,
                'environment': os.environ.get('ENVIRONMENT', 'development')
            },
            'console': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': level,
                'formatter': log_format,
                'filters': ['correlation_id'],
                'stream': 'ext://sys.stdout'
            }
        },
        'loggers': {
            'nexusrpc': {
                'level': level,
                'handlers': ['console'],
                'propagate': False
            },
            'rpc': {
                'level': level,
                'handlers': ['console'],
                'propagate': False
            },
            'security': {
                'level': level,
                'handlers': ['console'],
                'propagate': False
            },
            'discovery': {
                'level': level,
                'handlers': ['console'],
                'propagate': False
            }
        },
        'root': {
            'level': level,
            'handlers': ['console']
        }
    }
    
    # Add file handler if specified
    if log_file:
        config['handlers']['file'] = {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': level,
            'formatter': log_format,
            'filters': ['correlation_id'],
            'filename': log_file,
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        }
        
        for logger in config['loggers'].values():
            logger['handlers'].append('file')
        
        config['root']['handlers'].append('file')
    
    # Apply configuration
    logging.config.dictConfig(config)
    
    # Set third-party log levels
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured: level={log_level}, format={log_format}")


def get_logger(name: str) -> logging.Logger:
    """Get configured logger instance"""
    return logging.getLogger(name)


class LoggerMixin:
    """
    Mixin class to add logging to any class
    """
    
    @property
    def logger(self) -> logging.Logger:
        """Get class-specific logger"""
        name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        return get_logger(name)
    
    def log_debug(self, msg: str, **kwargs):
        """Log debug message with extra fields"""
        self.logger.debug(msg, extra={'extra': kwargs})
    
    def log_info(self, msg: str, **kwargs):
        """Log info message with extra fields"""
        self.logger.info(msg, extra={'extra': kwargs})
    
    def log_warning(self, msg: str, **kwargs):
        """Log warning message with extra fields"""
        self.logger.warning(msg, extra={'extra': kwargs})
    
    def log_error(self, msg: str, exc_info=False, **kwargs):
        """Log error message with extra fields"""
        self.logger.error(msg, exc_info=exc_info, extra={'extra': kwargs})
    
    def log_critical(self, msg: str, exc_info=False, **kwargs):
        """Log critical message with extra fields"""
        self.logger.critical(msg, exc_info=exc_info, extra={'extra': kwargs})
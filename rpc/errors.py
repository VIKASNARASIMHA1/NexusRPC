"""
NexusRPC Error Handling
Comprehensive exception hierarchy for all error conditions
"""

class RPCError(Exception):
    """Base exception for all RPC errors"""
    code = 1000
    message = "RPC Error"
    
    def __init__(self, message=None, cause=None):
        self.message = message or self.message
        self.cause = cause
        super().__init__(self.message)
    
    def to_dict(self):
        return {
            'code': self.code,
            'message': self.message,
            'cause': str(self.cause) if self.cause else None
        }


# Protocol Errors (1000-1099)
class ProtocolError(RPCError):
    """Protocol violation"""
    code = 1001
    message = "Protocol error"


class SerializationError(RPCError):
    """Serialization/deserialization failed"""
    code = 1002
    message = "Serialization error"


class FrameTooLargeError(ProtocolError):
    """Frame exceeds maximum size"""
    code = 1003
    message = "Frame too large"


class InvalidFrameError(ProtocolError):
    """Invalid frame format"""
    code = 1004
    message = "Invalid frame format"


class ChecksumMismatchError(ProtocolError):
    """CRC32 checksum verification failed"""
    code = 1005
    message = "Checksum mismatch"


# Connection Errors (1100-1199)
class ConnectionError(RPCError):
    """Connection-related errors"""
    code = 1100
    message = "Connection error"


class ConnectionTimeoutError(ConnectionError):
    """Connection timeout"""
    code = 1101
    message = "Connection timeout"


class ConnectionClosedError(ConnectionError):
    """Connection closed unexpectedly"""
    code = 1102
    message = "Connection closed"


class ConnectionRefusedError(ConnectionError):
    """Connection refused by server"""
    code = 1103
    message = "Connection refused"


class ConnectionPoolExhaustedError(ConnectionError):
    """No available connections in pool"""
    code = 1104
    message = "Connection pool exhausted"


# Timeout Errors (1200-1299)
class TimeoutError(RPCError):
    """Operation timeout"""
    code = 1200
    message = "Operation timeout"


class RequestTimeoutError(TimeoutError):
    """RPC request timeout"""
    code = 1201
    message = "Request timeout"


class ReadTimeoutError(TimeoutError):
    """Read operation timeout"""
    code = 1202
    message = "Read timeout"


class WriteTimeoutError(TimeoutError):
    """Write operation timeout"""
    code = 1203
    message = "Write timeout"


# Service Errors (1300-1399)
class ServiceError(RPCError):
    """Service-related errors"""
    code = 1300
    message = "Service error"


class ServiceNotFoundError(ServiceError):
    """Service not found"""
    code = 1301
    message = "Service not found"


class ServiceUnavailableError(ServiceError):
    """Service unavailable"""
    code = 1302
    message = "Service unavailable"


class ServiceBusyError(ServiceError):
    """Service busy"""
    code = 1303
    message = "Service busy"


# Method Errors (1400-1499)
class MethodError(RPCError):
    """Method-related errors"""
    code = 1400
    message = "Method error"


class MethodNotFoundError(MethodError):
    """Method not found"""
    code = 1401
    message = "Method not found"


class MethodNotAllowedError(MethodError):
    """Method not allowed"""
    code = 1402
    message = "Method not allowed"


class MethodExecutionError(MethodError):
    """Error during method execution"""
    code = 1403
    message = "Method execution error"


# Authentication Errors (1500-1599)
class AuthenticationError(RPCError):
    """Authentication errors"""
    code = 1500
    message = "Authentication error"


class InvalidCredentialsError(AuthenticationError):
    """Invalid username/password"""
    code = 1501
    message = "Invalid credentials"


class TokenExpiredError(AuthenticationError):
    """JWT token expired"""
    code = 1502
    message = "Token expired"


class InvalidTokenError(AuthenticationError):
    """Invalid JWT token"""
    code = 1503
    message = "Invalid token"


class InsufficientPermissionsError(AuthenticationError):
    """Insufficient permissions"""
    code = 1504
    message = "Insufficient permissions"


class APIKeyInvalidError(AuthenticationError):
    """Invalid API key"""
    code = 1505
    message = "Invalid API key"


# Discovery Errors (1600-1699)
class DiscoveryError(RPCError):
    """Service discovery errors"""
    code = 1600
    message = "Discovery error"


class RegistryUnavailableError(DiscoveryError):
    """Registry unavailable"""
    code = 1601
    message = "Registry unavailable"


class InstanceNotFoundError(DiscoveryError):
    """Service instance not found"""
    code = 1602
    message = "Instance not found"


class RegistrationFailedError(DiscoveryError):
    """Service registration failed"""
    code = 1603
    message = "Registration failed"


# Circuit Breaker Errors (1700-1799)
class CircuitBreakerError(RPCError):
    """Circuit breaker errors"""
    code = 1700
    message = "Circuit breaker error"


class CircuitOpenError(CircuitBreakerError):
    """Circuit is open"""
    code = 1701
    message = "Circuit breaker is open"


# Configuration Errors (1800-1899)
class ConfigurationError(RPCError):
    """Configuration errors"""
    code = 1800
    message = "Configuration error"


class InvalidConfigurationError(ConfigurationError):
    """Invalid configuration"""
    code = 1801
    message = "Invalid configuration"


# Monitoring Errors (1900-1999)
class MonitoringError(RPCError):
    """Monitoring errors"""
    code = 1900
    message = "Monitoring error"


class MetricsCollectionError(MonitoringError):
    """Metrics collection failed"""
    code = 1901
    message = "Metrics collection failed"


class TracingError(MonitoringError):
    """Distributed tracing error"""
    code = 1902
    message = "Tracing error"
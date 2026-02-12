"""
NexusRPC Protocol - Serialization/Deserialization Layer
Implements custom binary protocol with schema validation
"""

import struct
import json
import pickle
import zlib
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid


class MessageType(Enum):
    """RPC message types"""
    REQUEST = 0x01
    RESPONSE = 0x02
    ERROR = 0x03
    HEARTBEAT = 0x04
    STREAM = 0x05


class CompressionType(Enum):
    """Compression algorithms"""
    NONE = 0x00
    ZLIB = 0x01
    GZIP = 0x02


class SerializationType(Enum):
    """Serialization formats"""
    JSON = 0x01
    PICKLE = 0x02
    MSGPACK = 0x03  # Can be added later


@dataclass
class RPCRequest:
    """RPC Request message"""
    request_id: str
    service_name: str
    method_name: str
    args: Tuple
    kwargs: Dict[str, Any]
    metadata: Dict[str, str]
    timestamp: float
    
    @classmethod
    def create(cls, service: str, method: str, *args, **kwargs):
        return cls(
            request_id=str(uuid.uuid4()),
            service_name=service,
            method_name=method,
            args=args,
            kwargs=kwargs,
            metadata={},
            timestamp=datetime.utcnow().timestamp()
        )


@dataclass
class RPCResponse:
    """RPC Response message"""
    request_id: str
    result: Any
    error: Optional[str] = None
    metadata: Dict[str, str] = None
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().timestamp()
        if self.metadata is None:
            self.metadata = {}


class RPCProtocol:
    """
    Binary protocol for RPC communication
    
    Frame Format:
    ┌────────┬────────┬────────┬────────┬────────┬────────┐
    │ Magic  │ Version│ MsgType│ SerType│ Comp   │ Header │
    │ 0x4E52 │ 0x01   │ 1 byte │ 1 byte │ 1 byte │ Len(2) │
    └────────┴────────┴────────┴────────┴────────┴────────┘
    ┌────────┬────────┬──────────────────────────────────┐
    │ Header │ Payload│ CRC32 Checksum                   │
    │ Bytes  │ Len(4) │ (4 bytes)                        │
    └────────┴────────┴──────────────────────────────────┘
    """
    
    MAGIC = b'NR'  # NexusRPC
    VERSION = 0x01
    HEADER_SIZE = 12
    
    @staticmethod
    def encode_message(msg_type: MessageType, 
                      payload: bytes,
                      ser_type: SerializationType = SerializationType.JSON,
                      comp_type: CompressionType = CompressionType.NONE) -> bytes:
        """Encode message into binary frame"""
        
        # Compress payload if needed
        if comp_type == CompressionType.ZLIB:
            payload = zlib.compress(payload)
        elif comp_type == CompressionType.GZIP:
            import gzip
            payload = gzip.compress(payload)
        
        # Calculate lengths
        payload_len = len(payload)
        header = struct.pack('!2sBBBBH', 
                           RPCProtocol.MAGIC,
                           RPCProtocol.VERSION,
                           msg_type.value,
                           ser_type.value,
                           comp_type.value,
                           0)  # Reserved
        
        # Build frame: header + payload_len + payload + crc32
        frame = header
        frame += struct.pack('!I', payload_len)
        frame += payload
        frame += struct.pack('!I', zlib.crc32(payload))
        
        return frame
    
    @staticmethod
    def decode_frame(data: bytes) -> Tuple[MessageType, bytes, Dict]:
        """Decode binary frame into message"""
        
        if len(data) < RPCProtocol.HEADER_SIZE + 8:
            raise ValueError("Incomplete frame")
        
        # Parse header
        magic, version, msg_type, ser_type, comp_type, _ = \
            struct.unpack('!2sBBBBH', data[:RPCProtocol.HEADER_SIZE])
        
        if magic != RPCProtocol.MAGIC:
            raise ValueError(f"Invalid magic bytes: {magic}")
        
        if version != RPCProtocol.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        # Parse payload length
        payload_len = struct.unpack('!I', data[RPCProtocol.HEADER_SIZE:
                                              RPCProtocol.HEADER_SIZE+4])[0]
        
        # Extract payload and checksum
        payload_start = RPCProtocol.HEADER_SIZE + 4
        payload = data[payload_start:payload_start + payload_len]
        stored_crc32 = struct.unpack('!I', 
                                     data[payload_start + payload_len:
                                          payload_start + payload_len + 4])[0]
        
        # Verify checksum
        calculated_crc32 = zlib.crc32(payload)
        if calculated_crc32 != stored_crc32:
            raise ValueError(f"CRC32 mismatch: {calculated_crc32} != {stored_crc32}")
        
        # Decompress if needed
        comp_type = CompressionType(comp_type)
        if comp_type == CompressionType.ZLIB:
            payload = zlib.decompress(payload)
        elif comp_type == CompressionType.GZIP:
            import gzip
            import io
            payload = gzip.decompress(payload)
        
        metadata = {
            'version': version,
            'serialization': ser_type,
            'compression': comp_type.value,
            'payload_size': payload_len
        }
        
        return MessageType(msg_type), payload, metadata
    
    @staticmethod
    def serialize(obj: Any, ser_type: SerializationType) -> bytes:
        """Serialize Python object to bytes"""
        if ser_type == SerializationType.JSON:
            return json.dumps(obj, default=str).encode('utf-8')
        elif ser_type == SerializationType.PICKLE:
            return pickle.dumps(obj)
        else:
            raise ValueError(f"Unsupported serialization: {ser_type}")
    
    @staticmethod
    def deserialize(data: bytes, ser_type: SerializationType) -> Any:
        """Deserialize bytes to Python object"""
        if ser_type == SerializationType.JSON:
            return json.loads(data.decode('utf-8'))
        elif ser_type == SerializationType.PICKLE:
            return pickle.loads(data)
        else:
            raise ValueError(f"Unsupported serialization: {ser_type}")
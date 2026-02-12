"""
Tests for RPC protocol implementation
"""

import pytest
import struct
import zlib
from rpc.protocol import (
    RPCProtocol, RPCRequest, RPCResponse,
    MessageType, SerializationType, CompressionType
)


class TestRPCProtocol:
    """Test RPC protocol encoding/decoding"""
    
    def test_encode_decode_request(self):
        """Test encoding and decoding RPC request"""
        # Create request
        request = RPCRequest.create(
            service_name="TestService",
            method_name="test_method",
            "arg1", "arg2",
            kwarg1="value1"
        )
        
        # Serialize
        payload = RPCProtocol.serialize(request.__dict__, SerializationType.JSON)
        
        # Encode
        frame = RPCProtocol.encode_message(
            MessageType.REQUEST,
            payload,
            SerializationType.JSON,
            CompressionType.NONE
        )
        
        # Decode
        msg_type, decoded_payload, metadata = RPCProtocol.decode_frame(frame)
        
        # Deserialize
        decoded_dict = RPCProtocol.deserialize(decoded_payload, SerializationType.JSON)
        decoded_request = RPCRequest(**decoded_dict)
        
        # Assert
        assert msg_type == MessageType.REQUEST
        assert decoded_request.service_name == request.service_name
        assert decoded_request.method_name == request.method_name
        assert decoded_request.args == request.args
        assert decoded_request.kwargs == request.kwargs
        assert decoded_request.request_id == request.request_id
    
    def test_encode_decode_response(self):
        """Test encoding and decoding RPC response"""
        response = RPCResponse(
            request_id="test-123",
            result={"key": "value"},
            metadata={"test": "true"}
        )
        
        payload = RPCProtocol.serialize(response.__dict__, SerializationType.JSON)
        frame = RPCProtocol.encode_message(MessageType.RESPONSE, payload)
        
        msg_type, decoded_payload, metadata = RPCProtocol.decode_frame(frame)
        decoded_dict = RPCProtocol.deserialize(decoded_payload, SerializationType.JSON)
        decoded_response = RPCResponse(**decoded_dict)
        
        assert msg_type == MessageType.RESPONSE
        assert decoded_response.request_id == response.request_id
        assert decoded_response.result == response.result
        assert decoded_response.metadata == response.metadata
    
    def test_compression(self):
        """Test payload compression"""
        # Large payload
        large_data = {"data": "x" * 10000}
        payload = RPCProtocol.serialize(large_data, SerializationType.JSON)
        
        # Compress
        compressed = zlib.compress(payload)
        assert len(compressed) < len(payload)
        
        # Encode with compression
        frame = RPCProtocol.encode_message(
            MessageType.REQUEST,
            payload,
            SerializationType.JSON,
            CompressionType.ZLIB
        )
        
        # Decode
        msg_type, decoded_payload, metadata = RPCProtocol.decode_frame(frame)
        
        # Should be decompressed automatically
        decoded_dict = RPCProtocol.deserialize(decoded_payload, SerializationType.JSON)
        assert decoded_dict == large_data
    
    def test_crc32_validation(self):
        """Test CRC32 checksum validation"""
        request = RPCRequest.create("Test", "method")
        payload = RPCProtocol.serialize(request.__dict__, SerializationType.JSON)
        
        frame = RPCProtocol.encode_message(MessageType.REQUEST, payload)
        
        # Corrupt frame
        corrupted = frame[:-4] + struct.pack('!I', 0)  # Wrong CRC32
        
        with pytest.raises(ValueError, match="CRC32 mismatch"):
            RPCProtocol.decode_frame(corrupted)
    
    def test_invalid_magic(self):
        """Test invalid magic bytes detection"""
        frame = b'XX' + b'\x00' * 14  # Wrong magic
        
        with pytest.raises(ValueError, match="Invalid magic bytes"):
            RPCProtocol.decode_frame(frame)
    
    def test_frame_too_large(self):
        """Test maximum frame size"""
        # This will be caught by transport layer
        pass
    
    def test_serialization_formats(self):
        """Test different serialization formats"""
        data = {"test": 123, "nested": {"value": "string"}}
        
        # JSON
        json_data = RPCProtocol.serialize(data, SerializationType.JSON)
        decoded = RPCProtocol.deserialize(json_data, SerializationType.JSON)
        assert decoded == data
        
        # Pickle
        pickle_data = RPCProtocol.serialize(data, SerializationType.PICKLE)
        decoded = RPCProtocol.deserialize(pickle_data, SerializationType.PICKLE)
        assert decoded == data
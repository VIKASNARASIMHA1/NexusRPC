"""
Tests for security module
"""

import pytest
import time
from security.auth import JWTAuthenticator, AuthConfig, PasswordHasher, APIKeyAuth
from security.tls import TLSConfig, TLSServer, TLSClient
from rpc.errors import AuthenticationError


class TestJWTAuthenticator:
    """Test JWT authentication"""
    
    def setup_method(self):
        self.config = AuthConfig(
            secret_key="test-secret-key",
            algorithm="HS256",
            access_token_expiry=1,  # 1 second for testing
            refresh_token_expiry=2
        )
        self.auth = JWTAuthenticator(self.config)
    
    def test_generate_access_token(self):
        """Test access token generation"""
        token = self.auth.generate_access_token("user123")
        assert token is not None
        assert isinstance(token, str)
    
    def test_verify_token(self):
        """Test token verification"""
        token = self.auth.generate_access_token("user123")
        payload = self.auth.verify_token(token)
        
        assert payload['sub'] == "user123"
        assert payload['type'] == "access"
        assert payload['iss'] == self.config.issuer
    
    def test_token_expiry(self):
        """Test token expiration"""
        token = self.auth.generate_access_token("user123")
        
        # Wait for token to expire
        time.sleep(1.5)
        
        with pytest.raises(AuthenticationError, match="expired"):
            self.auth.verify_token(token)
    
    def test_refresh_token(self):
        """Test refresh token"""
        refresh_token = self.auth.generate_refresh_token("user123")
        payload = self.auth.verify_token(refresh_token)
        
        assert payload['type'] == "refresh"
        assert 'jti' in payload
        
        # Generate new access token
        new_token = self.auth.refresh_access_token(refresh_token)
        assert new_token is not None
        
        payload = self.auth.verify_token(new_token)
        assert payload['type'] == "access"
        assert payload['sub'] == "user123"
    
    def test_invalid_token(self):
        """Test invalid token handling"""
        with pytest.raises(AuthenticationError):
            self.auth.verify_token("invalid.token.here")


class TestPasswordHasher:
    """Test password hashing"""
    
    def test_hash_verify(self):
        """Test password hashing and verification"""
        password = "SecurePassword123!"
        
        hashed = PasswordHasher.hash_password(password)
        assert hashed != password
        
        assert PasswordHasher.verify_password(password, hashed) is True
        assert PasswordHasher.verify_password("wrong", hashed) is False
    
    def test_unique_hashes(self):
        """Test same password produces different hashes"""
        password = "test123"
        
        hash1 = PasswordHasher.hash_password(password)
        hash2 = PasswordHasher.hash_password(password)
        
        assert hash1 != hash2


class TestAPIKeyAuth:
    """Test API key authentication"""
    
    def setup_method(self):
        self.auth = APIKeyAuth()
    
    def test_generate_verify(self):
        """Test API key generation and verification"""
        api_key = self.auth.generate_api_key("user123")
        assert api_key.startswith("nk_")
        
        user_id = self.auth.verify_api_key(api_key)
        assert user_id == "user123"
    
    def test_invalid_key(self):
        """Test invalid API key"""
        user_id = self.auth.verify_api_key("invalid_key")
        assert user_id is None
"""
NexusRPC Authentication Tests
Tests for JWT, password hashing, and API key authentication
"""

import pytest
import time
from security.auth import (
    JWTAuthenticator, 
    AuthConfig, 
    PasswordHasher, 
    APIKeyAuth,
    AuthenticationError
)


class TestJWTAuthenticator:
    """Test JWT token generation and verification"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.config = AuthConfig(
            secret_key="test-secret-key-for-testing-only",
            algorithm="HS256",
            access_token_expiry=1,  # 1 second for testing expiry
            refresh_token_expiry=2,
            issuer="test-issuer",
            audience="test-audience"
        )
        self.auth = JWTAuthenticator(self.config)
    
    def test_generate_access_token(self):
        """Test access token generation"""
        token = self.auth.generate_access_token(
            "user123",
            claims={"role": "admin"}
        )
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT format
    
    def test_verify_token(self):
        """Test token verification"""
        token = self.auth.generate_access_token("user123")
        payload = self.auth.verify_token(token)
        
        assert payload['sub'] == "user123"
        assert payload['iss'] == "test-issuer"
        assert payload['aud'] == "test-audience"
        assert payload['type'] == "access"
        assert 'exp' in payload
        assert 'iat' in payload
    
    def test_token_with_claims(self):
        """Test token with custom claims"""
        token = self.auth.generate_access_token(
            "user123",
            claims={
                "role": "admin",
                "department": "engineering"
            }
        )
        
        payload = self.auth.verify_token(token)
        assert payload['role'] == "admin"
        assert payload['department'] == "engineering"
    
    def test_token_expiry(self):
        """Test token expiration"""
        token = self.auth.generate_access_token("user123")
        
        # Wait for token to expire
        time.sleep(1.5)
        
        with pytest.raises(AuthenticationError) as excinfo:
            self.auth.verify_token(token)
        assert "expired" in str(excinfo.value).lower()
    
    def test_invalid_token_signature(self):
        """Test token with invalid signature"""
        token = self.auth.generate_access_token("user123")
        
        # Tamper with token
        parts = token.split('.')
        tampered = f"{parts[0]}.{parts[1]}.invalid"
        
        with pytest.raises(AuthenticationError) as excinfo:
            self.auth.verify_token(tampered)
        assert "invalid" in str(excinfo.value).lower()
    
    def test_malformed_token(self):
        """Test malformed token"""
        with pytest.raises(AuthenticationError):
            self.auth.verify_token("not.a.token")
        
        with pytest.raises(AuthenticationError):
            self.auth.verify_token("")
    
    def test_refresh_token_generation(self):
        """Test refresh token generation"""
        refresh_token = self.auth.generate_refresh_token("user123")
        payload = self.auth.verify_token(refresh_token)
        
        assert payload['sub'] == "user123"
        assert payload['type'] == "refresh"
        assert 'jti' in payload  # Unique token ID
    
    def test_refresh_access_token(self):
        """Test refreshing access token"""
        refresh_token = self.auth.generate_refresh_token("user123")
        new_token = self.auth.refresh_access_token(refresh_token)
        
        payload = self.auth.verify_token(new_token)
        assert payload['sub'] == "user123"
        assert payload['type'] == "access"
    
    def test_refresh_with_expired_token(self):
        """Test refresh with expired token"""
        refresh_token = self.auth.generate_refresh_token("user123")
        
        # Wait for token to expire
        time.sleep(2.5)
        
        with pytest.raises(AuthenticationError) as excinfo:
            self.auth.refresh_access_token(refresh_token)
        assert "expired" in str(excinfo.value)
    
    def test_auto_secret_key_generation(self):
        """Test automatic secret key generation"""
        config = AuthConfig()  # No secret key provided
        auth = JWTAuthenticator(config)
        
        token = auth.generate_access_token("user123")
        assert token is not None
        
        # Should verify with auto-generated key
        payload = auth.verify_token(token)
        assert payload['sub'] == "user123"
    
    def test_different_secret_keys(self):
        """Test tokens with different secret keys"""
        config1 = AuthConfig(secret_key="key1")
        config2 = AuthConfig(secret_key="key2")
        
        auth1 = JWTAuthenticator(config1)
        auth2 = JWTAuthenticator(config2)
        
        token = auth1.generate_access_token("user123")
        
        # Should fail with different key
        with pytest.raises(AuthenticationError):
            auth2.verify_token(token)


class TestPasswordHasher:
    """Test password hashing and verification"""
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "SecureP@ssw0rd123!"
        hashed = PasswordHasher.hash_password(password)
        
        assert hashed != password
        assert len(hashed) > 20  # bcrypt hash length
        assert hashed.startswith('$2b$')  # bcrypt prefix
    
    def test_verify_password_correct(self):
        """Test correct password verification"""
        password = "test123"
        hashed = PasswordHasher.hash_password(password)
        
        assert PasswordHasher.verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test incorrect password verification"""
        password = "test123"
        hashed = PasswordHasher.hash_password(password)
        
        assert PasswordHasher.verify_password("wrong", hashed) is False
    
    def test_verify_password_empty(self):
        """Test empty password verification"""
        hashed = PasswordHasher.hash_password("test123")
        assert PasswordHasher.verify_password("", hashed) is False
    
    def test_unique_hashes(self):
        """Test same password produces different hashes"""
        password = "samepassword"
        
        hash1 = PasswordHasher.hash_password(password)
        hash2 = PasswordHasher.hash_password(password)
        
        assert hash1 != hash2  # Different salts
    
    def test_hash_consistency(self):
        """Test hash verification is consistent"""
        password = "consistent123"
        hashed = PasswordHasher.hash_password(password)
        
        # Multiple verifications should all succeed
        assert PasswordHasher.verify_password(password, hashed) is True
        assert PasswordHasher.verify_password(password, hashed) is True
        assert PasswordHasher.verify_password(password, hashed) is True
    
    def test_special_characters(self):
        """Test passwords with special characters"""
        password = "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`"
        hashed = PasswordHasher.hash_password(password)
        assert PasswordHasher.verify_password(password, hashed) is True
    
    def test_unicode_password(self):
        """Test Unicode passwords"""
        password = "パスワード🔐"
        hashed = PasswordHasher.hash_password(password)
        assert PasswordHasher.verify_password(password, hashed) is True
    
    def test_long_password(self):
        """Test very long password"""
        password = "a" * 1000
        hashed = PasswordHasher.hash_password(password)
        assert PasswordHasher.verify_password(password, hashed) is True


class TestAPIKeyAuth:
    """Test API key authentication"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.auth = APIKeyAuth()
    
    def test_generate_api_key(self):
        """Test API key generation"""
        api_key = self.auth.generate_api_key("user123")
        
        assert api_key is not None
        assert isinstance(api_key, str)
        assert api_key.startswith("nk_")  # NexusRPC key prefix
        assert len(api_key) > 32
    
    def test_verify_api_key_valid(self):
        """Test valid API key verification"""
        user_id = "user123"
        api_key = self.auth.generate_api_key(user_id)
        
        verified_user = self.auth.verify_api_key(api_key)
        assert verified_user == user_id
    
    def test_verify_api_key_invalid(self):
        """Test invalid API key verification"""
        # Non-existent key
        assert self.auth.verify_api_key("nk_invalid123") is None
        
        # Malformed key
        assert self.auth.verify_api_key("invalid") is None
        assert self.auth.verify_api_key("") is None
    
    def test_multiple_keys_per_user(self):
        """Test multiple API keys for same user"""
        user_id = "user123"
        
        key1 = self.auth.generate_api_key(user_id)
        key2 = self.auth.generate_api_key(user_id)
        
        assert key1 != key2
        assert self.auth.verify_api_key(key1) == user_id
        assert self.auth.verify_api_key(key2) == user_id
    
    def test_multiple_users(self):
        """Test API keys for different users"""
        user1 = "alice"
        user2 = "bob"
        
        key1 = self.auth.generate_api_key(user1)
        key2 = self.auth.generate_api_key(user2)
        
        assert self.auth.verify_api_key(key1) == user1
        assert self.auth.verify_api_key(key2) == user2
        assert self.auth.verify_api_key(key1) != user2
    
    def test_case_sensitivity(self):
        """Test API key case sensitivity"""
        user_id = "user123"
        api_key = self.auth.generate_api_key(user_id)
        
        # Should be case sensitive
        assert self.auth.verify_api_key(api_key.upper()) is None
    
    def test_persistence_across_instances(self):
        """Test API key verification across different instances"""
        user_id = "user123"
        
        # Generate with one instance
        auth1 = APIKeyAuth()
        api_key = auth1.generate_api_key(user_id)
        
        # Verify with another instance (should fail - keys stored in memory)
        auth2 = APIKeyAuth()
        assert auth2.verify_api_key(api_key) is None
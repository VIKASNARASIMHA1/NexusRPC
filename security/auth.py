"""
NexusRPC Authentication Module
JWT-based authentication with OAuth2 support
"""

import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration"""
    secret_key: str = None
    algorithm: str = 'HS256'
    access_token_expiry: int = 3600  # 1 hour
    refresh_token_expiry: int = 604800  # 7 days
    issuer: str = 'nexusrpc'
    audience: str = 'nexusrpc-clients'


class JWTAuthenticator:
    """JWT token management"""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        if not config.secret_key:
            self.config.secret_key = secrets.token_urlsafe(32)
            logger.warning("Generated new secret key. Set explicitly for production.")
    
    def generate_access_token(self, user_id: str, 
                            claims: Optional[Dict] = None) -> str:
        """Generate JWT access token"""
        payload = {
            'sub': user_id,
            'iss': self.config.issuer,
            'aud': self.config.audience,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.config.access_token_expiry),
            'type': 'access'
        }
        if claims:
            payload.update(claims)
        
        return jwt.encode(
            payload,
            self.config.secret_key,
            algorithm=self.config.algorithm
        )
    
    def generate_refresh_token(self, user_id: str) -> str:
        """Generate refresh token"""
        payload = {
            'sub': user_id,
            'iss': self.config.issuer,
            'aud': self.config.audience,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.config.refresh_token_expiry),
            'type': 'refresh',
            'jti': secrets.token_urlsafe(16)  # Unique token ID
        }
        
        return jwt.encode(
            payload,
            self.config.secret_key,
            algorithm=self.config.algorithm
        )
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """Generate new access token from refresh token"""
        payload = self.verify_token(refresh_token)
        
        if payload.get('type') != 'refresh':
            raise AuthenticationError("Invalid token type")
        
        # Generate new access token
        return self.generate_access_token(payload['sub'])


class PasswordHasher:
    """Password hashing using bcrypt"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed.encode('utf-8')
        )


class APIKeyAuth:
    """API Key authentication"""
    
    def __init__(self):
        self.api_keys = {}  # user_id -> hashed_key
    
    def generate_api_key(self, user_id: str) -> str:
        """Generate new API key"""
        api_key = f"nk_{secrets.token_urlsafe(32)}"
        
        # Hash and store
        hashed = hashlib.sha256(api_key.encode()).hexdigest()
        self.api_keys[hashed] = user_id
        
        return api_key
    
    def verify_api_key(self, api_key: str) -> Optional[str]:
        """Verify API key and return user_id"""
        hashed = hashlib.sha256(api_key.encode()).hexdigest()
        return self.api_keys.get(hashed)


class AuthenticationError(Exception):
    """Authentication exception"""
    pass
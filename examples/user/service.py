"""
NexusRPC User Management Service
Complete user service with authentication, profiles, and role-based access control

Features:
- User registration with secure password hashing
- JWT-based authentication
- Profile management
- Role-based access control (RBAC)
- Session management
- User search and filtering
- Account status management
"""

import time
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import re

from rpc.server import RPCService
from security.auth import PasswordHasher, JWTAuthenticator, AuthConfig
from monitoring.logger import LoggerMixin
from rpc.errors import AuthenticationError, AuthorizationError


class UserService(RPCService, LoggerMixin):
    """
    Complete user management service with authentication and authorization.
    
    Features:
    - User registration and profile management
    - JWT token authentication
    - Role-based permissions (user, admin, moderator)
    - Session tracking and management
    - Password reset flow
    - Email verification simulation
    - User search and filtering
    
    API Methods:
    - create_user: Register new user
    - authenticate: Login and get JWT token
    - verify_token: Validate JWT token
    - get_user: Get user profile
    - update_user: Update user information
    - delete_user: Delete user account
    - list_users: List all users (admin only)
    - search_users: Search users by criteria
    - change_password: Update user password
    - reset_password: Initiate password reset
    - confirm_password_reset: Complete password reset
    - verify_email: Mark email as verified
    - get_user_stats: Get user statistics
    - logout: Invalidate user session
    - logout_all: Invalidate all user sessions
    """
    
    def __init__(self):
        """Initialize the user service with data stores and security components."""
        super().__init__(name="UserService", version="2.0.0")
        
        # Data stores
        self.users: Dict[str, Dict] = {}          # user_id -> user data
        self.sessions: Dict[str, str] = {}        # token -> user_id
        self.refresh_tokens: Dict[str, str] = {}  # refresh_token -> user_id
        self.password_resets: Dict[str, Dict] = {} # reset_token -> reset data
        self.email_verifications: Dict[str, str] = {} # verification_token -> user_id
        
        # Security components
        self.password_hasher = PasswordHasher()
        self.auth_config = AuthConfig(
            secret_key=str(uuid.uuid4()),  # In production, load from env
            algorithm="HS256",
            access_token_expiry=3600,      # 1 hour
            refresh_token_expiry=604800     # 7 days
        )
        self.authenticator = JWTAuthenticator(self.auth_config)
        
        # Default roles and permissions
        self.roles = {
            'user': ['read:own', 'write:own', 'delete:own'],
            'moderator': ['read:any', 'update:any', 'delete:own'],
            'admin': ['read:any', 'write:any', 'delete:any', 'admin:all']
        }
        
        # Pre-create admin user for demo
        self._create_admin_user()
        
        # Register all RPC methods
        self._register_methods()
        
        self.log_info("UserService initialized", version=self.version)
    
    def _register_methods(self):
        """Register all RPC methods with the service."""
        # User management
        self.register(self.create_user)
        self.register(self.get_user)
        self.register(self.update_user)
        self.register(self.delete_user)
        self.register(self.list_users)
        self.register(self.search_users)
        
        # Authentication
        self.register(self.authenticate)
        self.register(self.verify_token)
        self.register(self.refresh_token)
        self.register(self.logout)
        self.register(self.logout_all)
        
        # Password management
        self.register(self.change_password)
        self.register(self.reset_password)
        self.register(self.confirm_password_reset)
        
        # Email verification
        self.register(self.verify_email)
        self.register(self.resend_verification)
        
        # User stats and utilities
        self.register(self.get_user_stats)
        self.register(self.get_user_by_email)
        self.register(self.update_user_status)
        self.register(self.assign_role)
        self.register(self.revoke_role)
    
    def _create_admin_user(self):
        """Create default admin user for demo purposes."""
        admin_id = str(uuid.uuid4())
        admin = {
            'user_id': admin_id,
            'username': 'admin',
            'email': 'admin@nexusrpc.local',
            'password_hash': self.password_hasher.hash_password('admin123'),
            'full_name': 'System Administrator',
            'roles': ['admin'],
            'permissions': self.roles['admin'],
            'status': 'active',
            'email_verified': True,
            'created_at': time.time(),
            'updated_at': time.time(),
            'last_login': None,
            'login_count': 0,
            'profile': {
                'department': 'IT',
                'title': 'Administrator',
                'phone': None,
                'avatar': None,
                'timezone': 'UTC',
                'locale': 'en-US'
            },
            'metadata': {
                'source': 'system',
                'created_by': 'system'
            }
        }
        self.users[admin_id] = admin
        self.log_info("Default admin user created", username='admin')
    
    # ==================== User Management Methods ====================
    
    def create_user(self, username: str, email: str, password: str,
                   full_name: str = None, **kwargs) -> Dict:
        """
        Create a new user account.
        
        Args:
            username: Unique username
            email: Unique email address
            password: User password (will be hashed)
            full_name: Optional full name
            **kwargs: Additional profile fields
            
        Returns:
            Dict: Created user information (without sensitive data)
            
        Raises:
            ValueError: If username/email already exists or validation fails
            
        Example:
            >>> user = service.create_user(
            ...     username="john_doe",
            ...     email="john@example.com",
            ...     password="SecurePass123!",
            ...     full_name="John Doe",
            ...     department="Engineering"
            ... )
        """
        # Validate input
        self._validate_username(username)
        self._validate_email(email)
        self._validate_password(password)
        
        # Check uniqueness
        if self._username_exists(username):
            raise ValueError(f"Username '{username}' already exists")
        
        if self._email_exists(email):
            raise ValueError(f"Email '{email}' already registered")
        
        # Generate user ID
        user_id = str(uuid.uuid4())
        
        # Create verification token
        verification_token = str(uuid.uuid4())
        self.email_verifications[verification_token] = user_id
        
        # Build user object
        user = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'password_hash': self.password_hasher.hash_password(password),
            'full_name': full_name or username,
            'roles': ['user'],
            'permissions': self.roles['user'].copy(),
            'status': 'active',
            'email_verified': False,
            'verification_token': verification_token,
            'created_at': time.time(),
            'updated_at': time.time(),
            'last_login': None,
            'login_count': 0,
            'profile': {
                'avatar': None,
                'phone': kwargs.get('phone'),
                'department': kwargs.get('department'),
                'title': kwargs.get('title'),
                'location': kwargs.get('location'),
                'timezone': kwargs.get('timezone', 'UTC'),
                'locale': kwargs.get('locale', 'en-US'),
                'bio': kwargs.get('bio'),
                'website': kwargs.get('website'),
                'social_links': kwargs.get('social_links', {})
            },
            'metadata': {
                'source': kwargs.get('source', 'api'),
                'created_by': kwargs.get('created_by', 'self'),
                'ip_address': kwargs.get('ip_address'),
                'user_agent': kwargs.get('user_agent')
            },
            'preferences': {
                'notifications': kwargs.get('notifications', True),
                'newsletter': kwargs.get('newsletter', False),
                'theme': kwargs.get('theme', 'light'),
                'language': kwargs.get('language', 'en')
            }
        }
        
        # Store user
        self.users[user_id] = user
        
        self.log_info("User created",
                     user_id=user_id,
                     username=username,
                     email=email)
        
        # Return user without sensitive data
        return self._sanitize_user(user)
    
    def get_user(self, user_id: str, requester_id: str = None) -> Dict:
        """
        Get user by ID with permission check.
        
        Args:
            user_id: ID of user to retrieve
            requester_id: ID of user making request (for permission check)
            
        Returns:
            Dict: User information
            
        Raises:
            ValueError: If user not found
            AuthorizationError: If requester lacks permission
        """
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        
        # Check permissions
        if requester_id and requester_id != user_id:
            requester = self.users.get(requester_id)
            if not requester or 'read:any' not in requester.get('permissions', []):
                raise AuthorizationError("Insufficient permissions to view this user")
        
        return self._sanitize_user(user)
    
    def get_user_by_email(self, email: str) -> Dict:
        """
        Get user by email address.
        
        Args:
            email: Email address to search for
            
        Returns:
            Dict: User information
            
        Raises:
            ValueError: If email not found
        """
        for user in self.users.values():
            if user['email'].lower() == email.lower():
                return self._sanitize_user(user)
        
        raise ValueError(f"No user found with email {email}")
    
    def update_user(self, user_id: str, requester_id: str = None, **updates) -> Dict:
        """
        Update user information.
        
        Args:
            user_id: ID of user to update
            requester_id: ID of user making request
            **updates: Fields to update
            
        Returns:
            Dict: Updated user information
            
        Raises:
            ValueError: If user not found or validation fails
            AuthorizationError: If requester lacks permission
        """
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        requester = self.users.get(requester_id) if requester_id else user
        
        # Check permissions
        if requester_id != user_id and 'update:any' not in requester.get('permissions', []):
            raise AuthorizationError("Insufficient permissions to update this user")
        
        # Allowed fields for regular users
        allowed_fields = {
            'full_name', 'email', 'profile', 'preferences'
        }
        
        # Admin-only fields
        admin_fields = {'status', 'roles', 'permissions', 'metadata'}
        
        for field, value in updates.items():
            if field in allowed_fields:
                if field == 'email':
                    self._validate_email(value)
                    if self._email_exists(value) and value != user['email']:
                        raise ValueError(f"Email {value} already in use")
                    user['email'] = value
                    user['email_verified'] = False
                elif field == 'profile':
                    user['profile'].update(value)
                elif field == 'preferences':
                    user['preferences'].update(value)
                else:
                    user[field] = value
                    
            elif field in admin_fields and 'admin:all' in requester.get('permissions', []):
                user[field] = value
                
            elif field in ['username', 'password_hash', 'user_id']:
                raise ValueError(f"Cannot update {field} directly")
        
        user['updated_at'] = time.time()
        
        self.log_info("User updated", user_id=user_id, fields=list(updates.keys()))
        
        return self._sanitize_user(user)
    
    def delete_user(self, user_id: str, requester_id: str = None) -> Dict:
        """
        Delete a user account.
        
        Args:
            user_id: ID of user to delete
            requester_id: ID of user making request
            
        Returns:
            Dict: Deletion confirmation
            
        Raises:
            ValueError: If user not found
            AuthorizationError: If requester lacks permission
        """
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        requester = self.users.get(requester_id) if requester_id else None
        
        # Check permissions (users can delete themselves, admins can delete anyone)
        if requester_id != user_id:
            if not requester or 'delete:any' not in requester.get('permissions', []):
                raise AuthorizationError("Insufficient permissions to delete this user")
        
        # Prevent deleting last admin
        if 'admin' in self.users[user_id].get('roles', []):
            admin_count = sum(1 for u in self.users.values() 
                            if 'admin' in u.get('roles', []))
            if admin_count <= 1:
                raise ValueError("Cannot delete the last admin user")
        
        # Remove user
        deleted_user = self.users.pop(user_id)
        
        # Remove sessions
        tokens_to_remove = []
        for token, uid in self.sessions.items():
            if uid == user_id:
                tokens_to_remove.append(token)
        
        for token in tokens_to_remove:
            del self.sessions[token]
        
        # Remove refresh tokens
        refresh_to_remove = []
        for token, uid in self.refresh_tokens.items():
            if uid == user_id:
                refresh_to_remove.append(token)
        
        for token in refresh_to_remove:
            del self.refresh_tokens[token]
        
        self.log_info("User deleted", user_id=user_id)
        
        return {
            'success': True,
            'user_id': user_id,
            'username': deleted_user['username'],
            'message': 'User account deleted successfully'
        }
    
    def list_users(self, requester_id: str = None, limit: int = 100,
                  offset: int = 0, include_inactive: bool = False) -> Dict:
        """
        List all users (admin only).
        
        Args:
            requester_id: ID of user making request
            limit: Maximum number of users to return
            offset: Number of users to skip
            include_inactive: Include inactive users
            
        Returns:
            Dict: List of users and pagination info
            
        Raises:
            AuthorizationError: If requester is not admin
        """
        # Check admin permission
        requester = self.users.get(requester_id) if requester_id else None
        if not requester or 'admin:all' not in requester.get('permissions', []):
            raise AuthorizationError("Admin access required")
        
        users_list = []
        
        for user in self.users.values():
            if not include_inactive and user['status'] != 'active':
                continue
            users_list.append(self._sanitize_user(user))
        
        # Sort by created_at
        users_list.sort(key=lambda x: x['created_at'], reverse=True)
        
        # Apply pagination
        paginated = users_list[offset:offset + limit]
        
        return {
            'total': len(users_list),
            'limit': limit,
            'offset': offset,
            'count': len(paginated),
            'users': paginated
        }
    
    def search_users(self, query: str, requester_id: str = None,
                    fields: List[str] = None, limit: int = 50) -> Dict:
        """
        Search users by criteria.
        
        Args:
            query: Search string
            requester_id: ID of user making request
            fields: Fields to search in (default: username, email, full_name)
            limit: Maximum results
            
        Returns:
            Dict: Search results
            
        Raises:
            AuthorizationError: If requester lacks permission
        """
        # Check permission (moderator+ can search)
        requester = self.users.get(requester_id) if requester_id else None
        if requester:
            perms = requester.get('permissions', [])
            if 'read:any' not in perms and 'admin:all' not in perms:
                raise AuthorizationError("Insufficient permissions to search users")
        
        if not fields:
            fields = ['username', 'email', 'full_name']
        
        results = []
        query = query.lower()
        
        for user in self.users.values():
            # Skip inactive users unless requester is admin
            if user['status'] != 'active' and requester and 'admin:all' not in requester.get('permissions', []):
                continue
            
            # Search in specified fields
            for field in fields:
                if field in user:
                    value = str(user[field]).lower()
                    if query in value:
                        results.append(self._sanitize_user(user))
                        break
                
                # Search in profile
                if field in user.get('profile', {}):
                    value = str(user['profile'][field]).lower()
                    if query in value:
                        results.append(self._sanitize_user(user))
                        break
            
            if len(results) >= limit:
                break
        
        return {
            'query': query,
            'count': len(results),
            'results': results[:limit]
        }
    
    # ==================== Authentication Methods ====================
    
    def authenticate(self, username_or_email: str, password: str) -> Dict:
        """
        Authenticate user and return JWT tokens.
        
        Args:
            username_or_email: Username or email
            password: User password
            
        Returns:
            Dict: Access token, refresh token, and user info
            
        Raises:
            AuthenticationError: If authentication fails
        """
        # Find user
        user = None
        for u in self.users.values():
            if u['username'] == username_or_email or u['email'] == username_or_email:
                user = u
                break
        
        if not user:
            self.log_warning("Authentication failed - user not found",
                           username=username_or_email)
            raise AuthenticationError("Invalid username/email or password")
        
        # Check account status
        if user['status'] != 'active':
            self.log_warning("Authentication failed - account inactive",
                           user_id=user['user_id'],
                           status=user['status'])
            raise AuthenticationError(f"Account is {user['status']}")
        
        # Verify password
        if not self.password_hasher.verify_password(password, user['password_hash']):
            self.log_warning("Authentication failed - invalid password",
                           user_id=user['user_id'])
            raise AuthenticationError("Invalid username/email or password")
        
        # Update login stats
        user['last_login'] = time.time()
        user['login_count'] = user.get('login_count', 0) + 1
        
        # Generate tokens
        access_token = self.authenticator.generate_access_token(
            user['user_id'],
            claims={
                'username': user['username'],
                'email': user['email'],
                'roles': user['roles'],
                'permissions': user['permissions']
            }
        )
        
        refresh_token = self.authenticator.generate_refresh_token(user['user_id'])
        
        # Store sessions
        self.sessions[access_token] = user['user_id']
        self.refresh_tokens[refresh_token] = user['user_id']
        
        self.log_info("User authenticated",
                     user_id=user['user_id'],
                     username=user['username'])
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': self.auth_config.access_token_expiry,
            'user': self._sanitize_user(user)
        }
    
    def verify_token(self, token: str) -> Dict:
        """
        Verify JWT token and return user info.
        
        Args:
            token: JWT access token
            
        Returns:
            Dict: Token validation result and user info
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            payload = self.authenticator.verify_token(token)
            user_id = payload.get('sub')
            
            if user_id not in self.users:
                raise AuthenticationError("User not found")
            
            user = self.users[user_id]
            
            # Check if session exists
            if token not in self.sessions:
                raise AuthenticationError("Session expired or revoked")
            
            return {
                'valid': True,
                'user_id': user_id,
                'username': user['username'],
                'email': user['email'],
                'roles': user['roles'],
                'permissions': user['permissions'],
                'expires_at': payload.get('exp')
            }
            
        except Exception as e:
            self.log_warning("Token verification failed", error=str(e))
            return {
                'valid': False,
                'error': str(e)
            }
    
    def refresh_token(self, refresh_token: str) -> Dict:
        """
        Get new access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dict: New access token
            
        Raises:
            AuthenticationError: If refresh token is invalid
        """
        # Verify refresh token exists
        if refresh_token not in self.refresh_tokens:
            raise AuthenticationError("Invalid refresh token")
        
        try:
            # Verify JWT
            payload = self.authenticator.verify_token(refresh_token)
            user_id = payload.get('sub')
            
            if user_id not in self.users:
                raise AuthenticationError("User not found")
            
            # Verify token matches stored
            if self.refresh_tokens[refresh_token] != user_id:
                raise AuthenticationError("Token mismatch")
            
            user = self.users[user_id]
            
            # Generate new access token
            access_token = self.authenticator.generate_access_token(
                user_id,
                claims={
                    'username': user['username'],
                    'email': user['email'],
                    'roles': user['roles']
                }
            )
            
            # Store new session
            self.sessions[access_token] = user_id
            
            self.log_info("Token refreshed", user_id=user_id)
            
            return {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': self.auth_config.access_token_expiry
            }
            
        except Exception as e:
            # Remove invalid refresh token
            if refresh_token in self.refresh_tokens:
                del self.refresh_tokens[refresh_token]
            raise AuthenticationError(f"Token refresh failed: {e}")
    
    def logout(self, token: str) -> Dict:
        """
        Logout user by invalidating access token.
        
        Args:
            token: Access token to invalidate
            
        Returns:
            Dict: Logout confirmation
        """
        if token in self.sessions:
            user_id = self.sessions[token]
            del self.sessions[token]
            self.log_info("User logged out", user_id=user_id)
            return {'success': True, 'message': 'Logged out successfully'}
        else:
            return {'success': False, 'message': 'Token not found'}
    
    def logout_all(self, user_id: str, requester_id: str = None) -> Dict:
        """
        Logout user from all devices.
        
        Args:
            user_id: ID of user to logout
            requester_id: ID of user making request
            
        Returns:
            Dict: Logout confirmation
            
        Raises:
            AuthorizationError: If requester lacks permission
        """
        # Check permission (users can logout themselves, admins can logout anyone)
        if requester_id != user_id:
            requester = self.users.get(requester_id)
            if not requester or 'admin:all' not in requester.get('permissions', []):
                raise AuthorizationError("Insufficient permissions")
        
        # Remove all sessions for user
        tokens_removed = []
        for token, uid in list(self.sessions.items()):
            if uid == user_id:
                del self.sessions[token]
                tokens_removed.append(token)
        
        # Remove refresh tokens
        refresh_removed = []
        for token, uid in list(self.refresh_tokens.items()):
            if uid == user_id:
                del self.refresh_tokens[token]
                refresh_removed.append(token)
        
        self.log_info("User logged out from all devices",
                     user_id=user_id,
                     sessions=len(tokens_removed))
        
        return {
            'success': True,
            'sessions_terminated': len(tokens_removed),
            'refresh_tokens_removed': len(refresh_removed),
            'message': 'Logged out from all devices'
        }
    
    # ==================== Password Management ====================
    
    def change_password(self, user_id: str, current_password: str,
                       new_password: str) -> Dict:
        """
        Change user password.
        
        Args:
            user_id: ID of user
            current_password: Current password for verification
            new_password: New password
            
        Returns:
            Dict: Password change confirmation
            
        Raises:
            ValueError: If user not found or password validation fails
            AuthenticationError: If current password is incorrect
        """
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        
        # Verify current password
        if not self.password_hasher.verify_password(current_password, user['password_hash']):
            raise AuthenticationError("Current password is incorrect")
        
        # Validate new password
        self._validate_password(new_password)
        
        # Update password
        user['password_hash'] = self.password_hasher.hash_password(new_password)
        user['updated_at'] = time.time()
        
        # Optionally invalidate all existing sessions
        self.logout_all(user_id, user_id)
        
        self.log_info("Password changed", user_id=user_id)
        
        return {
            'success': True,
            'message': 'Password changed successfully'
        }
    
    def reset_password(self, email: str) -> Dict:
        """
        Initiate password reset process.
        
        Args:
            email: Email address of user
            
        Returns:
            Dict: Reset confirmation with token (for demo)
            
        Note:
            In production, this would send an email. For demo,
            we return the reset token directly.
        """
        # Find user by email
        user = None
        for u in self.users.values():
            if u['email'].lower() == email.lower():
                user = u
                break
        
        if not user:
            # Return success even if user not found (security)
            self.log_warning("Password reset attempted for non-existent email",
                           email=email)
            return {
                'success': True,
                'message': 'If the email exists, a reset link has been sent'
            }
        
        # Generate reset token
        reset_token = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        self.password_resets[reset_token] = {
            'user_id': user['user_id'],
            'email': email,
            'created_at': time.time(),
            'expires_at': expires_at.timestamp(),
            'used': False
        }
        
        self.log_info("Password reset initiated",
                     user_id=user['user_id'],
                     email=email)
        
        # In production, send email here
        return {
            'success': True,
            'reset_token': reset_token,  # In production, don't return this!
            'expires_in': 86400,
            'message': 'Password reset email sent'
        }
    
    def confirm_password_reset(self, reset_token: str, new_password: str) -> Dict:
        """
        Complete password reset with token.
        
        Args:
            reset_token: Token from reset_password call
            new_password: New password
            
        Returns:
            Dict: Reset confirmation
            
        Raises:
            ValueError: If token is invalid or expired
        """
        if reset_token not in self.password_resets:
            raise ValueError("Invalid or expired reset token")
        
        reset_data = self.password_resets[reset_token]
        
        # Check expiration
        if time.time() > reset_data['expires_at']:
            del self.password_resets[reset_token]
            raise ValueError("Reset token has expired")
        
        # Check if already used
        if reset_data.get('used'):
            raise ValueError("Reset token has already been used")
        
        user_id = reset_data['user_id']
        
        if user_id not in self.users:
            raise ValueError("User not found")
        
        user = self.users[user_id]
        
        # Validate new password
        self._validate_password(new_password)
        
        # Update password
        user['password_hash'] = self.password_hasher.hash_password(new_password)
        user['updated_at'] = time.time()
        
        # Mark token as used
        reset_data['used'] = True
        reset_data['completed_at'] = time.time()
        
        # Invalidate all sessions
        self.logout_all(user_id, user_id)
        
        self.log_info("Password reset completed", user_id=user_id)
        
        return {
            'success': True,
            'message': 'Password reset successfully'
        }
    
    # ==================== Email Verification ====================
    
    def verify_email(self, verification_token: str) -> Dict:
        """
        Verify user's email address.
        
        Args:
            verification_token: Token from email verification
            
        Returns:
            Dict: Verification confirmation
            
        Raises:
            ValueError: If token is invalid
        """
        if verification_token not in self.email_verifications:
            raise ValueError("Invalid verification token")
        
        user_id = self.email_verifications[verification_token]
        
        if user_id not in self.users:
            raise ValueError("User not found")
        
        user = self.users[user_id]
        user['email_verified'] = True
        user['updated_at'] = time.time()
        
        # Remove used token
        del self.email_verifications[verification_token]
        
        self.log_info("Email verified", user_id=user_id, email=user['email'])
        
        return {
            'success': True,
            'message': 'Email verified successfully'
        }
    
    def resend_verification(self, user_id: str) -> Dict:
        """
        Resend email verification token.
        
        Args:
            user_id: ID of user
            
        Returns:
            Dict: Verification confirmation with new token (for demo)
            
        Raises:
            ValueError: If user not found or already verified
        """
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        
        if user['email_verified']:
            raise ValueError("Email already verified")
        
        # Generate new verification token
        verification_token = str(uuid.uuid4())
        self.email_verifications[verification_token] = user_id
        user['verification_token'] = verification_token
        
        self.log_info("Verification email resent",
                     user_id=user_id,
                     email=user['email'])
        
        # In production, send email here
        return {
            'success': True,
            'verification_token': verification_token,  # In production, don't return this!
            'message': 'Verification email sent'
        }
    
    # ==================== Role Management ====================
    
    def assign_role(self, user_id: str, role: str, requester_id: str = None) -> Dict:
        """
        Assign a role to user (admin only).
        
        Args:
            user_id: ID of user
            role: Role to assign
            requester_id: ID of admin making request
            
        Returns:
            Dict: Updated user info
            
        Raises:
            ValueError: If user or role not found
            AuthorizationError: If requester is not admin
        """
        # Check admin permission
        requester = self.users.get(requester_id) if requester_id else None
        if not requester or 'admin:all' not in requester.get('permissions', []):
            raise AuthorizationError("Admin access required")
        
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        if role not in self.roles:
            raise ValueError(f"Unknown role: {role}")
        
        user = self.users[user_id]
        
        if role not in user['roles']:
            user['roles'].append(role)
            # Add role permissions
            for perm in self.roles[role]:
                if perm not in user['permissions']:
                    user['permissions'].append(perm)
            
            user['updated_at'] = time.time()
            
            self.log_info("Role assigned",
                         user_id=user_id,
                         role=role,
                         by=requester_id)
        
        return self._sanitize_user(user)
    
    def revoke_role(self, user_id: str, role: str, requester_id: str = None) -> Dict:
        """
        Revoke a role from user (admin only).
        
        Args:
            user_id: ID of user
            role: Role to revoke
            requester_id: ID of admin making request
            
        Returns:
            Dict: Updated user info
            
        Raises:
            ValueError: If user or role not found
            AuthorizationError: If requester is not admin
        """
        # Check admin permission
        requester = self.users.get(requester_id) if requester_id else None
        if not requester or 'admin:all' not in requester.get('permissions', []):
            raise AuthorizationError("Admin access required")
        
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        
        # Prevent revoking admin from last admin
        if role == 'admin':
            admin_count = sum(1 for u in self.users.values() 
                            if 'admin' in u.get('roles', []))
            if admin_count <= 1 and 'admin' in user['roles']:
                raise ValueError("Cannot revoke admin from the last administrator")
        
        if role in user['roles']:
            user['roles'].remove(role)
            # Remove role permissions
            for perm in self.roles[role]:
                if perm in user['permissions']:
                    # Only remove if not granted by another role
                    keep = False
                    for r in user['roles']:
                        if perm in self.roles.get(r, []):
                            keep = True
                            break
                    if not keep:
                        user['permissions'].remove(perm)
            
            user['updated_at'] = time.time()
            
            self.log_info("Role revoked",
                         user_id=user_id,
                         role=role,
                         by=requester_id)
        
        return self._sanitize_user(user)
    
    def update_user_status(self, user_id: str, status: str,
                          requester_id: str = None) -> Dict:
        """
        Update user account status (admin only).
        
        Args:
            user_id: ID of user
            status: New status (active, suspended, locked, disabled)
            requester_id: ID of admin making request
            
        Returns:
            Dict: Updated user info
            
        Raises:
            ValueError: If user not found or invalid status
            AuthorizationError: If requester is not admin
        """
        valid_statuses = ['active', 'suspended', 'locked', 'disabled']
        
        if status not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
        
        # Check admin permission
        requester = self.users.get(requester_id) if requester_id else None
        if not requester or 'admin:all' not in requester.get('permissions', []):
            raise AuthorizationError("Admin access required")
        
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        
        # Prevent disabling last admin
        if status != 'active' and 'admin' in user.get('roles', []):
            admin_count = sum(1 for u in self.users.values() 
                            if 'admin' in u.get('roles', []))
            if admin_count <= 1:
                raise ValueError("Cannot disable the last administrator")
        
        old_status = user['status']
        user['status'] = status
        user['updated_at'] = time.time()
        
        # If suspending/locking, invalidate sessions
        if status in ['suspended', 'locked', 'disabled']:
            self.logout_all(user_id, requester_id)
        
        self.log_info("User status updated",
                     user_id=user_id,
                     old_status=old_status,
                     new_status=status,
                     by=requester_id)
        
        return self._sanitize_user(user)
    
    # ==================== Stats and Utilities ====================
    
    def get_user_stats(self) -> Dict:
        """
        Get user statistics.
        
        Returns:
            Dict: User statistics
        """
        total = len(self.users)
        active = sum(1 for u in self.users.values() if u['status'] == 'active')
        verified = sum(1 for u in self.users.values() if u['email_verified'])
        
        role_counts = {}
        for u in self.users.values():
            for role in u.get('roles', []):
                role_counts[role] = role_counts.get(role, 0) + 1
        
        status_counts = {}
        for u in self.users.values():
            status = u.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_users': total,
            'active_users': active,
            'inactive_users': total - active,
            'verified_emails': verified,
            'unverified_emails': total - verified,
            'roles': role_counts,
            'statuses': status_counts,
            'active_sessions': len(self.sessions),
            'active_refresh_tokens': len(self.refresh_tokens),
            'timestamp': time.time()
        }
    
    # ==================== Helper Methods ====================
    
    def _validate_username(self, username: str):
        """Validate username format."""
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(username) > 30:
            raise ValueError("Username must be at most 30 characters")
        if not re.match(r'^[a-zA-Z0-9_\.]+$', username):
            raise ValueError("Username can only contain letters, numbers, dots, and underscores")
    
    def _validate_email(self, email: str):
        """Validate email format."""
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            raise ValueError("Invalid email format")
        if len(email) > 254:
            raise ValueError("Email too long")
    
    def _validate_password(self, password: str):
        """Validate password strength."""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', password):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError("Password must contain at least one special character")
    
    def _username_exists(self, username: str) -> bool:
        """Check if username already exists."""
        return any(u['username'].lower() == username.lower() 
                  for u in self.users.values())
    
    def _email_exists(self, email: str) -> bool:
        """Check if email already exists."""
        return any(u['email'].lower() == email.lower() 
                  for u in self.users.values())
    
    def _sanitize_user(self, user: Dict) -> Dict:
        """
        Remove sensitive data from user object.
        
        Args:
            user: Raw user dictionary
            
        Returns:
            Dict: User without sensitive fields
        """
        sanitized = user.copy()
        
        # Remove sensitive fields
        sensitive_fields = [
            'password_hash',
            'verification_token',
            'reset_token',
            'email_verifications'
        ]
        
        for field in sensitive_fields:
            sanitized.pop(field, None)
        
        return sanitized


def main():
    """Run user service standalone."""
    import logging
    from rpc.server import NexusRPCServer
    from security.tls import TLSConfig
    from rpc.config import NexusRPCConfig
    
    # Configure server
    config = NexusRPCConfig()
    config.service_name = "UserService"
    config.server.port = 50052  # Different port from banking service
    config.tls.enabled = True
    config.tls.certfile = "security/certs/server.crt"
    config.tls.keyfile = "security/certs/server.key"
    config.tls.cafile = "security/certs/ca.crt"
    
    # Create TLS config
    tls_config = TLSConfig(
        certfile=config.tls.certfile,
        keyfile=config.tls.keyfile,
        cafile=config.tls.cafile
    )
    
    # Create and start server
    server = NexusRPCServer(
        host="0.0.0.0",
        port=config.server.port,
        tls_config=tls_config,
        max_workers=10
    )
    
    # Register service
    server.register_service(UserService())
    
    print(f"🚀 User Service starting on port {config.server.port}...")
    print(f"🔒 TLS Enabled: {config.tls.enabled}")
    print(f"📡 Press Ctrl+C to stop\n")
    print(f"Default admin user:")
    print(f"  Username: admin")
    print(f"  Password: admin123")
    print(f"  Email: admin@nexusrpc.local\n")
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
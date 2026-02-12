"""
NexusRPC User Management Client
Complete client for interacting with UserService

Features:
- User registration and login
- Profile management
- Password management
- Admin operations
- Interactive CLI
"""

import time
import getpass
import json
from typing import Dict, Optional, List
from datetime import datetime

from rpc.client import RPCClient
from security.tls import TLSConfig
from rpc.errors import RPCError, AuthenticationError, AuthorizationError


class UserClient:
    """
    Complete client for User Management Service.
    
    This client provides a user-friendly interface to all UserService
    operations with proper error handling and formatted output.
    """
    
    def __init__(self, host='localhost', port=50052, use_tls=True):
        """
        Initialize the user client.
        
        Args:
            host: Server hostname
            port: Server port (default: 50052)
            use_tls: Enable TLS encryption
        """
        # Configure TLS
        self.tls_config = None
        if use_tls:
            self.tls_config = TLSConfig(
                certfile='security/certs/client.crt',
                keyfile='security/certs/client.key',
                cafile='security/certs/ca.crt',
                verify_mode='required'
            )
        
        # Create RPC client
        self.client = RPCClient(
            host=host,
            port=port,
            tls_config=self.tls_config,
            pool_size=5,
            timeout=10.0,
            retries=3
        )
        
        # Session state
        self.access_token = None
        self.refresh_token = None
        self.current_user = None
        self.current_user_id = None
    
    # ==================== Authentication Methods ====================
    
    def register(self, username: str = None, email: str = None,
                password: str = None, full_name: str = None) -> Dict:
        """
        Register a new user account.
        
        Args:
            username: Desired username (will prompt if None)
            email: Email address (will prompt if None)
            password: Password (will prompt securely if None)
            full_name: Full name (optional)
            
        Returns:
            Dict: Created user information
        """
        print(f"\n{'='*60}")
        print(f"📝 USER REGISTRATION")
        print(f"{'='*60}")
        
        # Get user input if not provided
        if not username:
            username = input("   Username: ").strip()
        
        if not email:
            email = input("   Email: ").strip()
        
        if not full_name:
            full_name = input("   Full name (optional): ").strip() or None
        
        if not password:
            while True:
                password = getpass.getpass("   Password: ")
                confirm = getpass.getpass("   Confirm password: ")
                
                if password != confirm:
                    print("   ❌ Passwords do not match. Try again.")
                else:
                    break
        
        try:
            response = self.client.call(
                'UserService',
                'create_user',
                username,
                email,
                password,
                full_name,
                source='client',
                notifications=True,
                newsletter=False
            )
            
            print(f"\n{'='*60}")
            print(f"✅ REGISTRATION SUCCESSFUL")
            print(f"{'='*60}")
            print(f"   User ID:     {response['user_id']}")
            print(f"   Username:    {response['username']}")
            print(f"   Email:       {response['email']}")
            print(f"   Full Name:   {response.get('full_name', 'N/A')}")
            print(f"   Created:     {datetime.fromtimestamp(response['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}\n")
            
            return response
            
        except RPCError as e:
            print(f"\n❌ Registration failed: {e}")
            raise
    
    def login(self, username_or_email: str = None, password: str = None) -> Dict:
        """
        Authenticate and get access tokens.
        
        Args:
            username_or_email: Username or email (will prompt if None)
            password: Password (will prompt securely if None)
            
        Returns:
            Dict: Authentication response with tokens
        """
        print(f"\n{'='*60}")
        print(f"🔐 LOGIN")
        print(f"{'='*60}")
        
        # Get user input if not provided
        if not username_or_email:
            username_or_email = input("   Username or Email: ").strip()
        
        if not password:
            password = getpass.getpass("   Password: ")
        
        try:
            response = self.client.call(
                'UserService',
                'authenticate',
                username_or_email,
                password
            )
            
            # Store session data
            self.access_token = response['access_token']
            self.refresh_token = response['refresh_token']
            self.current_user = response['user']
            self.current_user_id = response['user']['user_id']
            
            print(f"\n{'='*60}")
            print(f"✅ LOGIN SUCCESSFUL")
            print(f"{'='*60}")
            print(f"   Welcome, {response['user']['username']}!")
            print(f"   User ID:     {response['user']['user_id']}")
            print(f"   Roles:       {', '.join(response['user'].get('roles', []))}")
            print(f"   Token expires in: {response['expires_in']} seconds")
            print(f"{'='*60}\n")
            
            return response
            
        except AuthenticationError as e:
            print(f"\n❌ Login failed: {e}")
            raise
        except RPCError as e:
            print(f"\n❌ Login failed: {e}")
            raise
    
    def logout(self) -> Dict:
        """Logout and invalidate current session."""
        if not self.access_token:
            print("\n⚠️  Not logged in")
            return {'success': False, 'message': 'Not logged in'}
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'logout',
                self.access_token,
                token=self.access_token
            )
            
            # Clear session
            self.access_token = None
            self.refresh_token = None
            self.current_user = None
            self.current_user_id = None
            
            print(f"\n{'='*60}")
            print(f"👋 LOGOUT SUCCESSFUL")
            print(f"{'='*60}\n")
            
            return response
            
        except Exception as e:
            print(f"\n❌ Logout failed: {e}")
            raise
    
    def logout_all(self) -> Dict:
        """Logout from all devices."""
        if not self.current_user_id:
            print("\n⚠️  Not logged in")
            return {'success': False, 'message': 'Not logged in'}
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'logout_all',
                self.current_user_id,
                self.current_user_id,
                token=self.access_token
            )
            
            # Clear session
            self.access_token = None
            self.refresh_token = None
            self.current_user = None
            self.current_user_id = None
            
            print(f"\n{'='*60}")
            print(f"✅ LOGGED OUT FROM ALL DEVICES")
            print(f"{'='*60}")
            print(f"   Sessions terminated: {response.get('sessions_terminated', 0)}")
            print(f"{'='*60}\n")
            
            return response
            
        except Exception as e:
            print(f"\n❌ Logout all failed: {e}")
            raise
    
    def refresh_access_token(self) -> Dict:
        """Refresh the access token using refresh token."""
        if not self.refresh_token:
            print("\n⚠️  No refresh token available")
            return None
        
        try:
            response = self.client.call(
                'UserService',
                'refresh_token',
                self.refresh_token
            )
            
            self.access_token = response['access_token']
            
            print("✅ Access token refreshed")
            return response
            
        except AuthenticationError as e:
            print(f"\n❌ Token refresh failed: {e}")
            self.access_token = None
            self.refresh_token = None
            self.current_user = None
            self.current_user_id = None
            raise
    
    def verify_token(self) -> Dict:
        """Verify the current access token."""
        if not self.access_token:
            print("\n⚠️  No access token available")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'verify_token',
                self.access_token,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"🔑 TOKEN VERIFICATION")
            print(f"{'='*60}")
            print(f"   Valid:       {response['valid']}")
            if response.get('valid'):
                print(f"   User:        {response.get('username')}")
                print(f"   Email:       {response.get('email')}")
                print(f"   Roles:       {', '.join(response.get('roles', []))}")
                print(f"   Expires:     {datetime.fromtimestamp(response.get('expires_at', 0)).strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print(f"   Error:       {response.get('error')}")
            print(f"{'='=60}\n")
            
            return response
            
        except Exception as e:
            print(f"\n❌ Token verification failed: {e}")
            return {'valid': False, 'error': str(e)}
    
    # ==================== User Profile Methods ====================
    
    def get_profile(self, user_id: str = None) -> Dict:
        """
        Get user profile.
        
        Args:
            user_id: User ID (defaults to current user)
            
        Returns:
            Dict: User profile information
        """
        if not user_id:
            if not self.current_user_id:
                print("\n⚠️  Not logged in and no user ID provided")
                return None
            user_id = self.current_user_id
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'get_user',
                user_id,
                self.current_user_id,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"👤 USER PROFILE")
            print(f"{'='*60}")
            print(f"   User ID:     {response['user_id']}")
            print(f"   Username:    {response['username']}")
            print(f"   Email:       {response['email']}")
            print(f"   Full Name:   {response.get('full_name', 'N/A')}")
            print(f"   Status:      {response.get('status', 'N/A')}")
            print(f"   Verified:    {'✅' if response.get('email_verified') else '❌'}")
            print(f"   Roles:       {', '.join(response.get('roles', []))}")
            print(f"   Created:     {datetime.fromtimestamp(response['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   Last Login:  {datetime.fromtimestamp(response.get('last_login', 0)).strftime('%Y-%m-%d %H:%M:%S') if response.get('last_login') else 'Never'}")
            print(f"   Login Count: {response.get('login_count', 0)}")
            print(f"\n   Profile:")
            for key, value in response.get('profile', {}).items():
                if value:
                    print(f"     {key}: {value}")
            print(f"\n   Preferences:")
            for key, value in response.get('preferences', {}).items():
                print(f"     {key}: {value}")
            print(f"{'='*60}\n")
            
            return response
            
        except AuthorizationError:
            print("\n❌ You don't have permission to view this profile")
            raise
        except Exception as e:
            print(f"\n❌ Failed to get profile: {e}")
            raise
    
    def update_profile(self, **updates) -> Dict:
        """
        Update current user's profile.
        
        Args:
            **updates: Fields to update (email, full_name, profile.*, preferences.*)
            
        Returns:
            Dict: Updated user information
        """
        if not self.current_user_id:
            print("\n⚠️  You must be logged in to update your profile")
            return None
        
        print(f"\n{'='*60}")
        print(f"📝 UPDATE PROFILE")
        print(f"{'='*60}")
        
        # Interactive mode if no updates provided
        if not updates:
            print("\n   Leave blank to keep current value")
            
            email = input(f"   Email [{self.current_user.get('email', '')}]: ").strip()
            if email:
                updates['email'] = email
            
            full_name = input(f"   Full Name [{self.current_user.get('full_name', '')}]: ").strip()
            if full_name:
                updates['full_name'] = full_name
            
            # Profile updates
            profile_updates = {}
            phone = input(f"   Phone [{self.current_user.get('profile', {}).get('phone', '')}]: ").strip()
            if phone:
                profile_updates['phone'] = phone
            
            department = input(f"   Department [{self.current_user.get('profile', {}).get('department', '')}]: ").strip()
            if department:
                profile_updates['department'] = department
            
            location = input(f"   Location [{self.current_user.get('profile', {}).get('location', '')}]: ").strip()
            if location:
                profile_updates['location'] = location
            
            if profile_updates:
                updates['profile'] = profile_updates
            
            # Preferences
            pref_updates = {}
            theme = input(f"   Theme (light/dark) [{self.current_user.get('preferences', {}).get('theme', 'light')}]: ").strip()
            if theme:
                pref_updates['theme'] = theme
            
            notifications = input(f"   Enable notifications? (yes/no) [{self.current_user.get('preferences', {}).get('notifications', True)}]: ").strip()
            if notifications:
                pref_updates['notifications'] = notifications.lower() in ['yes', 'y', 'true']
            
            if pref_updates:
                updates['preferences'] = pref_updates
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'update_user',
                self.current_user_id,
                self.current_user_id,
                **updates,
                token=self.access_token
            )
            
            # Update cached user
            self.current_user = response
            
            print(f"\n✅ Profile updated successfully!")
            print(f"\n   Updated fields: {', '.join(updates.keys())}")
            print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to update profile: {e}")
            raise
    
    # ==================== Password Management ====================
    
    def change_password(self, current_password: str = None,
                       new_password: str = None) -> Dict:
        """
        Change user password.
        
        Args:
            current_password: Current password (will prompt if None)
            new_password: New password (will prompt if None)
            
        Returns:
            Dict: Password change confirmation
        """
        if not self.current_user_id:
            print("\n⚠️  You must be logged in to change your password")
            return None
        
        print(f"\n{'='*60}")
        print(f"🔑 CHANGE PASSWORD")
        print(f"{'='*60}")
        
        if not current_password:
            current_password = getpass.getpass("   Current password: ")
        
        if not new_password:
            while True:
                new_password = getpass.getpass("   New password: ")
                confirm = getpass.getpass("   Confirm new password: ")
                
                if new_password != confirm:
                    print("   ❌ Passwords do not match. Try again.")
                else:
                    break
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'change_password',
                self.current_user_id,
                current_password,
                new_password,
                token=self.access_token
            )
            
            print(f"\n✅ Password changed successfully!")
            print(f"   You have been logged out from all devices.")
            print(f"   Please login again with your new password.\n")
            
            # Clear session
            self.access_token = None
            self.refresh_token = None
            
            return response
            
        except AuthenticationError:
            print(f"\n❌ Current password is incorrect")
            raise
        except Exception as e:
            print(f"\n❌ Failed to change password: {e}")
            raise
    
    def reset_password(self, email: str = None) -> Dict:
        """
        Initiate password reset.
        
        Args:
            email: Email address (will prompt if None)
            
        Returns:
            Dict: Reset confirmation with token
        """
        print(f"\n{'='*60}")
        print(f"🔄 PASSWORD RESET")
        print(f"{'='*60}")
        
        if not email:
            email = input("   Email address: ").strip()
        
        try:
            response = self.client.call(
                'UserService',
                'reset_password',
                email
            )
            
            print(f"\n✅ Password reset initiated!")
            print(f"   Check your email for further instructions.")
            print(f"\n   [DEMO MODE] Reset token: {response.get('reset_token')}")
            print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to initiate password reset: {e}")
            raise
    
    def confirm_password_reset(self, reset_token: str = None,
                              new_password: str = None) -> Dict:
        """
        Complete password reset with token.
        
        Args:
            reset_token: Token from reset_password (will prompt if None)
            new_password: New password (will prompt if None)
            
        Returns:
            Dict: Reset confirmation
        """
        print(f"\n{'='*60}")
        print(f"✅ CONFIRM PASSWORD RESET")
        print(f"{'='*60}")
        
        if not reset_token:
            reset_token = input("   Reset token: ").strip()
        
        if not new_password:
            while True:
                new_password = getpass.getpass("   New password: ")
                confirm = getpass.getpass("   Confirm password: ")
                
                if new_password != confirm:
                    print("   ❌ Passwords do not match. Try again.")
                else:
                    break
        
        try:
            response = self.client.call(
                'UserService',
                'confirm_password_reset',
                reset_token,
                new_password
            )
            
            print(f"\n✅ Password reset successful!")
            print(f"   You can now login with your new password.\n")
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to reset password: {e}")
            raise
    
    # ==================== Admin Methods ====================
    
    def list_users(self, limit: int = 20, offset: int = 0,
                  include_inactive: bool = False) -> Dict:
        """
        List all users (admin only).
        
        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip
            include_inactive: Include inactive users
            
        Returns:
            Dict: List of users and pagination info
        """
        if not self.access_token:
            print("\n⚠️  Admin access required - please login first")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'list_users',
                self.current_user_id,
                limit,
                offset,
                include_inactive,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"📋 USER LIST (Admin)")
            print(f"{'='*60}")
            print(f"   Total users: {response['total']}")
            print(f"   Showing: {response['offset']+1}-{response['offset']+response['count']}")
            print(f"{'='*60}\n")
            
            for i, user in enumerate(response['users'], 1):
                print(f"   {i}. {user['username']} ({user['email']})")
                print(f"      ID: {user['user_id']}")
                print(f"      Status: {user.get('status', 'unknown')} {'✅' if user.get('email_verified') else '❌'}")
                print(f"      Roles: {', '.join(user.get('roles', []))}")
                print()
            
            return response
            
        except AuthorizationError:
            print("\n❌ Admin access required")
            raise
        except Exception as e:
            print(f"\n❌ Failed to list users: {e}")
            raise
    
    def search_users(self, query: str, limit: int = 20) -> Dict:
        """
        Search for users.
        
        Args:
            query: Search string
            limit: Maximum results
            
        Returns:
            Dict: Search results
        """
        if not self.access_token:
            print("\n⚠️  Login required to search users")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'search_users',
                query,
                self.current_user_id,
                None,
                limit,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"🔍 SEARCH RESULTS: '{query}'")
            print(f"{'='*60}")
            print(f"   Found {response['count']} users")
            print(f"{'='*60}\n")
            
            for i, user in enumerate(response['results'], 1):
                print(f"   {i}. {user['username']} ({user['email']})")
                print(f"      Name: {user.get('full_name', 'N/A')}")
                print(f"      Status: {user.get('status', 'unknown')}")
                print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Search failed: {e}")
            raise
    
    def update_user_status(self, user_id: str, status: str) -> Dict:
        """
        Update user account status (admin only).
        
        Args:
            user_id: ID of user to update
            status: New status (active, suspended, locked, disabled)
            
        Returns:
            Dict: Updated user info
        """
        if not self.access_token:
            print("\n⚠️  Admin access required")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'update_user_status',
                user_id,
                status,
                self.current_user_id,
                token=self.access_token
            )
            
            print(f"\n✅ User status updated")
            print(f"   User: {response['username']}")
            print(f"   New status: {response['status']}")
            print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to update user status: {e}")
            raise
    
    def assign_role(self, user_id: str, role: str) -> Dict:
        """
        Assign role to user (admin only).
        
        Args:
            user_id: ID of user
            role: Role to assign (user, moderator, admin)
            
        Returns:
            Dict: Updated user info
        """
        if not self.access_token:
            print("\n⚠️  Admin access required")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'assign_role',
                user_id,
                role,
                self.current_user_id,
                token=self.access_token
            )
            
            print(f"\n✅ Role assigned")
            print(f"   User: {response['username']}")
            print(f"   New roles: {', '.join(response.get('roles', []))}")
            print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to assign role: {e}")
            raise
    
    def revoke_role(self, user_id: str, role: str) -> Dict:
        """
        Revoke role from user (admin only).
        
        Args:
            user_id: ID of user
            role: Role to revoke
            
        Returns:
            Dict: Updated user info
        """
        if not self.access_token:
            print("\n⚠️  Admin access required")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'revoke_role',
                user_id,
                role,
                self.current_user_id,
                token=self.access_token
            )
            
            print(f"\n✅ Role revoked")
            print(f"   User: {response['username']}")
            print(f"   Updated roles: {', '.join(response.get('roles', []))}")
            print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to revoke role: {e}")
            raise
    
    def delete_user(self, user_id: str) -> Dict:
        """
        Delete user account (admin only).
        
        Args:
            user_id: ID of user to delete
            
        Returns:
            Dict: Deletion confirmation
        """
        if not self.access_token:
            print("\n⚠️  Admin access required")
            return None
        
        # Confirmation
        print(f"\n{'='*60}")
        print(f"⚠️  DELETE USER ACCOUNT")
        print(f"{'='*60}")
        print(f"   You are about to delete user: {user_id}")
        confirm = input("   Type 'yes' to confirm: ").strip()
        
        if confirm.lower() != 'yes':
            print("   ❌ Deletion cancelled")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'delete_user',
                user_id,
                self.current_user_id,
                token=self.access_token
            )
            
            print(f"\n✅ User deleted successfully")
            print(f"   User: {response.get('username', user_id)}")
            print(f"   Message: {response.get('message', '')}")
            print()
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to delete user: {e}")
            raise
    
    # ==================== Utility Methods ====================
    
    def get_stats(self) -> Dict:
        """
        Get user statistics (admin only).
        
        Returns:
            Dict: User statistics
        """
        if not self.access_token:
            print("\n⚠️  Admin access required")
            return None
        
        try:
            response = self.client.call_with_auth(
                'UserService',
                'get_user_stats',
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"📊 USER STATISTICS")
            print(f"{'='*60}")
            print(f"   Total Users:      {response['total_users']}")
            print(f"   Active Users:     {response['active_users']}")
            print(f"   Inactive Users:   {response['inactive_users']}")
            print(f"   Verified Emails:  {response['verified_emails']}")
            print(f"   Active Sessions:  {response['active_sessions']}")
            print(f"\n   Roles:")
            for role, count in response.get('roles', {}).items():
                print(f"     {role}: {count}")
            print(f"\n   Statuses:")
            for status, count in response.get('statuses', {}).items():
                print(f"     {status}: {count}")
            print(f"{'='=60}\n")
            
            return response
            
        except Exception as e:
            print(f"\n❌ Failed to get statistics: {e}")
            raise
    
    def close(self):
        """Close the client connection."""
        self.client.close()
        print("🔌 Client connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# ==================== Interactive CLI ====================

def interactive_cli():
    """
    Interactive command-line interface for UserService.
    
    This provides a menu-driven interface for all user operations.
    """
    print(f"\n{'='*60}")
    print(f"🚀 NEXUSRPC USER MANAGEMENT SERVICE")
    print(f"{'='*60}")
    print(f"\n📡 Connecting to user service...")
    
    # Initialize client
    client = UserClient(host='localhost', port=50052, use_tls=True)
    
    def print_menu():
        """Print the main menu."""
        print(f"\n{'─'*60}")
        print(f"📋 MAIN MENU")
        print(f"{'─'*60}")
        
        if client.current_user:
            print(f"👤 Logged in as: {client.current_user.get('username', 'Unknown')}")
            print(f"   Roles: {', '.join(client.current_user.get('roles', []))}")
            print(f"{'─'*60}")
        
        print(f"1. 📝 Register")
        print(f"2. 🔐 Login")
        print(f"3. 👋 Logout")
        print(f"4. 🚪 Logout All Devices")
        print(f"5. 👤 View Profile")
        print(f"6. 📝 Update Profile")
        print(f"7. 🔑 Change Password")
        print(f"8. 🔄 Reset Password")
        print(f"9. 🔍 Verify Token")
        
        if client.current_user and 'admin' in client.current_user.get('roles', []):
            print(f"{'─'*60}")
            print(f"🛡️  ADMIN MENU")
            print(f"10. 📋 List Users")
            print(f"11. 🔍 Search Users")
            print(f"12. 📊 View Statistics")
            print(f"13. ⚙️  Update User Status")
            print(f"14. 👑 Assign Role")
            print(f"15. 📉 Revoke Role")
            print(f"16. 🗑️  Delete User")
        
        print(f"{'─'*60}")
        print(f"0. ❌ Exit")
        print(f"{'─'*60}")
    
    try:
        while True:
            print_menu()
            choice = input("\n📌 Select option: ").strip()
            
            if choice == '0':
                print(f"\n{'='*60}")
                print(f"👋 Thank you for using NexusRPC User Service!")
                print(f"{'='*60}\n")
                break
            
            elif choice == '1':
                client.register()
            
            elif choice == '2':
                client.login()
            
            elif choice == '3':
                client.logout()
            
            elif choice == '4':
                client.logout_all()
            
            elif choice == '5':
                client.get_profile()
            
            elif choice == '6':
                client.update_profile()
            
            elif choice == '7':
                client.change_password()
            
            elif choice == '8':
                print(f"\n{'─'*60}")
                print(f"🔄 PASSWORD RESET OPTIONS")
                print(f"{'─'*60}")
                print(f"1. Request reset token")
                print(f"2. Confirm reset with token")
                subchoice = input("\nSelect option: ").strip()
                
                if subchoice == '1':
                    client.reset_password()
                elif subchoice == '2':
                    client.confirm_password_reset()
            
            elif choice == '9':
                client.verify_token()
            
            elif choice == '10' and client.current_user and 'admin' in client.current_user.get('roles', []):
                try:
                    limit = int(input("   Users per page (default 20): ").strip() or "20")
                    offset = int(input("   Offset (default 0): ").strip() or "0")
                    include_inactive = input("   Include inactive users? (y/n): ").strip().lower() == 'y'
                    client.list_users(limit, offset, include_inactive)
                except ValueError:
                    print("❌ Invalid input")
            
            elif choice == '11' and client.current_user and 'admin' in client.current_user.get('roles', []):
                query = input("   Search query: ").strip()
                if query:
                    client.search_users(query)
            
            elif choice == '12' and client.current_user and 'admin' in client.current_user.get('roles', []):
                client.get_stats()
            
            elif choice == '13' and client.current_user and 'admin' in client.current_user.get('roles', []):
                user_id = input("   User ID: ").strip()
                print("   Status options: active, suspended, locked, disabled")
                status = input("   New status: ").strip()
                if user_id and status:
                    client.update_user_status(user_id, status)
            
            elif choice == '14' and client.current_user and 'admin' in client.current_user.get('roles', []):
                user_id = input("   User ID: ").strip()
                print("   Role options: user, moderator, admin")
                role = input("   Role to assign: ").strip()
                if user_id and role:
                    client.assign_role(user_id, role)
            
            elif choice == '15' and client.current_user and 'admin' in client.current_user.get('roles', []):
                user_id = input("   User ID: ").strip()
                role = input("   Role to revoke: ").strip()
                if user_id and role:
                    client.revoke_role(user_id, role)
            
            elif choice == '16' and client.current_user and 'admin' in client.current_user.get('roles', []):
                user_id = input("   User ID to delete: ").strip()
                if user_id:
                    client.delete_user(user_id)
            
            else:
                if choice in ['10', '11', '12', '13', '14', '15', '16']:
                    print("\n❌ Admin access required")
                else:
                    print("\n❌ Invalid option")
    
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        client.close()


def main():
    """Main entry point."""
    import sys
    
    # Check for command line mode
    if len(sys.argv) > 1:
        # Command line mode - can be extended
        print("Command line mode not implemented in demo")
        print("Use without arguments for interactive CLI")
        return
    
    # Interactive CLI mode
    interactive_cli()


if __name__ == "__main__":
    main()
"""
NexusRPC Banking Service Client
Complete client implementation with all banking operations
"""

import time
import json
from typing import Dict, Optional
from rpc.client import RPCClient
from security.tls import TLSConfig
from security.auth import AuthConfig
from rpc.errors import RPCError, AuthenticationError


class BankingClient:
    """
    Complete banking service client with all operations
    Features: Account management, deposits, withdrawals, transfers
    """
    
    def __init__(self, host='localhost', port=50051, use_tls=True):
        # Configure TLS
        self.tls_config = None
        if use_tls:
            self.tls_config = TLSConfig(
                certfile='security/certs/client.crt',
                keyfile='security/certs/client.key',
                cafile='security/certs/ca.crt',
                verify_mode='required'
            )
        
        # Configure authentication
        self.auth_config = AuthConfig(
            secret_key='your-secret-key-here-change-in-production',
            algorithm='HS256'
        )
        
        # Create RPC client
        self.client = RPCClient(
            host=host,
            port=port,
            tls_config=self.tls_config,
            auth_config=self.auth_config,
            pool_size=5,
            timeout=10.0,
            retries=3
        )
        
        # Session state
        self.access_token = None
        self.current_account = None
        self.current_user = None
    
    def create_account(self, owner_name: str, initial_deposit: float = 0.0,
                      password: str = None) -> Dict:
        """
        Create a new bank account
        
        Args:
            owner_name: Account owner's name
            initial_deposit: Starting balance
            password: Account password for authentication
            
        Returns:
            Account details including account ID
        """
        try:
            response = self.client.call(
                'BankingService',
                'create_account',
                owner_name,
                initial_deposit,
                password
            )
            
            print(f"\n{'='*60}")
            print(f"✅ ACCOUNT CREATED SUCCESSFULLY")
            print(f"{'='*60}")
            print(f"   Account ID:  {response['account_id']}")
            print(f"   Owner:        {response['owner_name']}")
            print(f"   Balance:      ${response['balance']:.2f}")
            print(f"   Message:      {response['message']}")
            print(f"{'='*60}\n")
            
            return response['account_id']
            
        except RPCError as e:
            print(f"❌ Failed to create account: {e}")
            raise
    
    def authenticate(self, account_id: str, password: str = None) -> bool:
        """
        Authenticate and get access token
        
        Args:
            account_id: Account ID
            password: Account password
            
        Returns:
            True if authentication successful
        """
        try:
            response = self.client.call(
                'BankingService',
                'authenticate',
                account_id,
                password
            )
            
            if response.get('authenticated'):
                # Generate JWT token for subsequent calls
                self.access_token = self.client.authenticator.generate_access_token(
                    account_id,
                    {'role': 'customer', 'account': account_id}
                )
                self.current_account = account_id
                
                print(f"\n{'='*60}")
                print(f"🔐 LOGIN SUCCESSFUL")
                print(f"{'='*60}")
                print(f"   Account ID:  {account_id}")
                print(f"   Token:       {self.access_token[:20]}...")
                print(f"{'='*60}\n")
                
                return True
            else:
                print("❌ Authentication failed")
                return False
                
        except Exception as e:
            print(f"❌ Authentication error: {e}")
            return False
    
    def get_balance(self) -> float:
        """
        Get current account balance
        
        Returns:
            Current balance
        """
        if not self.current_account:
            raise ValueError("Not logged in. Please authenticate first.")
        
        try:
            response = self.client.call_with_auth(
                'BankingService',
                'get_balance',
                self.current_account,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"💰 BALANCE INQUIRY")
            print(f"{'='*60}")
            print(f"   Account ID:  {response['account_id']}")
            print(f"   Owner:        {response['owner_name']}")
            print(f"   Balance:      ${response['balance']:.2f}")
            print(f"   As of:        {time.ctime(response['timestamp'])}")
            print(f"{'='*60}\n")
            
            return response['balance']
            
        except AuthenticationError:
            print("❌ Authentication expired. Please login again.")
            self.access_token = None
            raise
        except Exception as e:
            print(f"❌ Failed to get balance: {e}")
            raise
    
    def deposit(self, amount: float) -> float:
        """
        Deposit money into account
        
        Args:
            amount: Amount to deposit
            
        Returns:
            New balance
        """
        if not self.current_account:
            raise ValueError("Not logged in")
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        try:
            response = self.client.call_with_auth(
                'BankingService',
                'deposit',
                self.current_account,
                amount,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"💵 DEPOSIT SUCCESSFUL")
            print(f"{'='*60}")
            print(f"   Amount:       ${amount:.2f}")
            print(f"   New Balance:  ${response['new_balance']:.2f}")
            print(f"   Message:      {response['message']}")
            print(f"{'='*60}\n")
            
            return response['new_balance']
            
        except Exception as e:
            print(f"❌ Deposit failed: {e}")
            raise
    
    def withdraw(self, amount: float) -> float:
        """
        Withdraw money from account
        
        Args:
            amount: Amount to withdraw
            
        Returns:
            New balance
        """
        if not self.current_account:
            raise ValueError("Not logged in")
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        try:
            response = self.client.call_with_auth(
                'BankingService',
                'withdraw',
                self.current_account,
                amount,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"💸 WITHDRAWAL SUCCESSFUL")
            print(f"{'='*60}")
            print(f"   Amount:       ${amount:.2f}")
            print(f"   New Balance:  ${response['new_balance']:.2f}")
            print(f"   Message:      {response['message']}")
            print(f"{'='*60}\n")
            
            return response['new_balance']
            
        except ValueError as e:
            print(f"❌ Withdrawal failed: {e}")
            raise
        except Exception as e:
            print(f"❌ Withdrawal failed: {e}")
            raise
    
    def transfer(self, to_account: str, amount: float) -> Dict:
        """
        Transfer money to another account
        
        Args:
            to_account: Destination account ID
            amount: Amount to transfer
            
        Returns:
            Transfer details
        """
        if not self.current_account:
            raise ValueError("Not logged in")
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        try:
            response = self.client.call_with_auth(
                'BankingService',
                'transfer',
                self.current_account,
                to_account,
                amount,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"🔄 TRANSFER SUCCESSFUL")
            print(f"{'='*60}")
            print(f"   Amount:       ${amount:.2f}")
            print(f"   From:         {response['from_account']}")
            print(f"   To:           {response['to_account']}")
            print(f"   Your Balance: ${response['from_balance']:.2f}")
            print(f"   Message:      {response['message']}")
            print(f"{'='*60}\n")
            
            return response
            
        except ValueError as e:
            print(f"❌ Transfer failed: {e}")
            raise
        except Exception as e:
            print(f"❌ Transfer failed: {e}")
            raise
    
    def get_transaction_history(self, limit: int = 10) -> list:
        """
        Get transaction history
        
        Args:
            limit: Maximum number of transactions to return
            
        Returns:
            List of transactions
        """
        if not self.current_account:
            raise ValueError("Not logged in")
        
        try:
            transactions = self.client.call_with_auth(
                'BankingService',
                'get_transaction_history',
                self.current_account,
                limit,
                token=self.access_token
            )
            
            print(f"\n{'='*60}")
            print(f"📊 TRANSACTION HISTORY")
            print(f"{'='*60}")
            
            if not transactions:
                print("   No transactions found")
            else:
                for i, tx in enumerate(transactions, 1):
                    tx_type = tx.get('type', 'unknown')
                    amount = tx.get('amount', 0)
                    timestamp = time.ctime(tx.get('timestamp', 0))
                    
                    if tx_type == 'deposit':
                        print(f"   {i}. 💵 Deposit     ${amount:.2f} - {timestamp}")
                    elif tx_type == 'withdrawal':
                        print(f"   {i}. 💸 Withdrawal  ${amount:.2f} - {timestamp}")
                    elif tx_type == 'transfer':
                        from_acc = tx.get('from_account', '')[:8]
                        to_acc = tx.get('to_account', '')[:8]
                        print(f"   {i}. 🔄 Transfer    ${amount:.2f} {from_acc}→{to_acc} - {timestamp}")
            
            print(f"{'='*60}\n")
            
            return transactions
            
        except Exception as e:
            print(f"❌ Failed to get transaction history: {e}")
            raise
    
    def logout(self):
        """Logout and clear session"""
        self.access_token = None
        self.current_account = None
        print(f"\n{'='*60}")
        print(f"👋 LOGGED OUT SUCCESSFULLY")
        print(f"{'='*60}\n")
    
    def close(self):
        """Close client connection"""
        self.client.close()
        print("🔌 Client connection closed")


def interactive_demo():
    """Interactive banking client demo"""
    print(f"\n{'='*60}")
    print(f"🚀 NEXUSRPC BANKING SERVICE - INTERACTIVE DEMO")
    print(f"{'='*60}")
    print(f"\n📡 Connecting to banking service...")
    
    # Initialize client
    client = BankingClient(host='localhost', port=50051, use_tls=True)
    
    try:
        while True:
            print(f"\n{'─'*60}")
            print(f"📋 MAIN MENU")
            print(f"{'─'*60}")
            print(f"1. 🏦 Create Account")
            print(f"2. 🔐 Login")
            print(f"3. 💰 Check Balance")
            print(f"4. 💵 Deposit")
            print(f"5. 💸 Withdraw")
            print(f"6. 🔄 Transfer")
            print(f"7. 📊 Transaction History")
            print(f"8. 👋 Logout")
            print(f"9. ❌ Exit")
            print(f"{'─'*60}")
            
            choice = input("\n📌 Select option: ").strip()
            
            if choice == '1':
                print(f"\n{'─'*60}")
                print(f"🏦 CREATE NEW ACCOUNT")
                print(f"{'─'*60}")
                name = input("   Owner name: ").strip()
                try:
                    deposit = float(input("   Initial deposit: $").strip() or "0")
                except ValueError:
                    deposit = 0.0
                password = input("   Password (optional): ").strip() or None
                
                client.create_account(name, deposit, password)
            
            elif choice == '2':
                print(f"\n{'─'*60}")
                print(f"🔐 LOGIN")
                print(f"{'─'*60}")
                account_id = input("   Account ID: ").strip()
                password = input("   Password: ").strip() or None
                
                client.authenticate(account_id, password)
            
            elif choice == '3':
                client.get_balance()
            
            elif choice == '4':
                try:
                    amount = float(input("   Amount to deposit: $").strip())
                    client.deposit(amount)
                except ValueError:
                    print("❌ Invalid amount")
            
            elif choice == '5':
                try:
                    amount = float(input("   Amount to withdraw: $").strip())
                    client.withdraw(amount)
                except ValueError:
                    print("❌ Invalid amount")
            
            elif choice == '6':
                to_account = input("   Destination account ID: ").strip()
                try:
                    amount = float(input("   Amount to transfer: $").strip())
                    client.transfer(to_account, amount)
                except ValueError:
                    print("❌ Invalid amount")
            
            elif choice == '7':
                try:
                    limit = int(input("   Number of transactions: ").strip() or "10")
                    client.get_transaction_history(limit)
                except ValueError:
                    client.get_transaction_history()
            
            elif choice == '8':
                client.logout()
            
            elif choice == '9':
                print(f"\n{'='*60}")
                print(f"👋 Thank you for using NexusRPC Banking Service!")
                print(f"{'='*60}\n")
                break
            
            else:
                print("❌ Invalid option")
    
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        client.close()


def main():
    """Main entry point"""
    interactive_demo()


if __name__ == "__main__":
    main()
"""
NexusRPC Payload Encryption
AES-256-GCM and RSA implementations
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class AESEncryption:
    """AES-256-GCM encryption for payloads"""
    
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate AES-256 key"""
        return os.urandom(AESEncryption.KEY_SIZE)
    
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> dict:
        """
        Encrypt with AES-256-GCM
        
        Args:
            key: 32-byte AES key
            plaintext: Data to encrypt
            aad: Additional authenticated data
            
        Returns:
            Dictionary with ciphertext, nonce, tag
        """
        if len(key) != AESEncryption.KEY_SIZE:
            raise ValueError(f"Key must be {AESEncryption.KEY_SIZE} bytes")
        
        nonce = os.urandom(AESEncryption.NONCE_SIZE)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        if aad:
            encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'tag': base64.b64encode(encryptor.tag).decode('ascii')
        }
    
    @staticmethod
    def decrypt(key: bytes, ciphertext_b64: str, nonce_b64: str, 
                tag_b64: str, aad: bytes = None) -> bytes:
        """
        Decrypt AES-256-GCM ciphertext
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext


class RSAEncryption:
    """RSA asymmetric encryption for key exchange"""
    
    KEY_SIZE = 2048
    
    @staticmethod
    def generate_keypair() -> tuple:
        """Generate RSA keypair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSAEncryption.KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def encrypt(public_key, plaintext: bytes) -> str:
        """Encrypt with RSA public key"""
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('ascii')
    
    @staticmethod
    def decrypt(private_key, ciphertext_b64: str) -> bytes:
        """Decrypt with RSA private key"""
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
import json
import base64
import os
from typing import Dict, Any, Tuple
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

class TelemetryEncryptor:
    """
    End-to-End Encryption (E2EE) for Clutch telemetry.
    Uses AES-256-CBC to ensure adversaries cannot inspect threat alerts in-flight.
    Requires a pre-shared 256-bit key (32 bytes) between the client and server.
    """
    
    def __init__(self, base64_key: str = None):
        self.enabled = CRYPTOGRAPHY_AVAILABLE
        if self.enabled:
            if base64_key:
                try:
                    self.key = base64.b64decode(base64_key)
                    if len(self.key) != 32:
                        raise ValueError("Key must be exactly 32 bytes for AES-256")
                except Exception as e:
                    print(f"[OPSEC] Invalid encryption key: {e}. Falling back to unencrypted.")
                    self.enabled = False
            else:
                # Generate a random key if none provided (for initial setup)
                self.key = os.urandom(32)
                print(f"[OPSEC] Generated new AES-256 key: {base64.b64encode(self.key).decode()}")
        else:
            print("[OPSEC] 'cryptography' library not found. Telemetry encryption disabled.")

    def encrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypts the JSON payload and returns a dictionary with IV and Ciphertext."""
        if not self.enabled:
            return payload # Pass-through
            
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        json_data = json.dumps(payload).encode('utf-8')
        padded_data = padder.update(json_data) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            "opsec_encrypted": True,
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypts a previously encrypted payload."""
        if not self.enabled or not payload.get("opsec_encrypted"):
            return payload # Pass-through
            
        try:
            iv = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"[OPSEC] Decryption failed: {e}")
            return {"error": "decryption_failed"}


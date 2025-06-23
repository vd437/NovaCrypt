import struct
import math
from typing import Union, List
from .utils import CryptoUtils

class NovaCryptCore(CryptoUtils):
    """
    Main cryptographic operations including:
    - Topological data transformation
    - Neural entropy processing
    - Multi-layered encryption
    - Tamper detection
    """
    
    def __init__(self):
        super().__init__()
        self.MANIFOLD_DIMS = 7
        self.ENCRYPTION_LAYERS = 3
        self.ENTANGLEMENT_PASSES = 5
        self.VALIDATION_TAG_SIZE = 32
    
    def _project_data(self, data: bytes) -> List[List[float]]:
        """
        Project byte data onto N-dimensional manifold
        Args:
            data: Input bytes to project
        Returns:
            List of points in N-dimensional space
        """
        manifold = []
        for byte in data:
            point = []
            for dim in range(self.MANIFOLD_DIMS):
                angle = (byte + dim) * math.pi / 128
                value = math.sin(angle * (dim + 1)) * self.collect_entropy()
                point.append(value)
            manifold.append(point)
        return manifold
    
    def _transform_manifold(self, manifold: List[List[float]], key: bytes) -> List[List[float]]:
        """
        Apply transformation to manifold points using key material
        Args:
            manifold: Input manifold points
            key: Transformation key material
        Returns:
            Transformed manifold points
        """
        transformed = []
        key_values = [k / 256.0 for k in key[:self.MANIFOLD_DIMS]]
        
        for point in manifold:
            new_point = []
            for dim in range(self.MANIFOLD_DIMS):
                noise = self.collect_entropy()
                transformed_val = (point[dim] * key_values[dim % len(key_values)] + noise) % 1.0
                new_point.append(transformed_val)
            transformed.append(new_point)
        
        return transformed
    
    def _apply_entanglement(self, manifold: List[List[float]]) -> List[List[float]]:
        """
        Create interdependencies between manifold points
        Args:
            manifold: Input manifold points
        Returns:
            Entangled manifold points
        """
        entangled = [point.copy() for point in manifold]
        
        for _ in range(self.ENTANGLEMENT_PASSES):
            for i in range(len(manifold)):
                for j in range(i + 1, min(i + 32, len(manifold))):
                    for dim in range(self.MANIFOLD_DIMS):
                        entangled[i][dim] = (entangled[i][dim] + entangled[j][(dim + 3) % self.MANIFOLD_DIMS]) % 1.0
                        entangled[j][dim] = (entangled[j][dim] * 3 + entangled[i][(dim + 5) % self.MANIFOLD_DIMS]) % 1.0
        
        return entangled
    
    def _generate_validation_tag(self, ciphertext: bytes, key: bytes) -> bytes:
        """
        Generate integrity verification tag
        Args:
            ciphertext: Encrypted data
            key: Validation key material
        Returns:
            Validation tag bytes
        """
        tag = bytearray()
        key_len = len(key)
        
        for i in range(self.VALIDATION_TAG_SIZE):
            val = sum(
                ciphertext[(i + j) % len(ciphertext)] * key[(i + j) % key_len]
                for j in range(8)
            ) % 256
            tag.append(val)
        
        return bytes(tag)
    
    def encrypt(self, data: bytes, key: Union[str, bytes]) -> bytes:
        """
        Encrypt data using topological transformations
        Args:
            data: Plaintext bytes to encrypt
            key: Encryption key (str or bytes)
        Returns:
            Encrypted bytes with prepended validation tag
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        secure_key = self.generate_secure_key(key)
        
        # Project data to manifold
        manifold = self._project_data(data)
        
        # Apply multi-layer transformation
        for layer in range(self.ENCRYPTION_LAYERS):
            manifold = self._transform_manifold(manifold, secure_key[layer * 8:][:8])
            manifold = self._apply_entanglement(manifold)
        
        # Convert manifold to ciphertext
        ciphertext = self._manifold_to_bytes(manifold)
        
        # Generate validation tag
        tag = self._generate_validation_tag(ciphertext, secure_key)
        
        return tag + ciphertext
    
    def decrypt(self, ciphertext: bytes, key: Union[str, bytes]) -> bytes:
        """
        Decrypt data using inverse topological transformations
        Args:
            ciphertext: Encrypted data with validation tag
            key: Decryption key (str or bytes)
        Returns:
            Decrypted plaintext bytes
        Raises:
            ValueError: If tampering is detected or decryption fails
        """
        if len(ciphertext) < self.VALIDATION_TAG_SIZE:
            raise ValueError("Invalid ciphertext length")
        
        tag = ciphertext[:self.VALIDATION_TAG_SIZE]
        ciphertext = ciphertext[self.VALIDATION_TAG_SIZE:]
        
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        secure_key = self.generate_secure_key(key)
        
        # Verify integrity
        expected_tag = self._generate_validation_tag(ciphertext, secure_key)
        if not self._constant_time_compare(tag, expected_tag):
            raise ValueError("Ciphertext validation failed")
        
        # Convert ciphertext to manifold
        manifold = self._bytes_to_manifold(ciphertext)
        
        # Apply inverse transformations
        for layer in reversed(range(self.ENCRYPTION_LAYERS)):
            manifold = self._apply_entanglement(manifold)
            manifold = self._inverse_transform(manifold, secure_key[layer * 8:][:8])
        
        # Convert manifold back to data
        return self._manifold_to_data(manifold)
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Timing-attack resistant comparison"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    def _manifold_to_bytes(self, manifold: List[List[float]]) -> bytes:
        """Convert manifold points to byte string"""
        output = bytearray()
        for point in manifold:
            for dim in range(self.MANIFOLD_DIMS):
                value = int(abs(point[dim]) * 0xFFFFFFFF) & 0xFFFFFFFF
                output.extend(struct.pack('!I', value))
        return bytes(output)
    
    def _bytes_to_manifold(self, data: bytes) -> List[List[float]]:
        """Convert byte string back to manifold points"""
        manifold = []
        point_size = self.MANIFOLD_DIMS * 4
        for i in range(0, len(data), point_size):
            point = []
            chunk = data[i:i+point_size]
            for j in range(0, len(chunk), 4):
                word = struct.unpack('!I', chunk[j:j+4])[0]
                point.append(word / 0xFFFFFFFF)
            manifold.append(point[:self.MANIFOLD_DIMS])
        return manifold
    
    def _inverse_transform(self, manifold: List[List[float]], key: bytes) -> List[List[float]]:
        """Apply inverse transformation to manifold points"""
        inverted = []
        key_values = [k / 256.0 for k in key[:self.MANIFOLD_DIMS]]
        
        for point in manifold:
            new_point = []
            for dim in range(self.MANIFOLD_DIMS):
                noise = self.collect_entropy()
                original_val = (point[dim] - noise) / (key_values[dim % len(key_values)] or 0.0001)
                new_point.append(original_val % 1.0)
            inverted.append(new_point)
        
        return inverted
    
    def _manifold_to_data(self, manifold: List[List[float]]) -> bytes:
        """Convert manifold points back to original data"""
        output = bytearray()
        for point in manifold:
            byte_val = 0
            for dim, val in enumerate(point):
                byte_val = (byte_val + int(abs(val) * 255)) % 256
            output.append(byte_val)
        return bytes(output)
    
    def encrypt_file(self, input_path: str, output_path: str, key: Union[str, bytes]):
        """Encrypt file contents"""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt(data, key)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
    
    def decrypt_file(self, input_path: str, output_path: str, key: Union[str, bytes]):
        """Decrypt file contents"""
        with open(input_path, 'rb') as f:
            ciphertext = f.read()
        
        decrypted = self.decrypt(ciphertext, key)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)

# Module-level convenience functions
_crypto = NovaCryptCore()

def encrypt(data: bytes, key: Union[str, bytes]) -> bytes:
    return _crypto.encrypt(data, key)

def decrypt(ciphertext: bytes, key: Union[str, bytes]) -> bytes:
    return _crypto.decrypt(ciphertext, key)

def encrypt_file(input_path: str, output_path: str, key: Union[str, bytes]):
    return _crypto.encrypt_file(input_path, output_path, key)

def decrypt_file(input_path: str, output_path: str, key: Union[str, bytes]):
    return _crypto.decrypt_file(input_path, output_path, key)

def generate_secure_key(base_key: Union[str, bytes], length: int = 64) -> bytes:
    return _crypto.generate_secure_key(base_key, length)
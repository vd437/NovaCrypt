import os
import time
import struct
import math
from typing import Tuple
from collections import deque

class CryptoUtils:
    """
    Utility functions for cryptographic operations including:
    - Entropy collection
    - Key generation and mutation
    - Pseudo-random value generation
    """
    
    def __init__(self):
        self._noise_buffer = deque(maxlen=256)
        self._entropy_pool = self._init_entropy_pool()
    
    def _init_entropy_pool(self) -> int:
        """Initialize entropy pool with system state information"""
        pool = 0
        pool ^= (os.getpid() << 32)
        pool ^= (time.perf_counter_ns() % 2**64)
        pool ^= (id(self) & 0xFFFFFFFF)
        return pool
    
    def collect_entropy(self) -> float:
        """
        Generate pseudo-random values using system entropy sources
        Returns float in range [0, 1)
        """
        t = time.perf_counter_ns() % 2**20
        x = math.sin(t * 0.000001) * 2**30
        y = math.cos(x * 0.0000001) * 2**30
        value = (x * y) % 1.0
        self._noise_buffer.append(value)
        return sum(self._noise_buffer) / len(self._noise_buffer)
    
    def generate_secure_key(self, base_key: bytes, length: int = 64) -> bytes:
        """
        Derive a secure encryption key from base material
        Args:
            base_key: Input key material
            length: Desired key length in bytes
        Returns:
            Derived key bytes
        """
        key_material = bytearray()
        
        # Initial expansion
        for i in range(length):
            key_material.append((base_key[i % len(base_key)] + i) % 256)
        
        # Add system entropy
        entropy = self.collect_entropy()
        key_material.extend(struct.pack('!d', entropy))
        
        # Nonlinear transformation
        for i in range(len(key_material)):
            key_material[i] ^= int(self.collect_entropy() * 255)
            key_material[i] = (key_material[i] + 179) % 256
        
        return bytes(key_material)[:length]
    
    def validate_key_strength(self, key: bytes) -> bool:
        """
        Check if key meets minimum security requirements
        Args:
            key: Key to validate
        Returns:
            True if key is sufficiently strong
        """
        if len(key) < 32:
            return False
        
        # Check byte distribution
        byte_counts = [0] * 256
        for b in key:
            byte_counts[b] += 1
        
        # Ensure no single byte dominates
        max_count = max(byte_counts)
        return max_count <= len(key) / 8￼Enter

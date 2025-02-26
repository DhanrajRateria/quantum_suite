import hashlib
from typing import Tuple

# ---------------------------
# Core Cryptographic Functions
# ---------------------------

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def shake128(data: bytes, output_length: int) -> bytes:
    return hashlib.shake_128(data).digest(output_length)

def shake256(data: bytes, output_length: int) -> bytes:
    return hashlib.shake_256(data).digest(output_length)

# ---------------------------
# ML-KEM Specific Functions
# ---------------------------

def PRF(eta: int, s: bytes, b: bytes) -> bytes:
    """
    Pseudorandom Function (FIPS 203 Algorithm 4.3)
    η ∈ {2,3}, s: 32-byte seed, b: 1-byte domain separator
    """
    if eta not in {2, 3}:
        raise ValueError("η must be 2 or 3")
    if len(s) != 32:
        raise ValueError("s must be 32 bytes")
    if len(b) != 1:
        raise ValueError("b must be 1 byte")
    
    return shake256(s + b, 64 * eta)

def H(s: bytes) -> bytes:
    """Hash function (FIPS 203 4.4)"""
    return sha3_256(s)

def J(s: bytes) -> bytes:
    """Hash function (FIPS 203 4.4)"""
    return shake256(s, 32)

def G(c: bytes) -> Tuple[bytes, bytes]:
    """Hash function (FIPS 203 4.5)"""
    digest = sha3_512(c)
    return digest[:32], digest[32:]

# ---------------------------
# XOF Wrapper (FIPS 203 Algorithm 2)
# ---------------------------

class XOF:
    """Incremental SHAKE128 wrapper (FIPS 203 4.6)"""
    def __init__(self):
        self._ctx = hashlib.shake_128()
    
    def absorb(self, data: bytes) -> None:
        """Absorb data into the XOF state"""
        self._ctx.update(data)
    
    def squeeze(self, length: int) -> bytes:
        """Squeeze output bytes from the XOF state"""
        return self._ctx.digest(length)
    
# ---------------------------
# Validation Tests
# ---------------------------

def test_crypto_functions():
    # Test input
    test_data = b"ML-KEM Test Vector"
    
    # Test PRF
    prf_output = PRF(2, b'\x00'*32, b'\x00')
    assert len(prf_output) == 128, "PRF(η=2) should output 128 bytes"
    
    # Test H function
    h = H(test_data)
    assert len(h) == 32, "H should output 32 bytes"
    
    # Test J function
    j = J(test_data)
    assert len(j) == 32, "J should output 32 bytes"
    
    # Test G function
    g1, g2 = G(test_data)
    assert len(g1) == 32 and len(g2) == 32, "G should output two 32-byte values"
    
    # Test XOF
    xof = XOF()
    xof.absorb(b'absorb1')
    xof.absorb(b'absorb2')
    squeezed = xof.squeeze(32)
    assert len(squeezed) == 32, "XOF should output requested length"
    
    print("All cryptographic function tests passed!")

# ---------------------------
# Example Usage
# ---------------------------

if __name__ == "__main__":
    # Run validation tests
    test_crypto_functions()
    
    # Example usage
    data = b"Important ML-KEM Message"
    
    # Hash examples
    print(f"SHA3-256({data!r}): {sha3_256(data).hex()}")
    print(f"SHAKE128({data!r}, 32): {shake128(data, 32).hex()}")
    
    # ML-KEM functions
    prf_result = PRF(3, b'\x01'*32, b'\x02')
    print(f"PRF(η=3) first 16 bytes: {prf_result[:16].hex()}...")
    
    g1, g2 = G(data)
    print(f"G function outputs:\n{g1.hex()}\n{g2.hex()}")
    
    # XOF usage
    xof = XOF()
    xof.absorb(b'Phase1')
    xof.absorb(b'Phase2')
    print(f"XOF output: {xof.squeeze(16).hex()}")
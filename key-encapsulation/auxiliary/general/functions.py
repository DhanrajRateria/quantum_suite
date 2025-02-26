import math
import hashlib
from ..cryptographic.functions import XOF

# ---------------------------
# Bit/Byte Conversion
# ---------------------------

def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert bit array (little-endian) to byte array"""
    if len(bits) % 8 != 0:
        raise ValueError("Bit array length must be multiple of 8")
    
    byte_count = len(bits) // 8
    result = bytearray(byte_count)
    
    for i in range(byte_count):
        byte_val = 0
        for j in range(8):
            bit = bits[i*8 + j]
            if bit not in (0, 1):
                raise ValueError("Bits must be 0 or 1")
            byte_val |= bit << j  # Little-endian: first bit = LSB
        result[i] = byte_val
    
    return bytes(result)

def bytes_to_bits(data: bytes) -> list[int]:
    """Convert byte array to bit array (little-endian)"""
    bits = []
    for byte in data:
        for j in range(8):
            bits.append((byte >> j) & 0x01)  # Little-endian extraction
    return bits

# ---------------------------
# Compression/Decompression
# ---------------------------

def compress(x: int, d: int, q: int = 3329) -> int:
    """Compress integer modulo q to d bits"""
    if not (1 <= d < 12):
        raise ValueError("d must be 1 ≤ d < 12")
    return ((x << d) // q) & ((1 << d) - 1)

def decompress(y: int, d: int, q: int = 3329) -> int:
    """Decompress d-bit integer to modulo q"""
    if not (1 <= d < 12):
        raise ValueError("d must be 1 ≤ d < 12")
    return ((y * q) + (1 << (d - 1))) >> d  # Rounding division

# ---------------------------
# Byte Encoding/Decoding (Algorithms 5 & 6)
# ---------------------------

def byte_encode(F: list[int], d: int, q: int = 3329) -> bytes:
    """Encode array of integers to byte array"""
    if len(F) != 256:
        raise ValueError("Array must contain exactly 256 elements")
    
    m = (1 << d) if d < 12 else q
    total_bits = 256 * d
    if total_bits % 8 != 0:
        raise ValueError(f"d={d} doesn't produce whole bytes (256×{d} bits)")
    
    bits = []
    for x in F:
        if not (0 <= x < m):
            raise ValueError(f"Value {x} out of range [0, {m-1}]")
        
        # Convert to d bits (little-endian)
        for j in range(d):
            bits.append((x >> j) & 0x01)
    
    return bits_to_bytes(bits)

def byte_decode(B: bytes, d: int, q: int = 3329) -> list[int]:
    """Decode byte array to array of integers"""
    m = (1 << d) if d < 12 else q
    expected_bytes = (256 * d) // 8
    if len(B) != expected_bytes:
        raise ValueError(f"Expected {expected_bytes} bytes for d={d}")
    
    bits = bytes_to_bits(B)
    F = []
    
    for i in range(256):
        # Extract d bits for each element
        chunk = bits[i*d : (i+1)*d]
        if len(chunk) != d:
            raise ValueError("Invalid bit length during decoding")
        
        # Convert bits to integer (little-endian)
        x = sum(bit << j for j, bit in enumerate(chunk))
        F.append(x % m)  # Apply modulus
    
    return F

# ---------------------------
# Sampling Algorithms (FIPS 203 4.2.2)
# ---------------------------

def sample_ntt(B: bytes) -> list[int]:
    """
    Algorithm 7: SampleNTT - Uniform sampling in NTT domain
    Input: 34-byte array B (32-byte seed + 2-byte indices)
    Output: 256 coefficients in Z_q
    """
    q = 3329
    if len(B) != 34:
        raise ValueError("SampleNTT requires exactly 34 input bytes")
    
    xof = XOF()
    xof.absorb(B)
    coefficients = []
    
    while len(coefficients) < 256:
        # Squeeze 3 bytes (24 bits)
        C = xof.squeeze(3)
        if len(C) != 3:
            raise RuntimeError("XOF failed to produce required bytes")
        
        # Calculate d1 and d2 (12-bit values)
        d1 = C[0] + 256 * (C[1] & 0x0F)
        d2 = (C[1] >> 4) + 16 * C[2]
        
        # Store valid coefficients
        if d1 < q:
            coefficients.append(d1)
            if len(coefficients) == 256:
                break
        if d2 < q and len(coefficients) < 256:
            coefficients.append(d2)
    
    return coefficients

def sample_poly_cbd(eta: int, B: bytes) -> list[int]:
    """
    Algorithm 8: SamplePolyCBD - Centered Binomial Distribution sampling
    Input: eta ∈ {2,3}, B: 64η-byte array
    Output: 256 coefficients in Z_q
    """
    q = 3329
    if eta not in {2, 3}:
        raise ValueError("η must be 2 or 3")
    
    expected_length = 64 * eta
    if len(B) != expected_length:
        raise ValueError(f"Expected {expected_length} bytes for η={eta}")
    
    bits = bytes_to_bits(B)
    coefficients = []
    
    for i in range(256):
        # Extract 2η bits for each coefficient
        start = i * 2 * eta
        x_bits = bits[start : start + eta]
        y_bits = bits[start + eta : start + 2 * eta]
        
        x = sum(x_bits)
        y = sum(y_bits)
        coefficients.append((x - y) % q)
    
    return coefficients

# ---------------------------
# Validation Tests
# ---------------------------

def test_conversion_algorithms():
    # Test bit/byte conversion
    test_bits = [1,1,0,1,0,0,0,1]  # Should become 0x8B (139)
    test_bytes = bits_to_bytes(test_bits)
    assert test_bytes == b'\x8b'
    assert bytes_to_bits(test_bytes) == test_bits
    
    # Test compression/decompression round trip (d=10)
    original = 1234
    compressed = compress(original, 10)
    decompressed = decompress(compressed, 10)
    assert decompressed-original <= 5 

    # Test byte encoding/decoding (d=8)
    test_array = [i % 256 for i in range(256)]
    encoded = byte_encode(test_array, 8)
    decoded = byte_decode(encoded, 8)
    assert decoded == test_array
    
    # Test special case d=12
    q = 3329
    test_values = [i % q for i in range(256)]
    encoded_12 = byte_encode(test_values, 12, q)
    decoded_12 = byte_decode(encoded_12, 12, q)
    assert decoded_12 == test_values
    
    print("All conversion algorithm tests passed!")

def test_sampling_algorithms():
    q = 3329
    
    # Test SampleNTT with known input
    test_seed = bytes([i % 256 for i in range(34)])
    ntt_coeffs = sample_ntt(test_seed)
    assert len(ntt_coeffs) == 256, "SampleNTT should return 256 coefficients"
    assert all(0 <= c < q for c in ntt_coeffs), "All coefficients must be in Z_q"
    
    # Test SamplePolyCBD (η=2)
    # All bits 1 → x=2, y=2 → coeff=0
    B_eta2 = b'\xff' * 128  # 64*2 = 128 bytes
    cbd2 = sample_poly_cbd(2, B_eta2)
    assert all(c == 0 for c in cbd2), "All-1 bits should produce zeros"
    
    # Test η=3 edge case
    B_eta3 = bytes([0b10101010] * 192)  # Alternating bits
    cbd3 = sample_poly_cbd(3, B_eta3)
    assert all(-3 <= (c if c < 3 else c - q) <= 3 for c in cbd3), "Values should be in [-3,3]"
    
    print("All sampling algorithm tests passed!")

# ---------------------------
# Example Usage
# ---------------------------

if __name__ == "__main__":
    test_conversion_algorithms()
    
    # Example compression
    x = 2500  # Original value in Z_q
    d = 10
    y = compress(x, d)
    x_recovered = decompress(y, d)
    print(f"\nCompression example (d={d}):")
    print(f"Original: {x}, Compressed: {y}, Recovered: {x_recovered}")
    
    # Byte encoding example
    sample_data = [i % 100 for i in range(256)]
    encoded_bytes = byte_encode(sample_data, 10)
    print(f"\nByte encoding (d=10) output length: {len(encoded_bytes)} bytes")
    
    # Special d=12 case
    encoded_12 = byte_encode([1234]*256, 12)
    decoded_12 = byte_decode(encoded_12, 12)
    print(f"\nd=12 decoding check: All values = {decoded_12[0]} (expected 1234)")

    test_sampling_algorithms()
    
    # SampleNTT example
    seed = bytes(range(34))  # 0x00-0x21
    print("\nSampleNTT first 5 coefficients:", sample_ntt(seed)[:5])
    
    # SamplePolyCBD example (η=2)
    random_bits = bytes(128)  # All zeros
    cbd_sample = sample_poly_cbd(2, random_bits)
    print(f"\nCBD(η=2) coefficient range: {min(cbd_sample)}-{max(cbd_sample)}")
    
    # Extreme values test
    max_bits = bytes([255]) * 64*3  # All bits 1 for η=3
    cbd_extreme = sample_poly_cbd(3, max_bits)
    print(f"CBD(η=3) all zeros check: {all(c == 0 for c in cbd_extreme)}")
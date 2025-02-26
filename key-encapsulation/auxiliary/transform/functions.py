import copy

# ---------------------------
# Constants and Precomputation
# ---------------------------

Q = 3329
N = 256
ZETA = 17

# Precomputed ζ values from Appendix A
ZETA_PRECOMP = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
]

# Precomputed γ values (ζ^(2*BitRev7(i)+1) for multiplication
GAMMA_PRECOMP = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649, 1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233, 756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, 1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388, 733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220, 375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757, 2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026, 1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029, 2110, -2110, 2935, -2935, 885, -885, 2154, -2154
]

ZETA_PRECOMP_INV = [pow(z, -1, Q) for z in ZETA_PRECOMP]

def bitrev7(i: int) -> int:
    """Bit-reverse a 7-bit number"""
    return int(format(i, '07b')[::-1], 2)

# ---------------------------
# NTT Algorithms (9 & 10)
# ---------------------------

def ntt(f: list[int]) -> list[int]:
    """Algorithm 9: Forward NTT transform"""
    f_hat = copy.copy(f)
    k = 1  # ZETA_PRECOMP index
    
    # Layers from len=128 down to 2
    length = 128
    while length >= 2:
        for start in range(0, N, 2*length):
            zeta = ZETA_PRECOMP[k]
            k += 1
            
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        
        length >>= 1
    
    return f_hat

def ntt_inv(f_hat: list[int]) -> list[int]:
    """Algorithm 10: Inverse NTT transform"""
    f = copy.copy(f_hat)
    k = 127  # ZETA_PRECOMP_INV index
    
    # Layers from len=2 up to 128
    length = 2
    while length <= 128:
        for start in range(0, N, 2*length):
            zeta_inv = ZETA_PRECOMP_INV[k]
            k -= 1
            
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta_inv * ((f[j + length] - t) % Q)) % Q
        
        length <<= 1
    
    # Final scaling by n^-1 mod Q = 3303
    n_inv = 3303
    return [(x * n_inv) % Q for x in f]

# ---------------------------
# NTT Multiplication (11 & 12)
# ---------------------------

def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple[int, int]:
    """Algorithm 12: Base case polynomial multiplication"""
    c0 = (a0 * b0 % Q + a1 * b1 % Q * gamma % Q) % Q
    c1 = (a0 * b1 % Q + a1 * b0 % Q) % Q
    return c0, c1

def multiply_ntts(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """Algorithm 11: NTT domain multiplication"""
    h_hat = [0] * N
    for i in range(128):
        gamma = GAMMA_PRECOMP[i]
        f0, f1 = f_hat[2*i], f_hat[2*i+1]
        g0, g1 = g_hat[2*i], g_hat[2*i+1]
        
        h0, h1 = base_case_multiply(f0, f1, g0, g1, gamma)
        h_hat[2*i] = h0
        h_hat[2*i+1] = h1
    return h_hat

# ---------------------------
# Validation Tests
# ---------------------------

def test_ntt_operations():
    # Test polynomial: f(x) = x + 1
    f = [1, 1] + [0] * (N-2)  # First two coefficients are 1, rest are 0
    
    # Forward NTT
    f_hat = ntt(f)
    assert len(f_hat) == N, "NTT output length mismatch"
    
    # Inverse NTT
    f_recovered = ntt_inv(f_hat)
    
    # Check if original and recovered polynomials match
    match = True
    for i in range(N):
        if f[i] != f_recovered[i]:
            match = False
            print(f"Mismatch at index {i}: Expected {f[i]}, got {f_recovered[i]}")
            break
    
    assert match, "NTT inversion failed"
    
    # Test multiplication
    g = [2] * N  # Constant polynomial 2
    g_hat = ntt(g)
    h_hat = multiply_ntts(f_hat, g_hat)
    h = ntt_inv(h_hat)
    
    # Expected result: 2x + 2
    expected = [2] * N
    expected[1] = 2
    assert h == expected, "NTT multiplication failed"
    
    print("All NTT operations tests passed!")

# ---------------------------
# Example Usage
# ---------------------------

if __name__ == "__main__":
    test_ntt_operations()
    
    # Example NTT transform
    poly = [i % Q for i in range(N)]
    print("\nOriginal polynomial (first 5 coefficients):", poly[:5])
    
    ntt_poly = ntt(poly)
    print("NTT representation (first 5 coefficients):", ntt_poly[:5])
    
    recovered_poly = ntt_inv(ntt_poly)
    print("Recovered polynomial (first 5 coefficients):", recovered_poly[:5])
    
    # Multiplication example
    a = [1, 2] + [0]*(N-2)
    b = [3, 4] + [0]*(N-2)
    a_ntt = ntt(a)
    b_ntt = ntt(b)
    c_ntt = multiply_ntts(a_ntt, b_ntt)
    c = ntt_inv(c_ntt)
    print("\nPolynomial multiplication result (coefficient 0-1):", c[:2])
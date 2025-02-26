import os
from typing import Tuple, List
from ..auxiliary.cryptographic.functions import PRF
from ..auxiliary.general.functions import byte_encode, sample_poly_cbd, sample_ntt
from ..auxiliary.transform.functions import ntt, multiply_ntts

def poly_add(a: List[int], b: List[int], q: int = 3329) -> List[int]:
    """
    Add two degree-255 polynomials mod q.
    """
    return [(x + y) % q for x, y in zip(a, b)]

def k_pke_keygen(d: int,
                 eta1: int = 2,
                 eta2: int = 2) -> Tuple[
                     Tuple[List[int], List[int]],
                     Tuple[bytes, List[int], List[int]]
                 ]:
    """
    Implements Algorithm 13: K-PKE.KeyGen(d)

    Args:
        d: Compression parameter in {8, 10, 12}.
        eta1, eta2: Parameters for the centered binomial distribution (CBD).

    Returns:
        A tuple of:
          - Encryption key eK_{K-PKE} = (A, t),
          - Decryption key dK_{K-PKE} = (b, s1, s2),
        where:
          A  is the 'public' polynomial (in NTT form),
          t  is A*s1 + s2 in NTT form,
          b  is byte-encoding of t,
          s1, s2  are secret polynomials in normal domain.
    """

    # 1. Generate two pseudorandom 32-byte seeds r1, r2
    r1 = os.urandom(32)
    r2 = os.urandom(32)

    # 2. Derive secret polynomials s1, s2 via CBD sampler and PRF
    #    Use domain-separation bytes b'\x00' and b'\x01' (typical choice).
    seed_s1 = PRF(eta1, r1, b'\x00')
    s1 = sample_poly_cbd(eta1, seed_s1)

    seed_s2 = PRF(eta2, r1, b'\x01')
    s2 = sample_poly_cbd(eta2, seed_s2)

    # 3. Generate public polynomial A from seed r2 (in "NTT domain" sampling).
    #    sample_ntt expects 34 bytes: 32-byte seed + 2-byte "index".
    #    For a single polynomial, you can set the index to zero:
    A_input = r2 + b'\x00\x00'
    A = sample_ntt(A_input)  # 256 coefficients in [0, Q)

    # 4. Convert s1, s2 to NTT domain and compute t = A*s1 + s2 (NTT-based multiply)
    s1_hat = ntt(s1)
    s2_hat = ntt(s2)
    # multiply_ntts() does pairwise base-case multiplication in NTT domain
    product = multiply_ntts(A, s1_hat)
    t_hat = poly_add(product, s2_hat)

    # 5. Encode t_hat -> b for the decryption key
    b_enc = byte_encode(t_hat, d)

    # 6. Return keys
    # eK_{K-PKE} = (A, t_hat)
    # dK_{K-PKE} = (b_enc, s1, s2)
    return (A, t_hat), (b_enc, s1, s2)


# ---------------------------
# Example usage / test
# ---------------------------
if __name__ == "__main__":
    # Example: d=10
    (A, t_hat), (b, s1, s2) = k_pke_keygen(d=10, eta1=2, eta2=2)

    print("Encryption Key (truncated for display):")
    print("  A[0..4]:", A[:5])
    print("  t_hat[0..4]:", t_hat[:5])
    print()
    print("Decryption Key (truncated for display):")
    print("  b (encoded t) length:", len(b), "bytes")
    print("  s1[0..4]:", s1[:5])
    print("  s2[0..4]:", s2[:5])
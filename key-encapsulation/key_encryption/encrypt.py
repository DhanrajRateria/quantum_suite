import os
from typing import Tuple, List
from auxiliary.cryptographic.functions import PRF
from auxiliary.general.functions import byte_encode, sample_poly_cbd, bytes_to_bits, compress
from auxiliary.transform.functions import ntt, multiply_ntts
from .keygen import poly_add

def encode_message(m: bytes, q: int = 3329) -> List[int]:
    """
    Interpret a 32-byte message as 256 bits, each bit
    mapped to a polynomial coefficient in {0, 1} (mod q).
    """
    if len(m) != 32:
        raise ValueError("Message must be exactly 32 bytes (=256 bits).")

    bit_array = bytes_to_bits(m)  # 256 bits in little-endian order
    # Map each bit ∈ {0,1} to a coefficient in Z_q
    return [bit % q for bit in bit_array]

def k_pke_encrypt(
    ek_pke: Tuple[List[int], List[int]],  # (A, t_hat) for single-polynomial setting
    m: bytes,                            # 32-byte message
    r: bytes,                            # random 32-byte seed for ephemeral sampling
    d: int,                              # compression parameter
    eta: int = 2
) -> bytes:
    """
    Implements Algorithm 14: K-PKE.Encrypt

    Args:
        ek_pke: the encryption key, consisting of:
                (A, t_hat), where A is a public polynomial (NTT domain),
                and t_hat = A * s1 + s2 (also in NTT domain).
        m: 32-byte message to be encrypted.
        r: 32-byte random seed used to generate ephemeral polynomials and noise.
        d: compression parameter (e.g., 8, 10, or 12).
        eta: parameter for centered binomial distribution sampling (often 2 or 3).

    Returns:
        A byte string representing the ciphertext c = (c1 || c2).
        - c1 is the byte-encoded version of u_hat = A * y_hat + e1_hat
        - c2 is the byte-encoded version of v_hat = t_hat * y_hat + e2_hat + encode(m)
    """
    # Unpack the encryption key
    A, t_hat = ek_pke  # Both are length-256 polynomials in NTT domain

    # -------------------------------
    # 1. Generate ephemeral polynomials and noise from r
    #    using domain-separation bytes 0x00, 0x01, 0x02
    # -------------------------------
    y_seed  = PRF(eta, r, b'\x00')  # 64*eta bytes
    e1_seed = PRF(eta, r, b'\x01')
    e2_seed = PRF(eta, r, b'\x02')

    y  = sample_poly_cbd(eta, y_seed)
    e1 = sample_poly_cbd(eta, e1_seed)
    e2 = sample_poly_cbd(eta, e2_seed)

    # Convert y, e1, e2 to NTT domain
    y_hat  = ntt(y)
    e1_hat = ntt(e1)
    e2_hat = ntt(e2)

    # -------------------------------
    # 2. Compute u_hat and v_hat
    #    u_hat = A * y_hat + e1_hat
    #    v_hat = t_hat * y_hat + e2_hat + encode(m)
    # -------------------------------
    # 2.1: u_hat
    A_times_y = multiply_ntts(A, y_hat)
    u_hat = poly_add(A_times_y, e1_hat)

    # 2.2: v_hat
    t_times_y = multiply_ntts(t_hat, y_hat)
    v_hat = poly_add(t_times_y, e2_hat)

    # Encode the message as a polynomial and add it in NTT domain
    m_poly = encode_message(m)
    m_hat  = ntt(m_poly)
    v_hat  = poly_add(v_hat, m_hat)

    # -------------------------------
    # 3. Compress and encode (u_hat, v_hat) into bytes
    # -------------------------------
    u_hat_compressed = [compress(coeff, d) for coeff in u_hat]
    c1 = byte_encode(u_hat_compressed, d)
    v_hat_compressed = [compress(coeff, d) for coeff in v_hat]
    c2 = byte_encode(v_hat_compressed, d)

    # -------------------------------
    # 4. Output ciphertext c
    # -------------------------------
    return c1 + c2


# ---------------------------
# Example usage / test
# ---------------------------
if __name__ == "__main__":
    # Suppose we have from K-PKE.KeyGen:
    #   ek_pke = (A, t_hat),  dk_pke = (b_enc, s1, s2)
    # For demonstration, assume we already have them:
    import os

    # Fake key for demonstration (each polynomial is random mod Q)
    from random import randrange
    A_demo = [randrange(3329) for _ in range(256)]
    t_hat_demo = [randrange(3329) for _ in range(256)]
    ek_demo = (A_demo, t_hat_demo)

    # 32-byte message
    message = b"01234567890123456789012345678901"  # exactly 32 bytes

    # 32-byte random seed for ephemeral sampling
    ephemeral_r = os.urandom(32)

    # Encrypt
    ciphertext = k_pke_encrypt(ek_demo, message, ephemeral_r, d=10, eta=2)

    print(f"Ciphertext length = {len(ciphertext)} bytes")
    print(f"Ciphertext (hex) = {ciphertext.hex()[:80]}...")
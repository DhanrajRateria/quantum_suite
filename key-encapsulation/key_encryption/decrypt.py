from typing import Tuple, List
from auxiliary.general.functions import byte_decode, bits_to_bytes, decompress
from auxiliary.transform.functions import ntt, ntt_inv, multiply_ntts

def decode_message(poly: List[int], q: int = 3329) -> bytes:
    """
    Inverse of a simple "bit embedding" in encryption:
      - Interprets each coefficient poly[i] as bit 0 or 1,
        using a threshold of q/2.
      - Collects 256 bits into 32 bytes.
    """
    bits = []
    for coeff in poly[:256]:
        # 0 if coeff < q/2, else 1
        bits.append(0 if coeff < (q // 2) else 1)
    return bits_to_bytes(bits)

def k_pke_decrypt(
    dk_pke: Tuple[bytes, List[int], List[int]],  # (b_enc, s1, s2)
    c: bytes, 
    d: int
) -> bytes:
    """
    Implements Algorithm 15: K-PKE.Decrypt

    Args:
        dk_pke: decryption key (b_enc, s1, s2).
                - b_enc is the byte-encoded t-hat from keygen (not used here).
                - s1, s2 are the secret polynomials in normal domain.
        c: ciphertext c = c1 || c2 (two compressed polynomials).
        d: compression parameter in {8, 10, 12}.

    Returns:
        The 32-byte plaintext message m.
    """
    # Unpack the secret key
    _, s1, _ = dk_pke  # s2 often not used directly for decryption

    # -----------------------------------------------------
    # 1. Parse ciphertext into c1, c2
    #    Each part is (256*d)/8 bytes
    # -----------------------------------------------------
    poly_bytes_len = (256 * d) // 8
    c1 = c[:poly_bytes_len]
    c2 = c[poly_bytes_len:]

    # -----------------------------------------------------
    # 2. Decompress + ByteDecode => polynomials in NTT domain
    # -----------------------------------------------------
    u_hat_compressed = byte_decode(c1, d)  # length 256
    v_hat_compressed = byte_decode(c2, d)  # length 256

    u_hat = [decompress(y, d) for y in u_hat_compressed]
    v_hat = [decompress(y, d) for y in v_hat_compressed]

    # -----------------------------------------------------
    # 3. Convert s1 to NTT domain
    # -----------------------------------------------------
    s1_hat = ntt(s1)

    # -----------------------------------------------------
    # 4. Subtract u_hat*s1_hat from v_hat in the NTT domain
    #    w_hat = v_hat - multiply_ntts(u_hat, s1_hat)
    # -----------------------------------------------------
    u_s1_hat = multiply_ntts(u_hat, s1_hat)
    w_hat = [(vh - uh) % 3329 for vh, uh in zip(v_hat, u_s1_hat)]

    # -----------------------------------------------------
    # 5. Inverse NTT => w in normal domain
    # -----------------------------------------------------
    w = ntt_inv(w_hat)

    # -----------------------------------------------------
    # 6. Decode w => 32-byte message
    # -----------------------------------------------------
    m = decode_message(w, q=3329)

    return m


# ---------------------------
# Example usage / test
# ---------------------------
if __name__ == "__main__":
    import os
    from random import randrange

    # Fake secret key for demonstration: 
    #   s1, s2 are small random polynomials
    s1_demo = [randrange(3329) for _ in range(256)]
    s2_demo = [randrange(3329) for _ in range(256)]
    b_enc_demo = b"dummy"  # Not used in this demonstration
    dk_demo = (b_enc_demo, s1_demo, s2_demo)

    # Fake ciphertext c = c1||c2, each 256*d/8 bytes for d=10 => 256*10/8=320 bytes each
    d_param = 10
    c1_demo = os.urandom(320)
    c2_demo = os.urandom(320)
    ciphertext_demo = c1_demo + c2_demo

    # Decrypt
    plaintext_recovered = k_pke_decrypt(dk_demo, ciphertext_demo, d=d_param)
    print(f"Recovered message (hex) = {plaintext_recovered.hex()}")
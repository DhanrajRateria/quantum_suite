from typing import Tuple
# from k_pke_encrypt import k_pke_encrypt
# from cryptographic.functions import H, G

def ml_kem_encaps_internal(ek: bytes, r: bytes, d: int) -> Tuple[bytes, bytes]:
    """
    ML-KEM.Encaps_internal(ek, r):

    Inputs:
      ek: the ML-KEM encapsulation key (containing the K-PKE public key)
      r:  a 32-byte random seed for ephemeral usage
      d:  compression parameter for K-PKE

    Outputs:
      c: ciphertext (bytes)
      K: shared secret key (32 bytes)

    High-level steps:
      1. Derive ephemeral random for K-PKE from ek and r (e.g., ephemeral_r = G(H(ek) || r)).
      2. Use K-PKE.Encrypt(ek_pke, ephemeral_r, ephemeral_r, d) to get ciphertext c.
      3. Derive the shared key K = H(ephemeral_r) or another function of ephemeral_r.
    """
    # 1. Parse the encapsulation key (ek) to retrieve the K-PKE public key
    #    For example, if ek = (ek_pke,) from ml_kem_keygen_internal:
    ek_pke = ek[0]  # (A, t_hat) from the prior example

    # 2. Derive ephemeral randomness for the K-PKE encryption from ek + r
    #    Typical approach: ephemeral_r = G(H(ek) || r)
    from auxiliary.cryptographic.functions import H, G  # Adjust import to your code
    # We'll do a simple approach:
    hashed_ek = H(ek[0].__repr__().encode())  # e.g., hash the string representation of ek_pke
    # Concatenate hashed_ek + r and feed to G:
    ephemeral_input = hashed_ek + r
    k1, k2 = G(ephemeral_input)  # G returns 64 bytes, for example, we take first 32
    ephemeral_r = k1

    # 3. Encrypt ephemeral_r under K-PKE
    from key_encryption.encrypt import k_pke_encrypt  # Adjust import path
    # In many KEMs, the ephemeral random is the "message" or the "encryption randomness".
    # We'll treat ephemeral_r as the "randomness" for K-PKE.Encrypt.
    # If your K-PKE.Encrypt expects a 32-byte message, we can do so:
    c = k_pke_encrypt(ek_pke, ephemeral_r, ephemeral_r, d)

    # 4. Derive the final shared key K from ephemeral_r
    #    Often done as K = H(ephemeral_r).
    K = H(ephemeral_r)

    # Return ciphertext + shared key
    return c, K

if __name__ == "__main__":
    # Demo usage:
    from .keygen import ml_kem_keygen_internal
    import os

    d_param = 10
    ek_demo, _ = ml_kem_keygen_internal(d_param)
    # 32-byte random
    r_demo = os.urandom(32)

    ciphertext, shared_key = ml_kem_encaps_internal(ek_demo, r_demo, d_param)
    print("Ciphertext (hex) =", ciphertext.hex()[:80], "...")
    print("Shared key (hex) =", shared_key.hex())
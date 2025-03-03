import os
from typing import Tuple

def ml_kem_encaps(ek: bytes, d: int) -> Tuple[bytes, bytes]:
    """
    ML-KEM.Encaps(ek):

    Inputs:
      ek : the ML-KEM encapsulation key
      d  : compression parameter for the underlying K-PKE

    Outputs:
      (K, c): a 32-byte shared secret key K, and a ciphertext c.

    Steps:
      1. (Optional) Validate ek if needed.
      2. Generate random r (32 bytes).
      3. (c, K) = ML-KEM.Encaps_internal(ek, r, d).
      4. Return (K, c).
    """
    from ml_kem_internal.encaps import ml_kem_encaps_internal

    # 2. Generate ephemeral random r
    r = os.urandom(32)

    # 3. Call the internal encapsulation routine
    c, K = ml_kem_encaps_internal(ek, r, d)

    # 4. Return
    return K, c


if __name__ == "__main__":
    # Example usage:
    from .keygen import ml_kem_keygen

    d_param = 10
    ek_demo, dk_demo = ml_kem_keygen(d_param)

    # Encapsulate
    K_enc, c_demo = ml_kem_encaps(ek_demo, d_param)
    print("Encaps => Shared Key (hex):", K_enc.hex())
    print("Ciphertext (hex):", c_demo.hex()[:80], "...")
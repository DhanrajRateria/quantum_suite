from typing import Tuple

def ml_kem_decaps(dk: bytes, c: bytes, d: int) -> bytes:
    """
    ML-KEM.Decaps(dk, c):

    Inputs:
      dk : the ML-KEM decapsulation key
      c  : the ciphertext produced by ML-KEM.Encaps
      d  : compression parameter for the underlying K-PKE

    Output:
      K : the 32-byte shared secret key

    Steps:
      1. (Optional) Validate dk if needed.
      2. (Optional) Check ciphertext length or format if needed.
      3. K = ML-KEM.Decaps_internal(dk, c, d).
      4. Return K.
    """
    from ml_kem_internal.decaps import ml_kem_decaps_internal

    # 3. Call the internal decapsulation routine
    K = ml_kem_decaps_internal(dk, c, d)
    return K


if __name__ == "__main__":
    # Example usage:
    from .keygen import ml_kem_keygen
    from .encaps import ml_kem_encaps

    d_param = 10
    ek_demo, dk_demo = ml_kem_keygen(d_param)

    # Encapsulate
    K_enc, c_demo = ml_kem_encaps(ek_demo, d_param)
    print("Encaps => K_enc:", K_enc.hex())

    # Decapsulate
    K_dec = ml_kem_decaps(dk_demo, c_demo, d_param)
    print("Decaps => K_dec:", K_dec.hex())

    print("Match?", "YES" if K_enc == K_dec else "NO")
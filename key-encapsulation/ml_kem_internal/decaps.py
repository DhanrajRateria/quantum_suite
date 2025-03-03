from typing import Tuple
# from k_pke_decrypt import k_pke_decrypt
# from cryptographic.functions import H

def ml_kem_decaps_internal(dk: bytes, c: bytes, d: int) -> bytes:
    """
    ML-KEM.Decaps_internal(dk, c):

    Inputs:
      dk: ML-KEM decapsulation key (containing the K-PKE secret key)
      c:  ciphertext from ML-KEM.Encaps_internal
      d:  compression parameter for K-PKE

    Output:
      K:  shared key (32 bytes)

    Steps (typical):
      1. Parse dk to retrieve K-PKE secret key.
      2. ephemeral_r = K-PKE.Decrypt(dk_pke, c, d).
      3. K = H(ephemeral_r).

    If the ciphertext is invalid, ephemeral_r will be wrong => K is effectively random
    => "implicit rejection."
    """
    # 1. Parse the decapsulation key to get the K-PKE secret key
    #    If dk = (dk_pke,) from ml_kem_keygen_internal:
    dk_pke = dk[0]  # (b_enc, s1, s2)

    # 2. Decrypt to recover ephemeral_r
    from key_encryption.decrypt import k_pke_decrypt  # Adjust to your code path
    ephemeral_r = k_pke_decrypt(dk_pke, c, d)

    # 3. Derive the shared key K = H(ephemeral_r)
    from auxiliary.cryptographic.functions import H
    K = H(ephemeral_r)

    return K

if __name__ == "__main__":
    # Demo usage:
    from .keygen import ml_kem_keygen_internal
    from .encaps import ml_kem_encaps_internal
    import os

    d_param = 10
    ek_demo, dk_demo = ml_kem_keygen_internal(d_param)

    # Encapsulate
    r_demo = os.urandom(32)
    c_demo, k_enc = ml_kem_encaps_internal(ek_demo, r_demo, d_param)
    print("Encaps side: ciphertext len =", len(c_demo), " shared key =", k_enc.hex())

    # Decapsulate
    k_dec = ml_kem_decaps_internal(dk_demo, c_demo, d_param)
    print("Decaps side: shared key =", k_dec.hex())

    print("Keys match?", ("YES" if k_enc == k_dec else "NO"))
import os
from typing import Tuple

def ml_kem_keygen(d: int, sK: bytes = None) -> Tuple[bytes, bytes]:
    """
    ML-KEM.KeyGen(d, sK)

    Inputs:
      d  : compression parameter (e.g., 8, 10, 12)
      sK : optional 32-byte seed (if None, generate fresh randomness)

    Outputs:
      ek : encapsulation key for ML-KEM
      dk : decapsulation key for ML-KEM

    Steps (typical):
      1. If sK is None, generate 32 random bytes for internal seeding (optional).
      2. Call ML-KEM.KeyGen_internal(d) to produce (ek, dk).
      3. Optionally perform key checks (pairwise consistency, etc.).
      4. Return (ek, dk).
    """
    from ml_kem_internal.keygen import ml_kem_keygen_internal

    # 1. If sK is not given, we might just ignore it or generate fresh randomness.
    #    In the standard K-PKE-based approach, ML-KEM.KeyGen_internal(d) usually
    #    handles its own randomness. So sK might be unused, or used for advanced seeding.
    if sK is not None and len(sK) != 32:
        raise ValueError("Provided sK must be 32 bytes if used.")

    # 2. Call the internal key generation (which in turn calls K-PKE.KeyGen)
    ek, dk = ml_kem_keygen_internal(d)

    # 3. (Optional) Perform any key checks or serialization if needed.

    return ek, dk


if __name__ == "__main__":
    # Example usage:
    d_param = 10
    ek_demo, dk_demo = ml_kem_keygen(d_param)
    print("ML-KEM KeyGen => ek, dk generated.")
    print("Encap key (demo):", ek_demo)
    print("Decap key (demo):", dk_demo)
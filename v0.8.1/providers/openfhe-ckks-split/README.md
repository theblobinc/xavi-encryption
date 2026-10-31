# OpenFHE CKKS split provider

This is the packed approximate-vector FHE lane for the trusted WG client.

- `client.py` owns the OpenFHE CKKS secret key and performs key generation, encryption and decryption.
- `evaluator.py` must receive only `context.bin`, `public.bin`, `eval-mult.bin`, `eval-auto.bin`, and `manifest.json`. It fails closed if `private.bin` is present.
- Default packing is 16 values per ciphertext. Larger WG vectors are chunked across ciphertexts; scalar encrypted partials can be combined with `sum_handles`.
- The evaluator never branches on decrypted values and exposes no decrypt operation.

The bundle is tied by `key_id = SHA-256(context || public || eval-mult || eval-auto)`. Private-key bytes are excluded from the evaluator manifest.

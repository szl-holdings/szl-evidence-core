# Vendored, byte-for-byte

| file | source | commit | git blob | sha256 |
|---|---|---|---|---|
| `szl_lambda_v1.py` | szl-holdings/szl-lambda-gate `reference/szl_lambda_v1.py` | `fad931134338d05136e522af48e003f4a4a57988` | `8396d8bee64f8aa4431e215dba203eae25225fc2` | `57b264fa96056d1f2d77b797ba80eab087a729283f16416196fdd1423c9c532f` |
| `../spec/lambda_v1_vectors.json` | szl-holdings/szl-lambda-gate `spec/lambda_v1_vectors.json` | same | `d99cc31298b8fad424d6783bdd2295ca9d7adab2` | canonical (szl.lambda/v1 profile) `61bfb0410b9f0eaab0eb9f22f29cb7cb13cfde8c083fe308d895565d6ba9ebd4` |
| `../spec/szl.lambda.v1.json` | szl-holdings/szl-lambda-gate `spec/szl.lambda.v1.json` | same | `57c12a3c9233a4a1fe788e9cb2329e941f4e6be5` | — |

`chain.py` is a port, not a copy, of szl-holdings/szl-kernels `torch-ext/szl_kernels/_chain.py`
at commit `c2b2fc81354b7be6294f50f90d84da2a0ec0cffc` (blob `87118ab32287dad4b64a6c0a92d61ac3bf58d05c`,
sha256 `9344309099b3b8e8f4a30f7d412c699ea8637a09d3cbf35d101d8c3beca01b56`). Byte-equality of
digests, verdict tuples, exports and checkpoints is proven by `python -m szl_evidence_core compat`,
not asserted.

Do not edit vendored files by hand. Re-copy from source and update this table.

# Classic Benchmark Summary

| case | n/t | paillier | keygen_iters | sign_iters | elapsed_sec | keygen_strict_ratio% | sign_strict_ratio% |
|---|---:|---:|---:|---:|---:|---:|---:|
| n2_t1_p2048_k3_s20 | 2/1 | 2048 | 3 | 20 | 24.55 | 88.88 | 76.52 |
| n3_t1_p2048_k3_s20 | 3/1 | 2048 | 3 | 20 | 28.61 | 88.26 | 76.52 |
| n5_t2_p2048_k2_s20 | 5/2 | 2048 | 2 | 20 | 67.21 | 86.74 | 78.38 |
| n5_t2_p3072_k1_s10 | 5/2 | 3072 | 1 | 10 | 80.09 | 89.20 | 75.17 |

## Key phase metrics

| case | keygen.phase1 ms | keygen.phase3 ms | sign.phase2 ms | sign.phase5B ms |
|---|---:|---:|---:|---:|
| n2_t1_p2048_k3_s20 | 580.167 | 454.142 | 701.882 | 5.444 |
| n3_t1_p2048_k3_s20 | 895.102 | 1135.580 | 697.211 | 5.452 |
| n5_t2_p2048_k2_s20 | 1604.661 | 3406.668 | 1936.503 | 12.839 |
| n5_t2_p3072_k1_s10 | 4781.857 | 10767.474 | 3650.571 | 12.846 |

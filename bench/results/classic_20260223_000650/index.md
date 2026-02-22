# Classic Benchmark Index

generated_at=2026-02-23T00:10:10+08:00
output_dir=bench/results/classic_20260223_000650

- n2_t1_p2048_k3_s20.txt
  - command: ./build/protocol_flow_bench --n 2 --t 1 --paillier-bits 2048 --keygen-iters 3 --sign-iters 20
  - elapsed_sec: 24.55
- n3_t1_p2048_k3_s20.txt
  - command: ./build/protocol_flow_bench --n 3 --t 1 --paillier-bits 2048 --keygen-iters 3 --sign-iters 20
  - elapsed_sec: 28.61
- n5_t2_p2048_k2_s20.txt
  - command: ./build/protocol_flow_bench --n 5 --t 2 --paillier-bits 2048 --keygen-iters 2 --sign-iters 20
  - elapsed_sec: 67.21
- n5_t2_p3072_k1_s10.txt
  - command: ./build/protocol_flow_bench --n 5 --t 2 --paillier-bits 3072 --keygen-iters 1 --sign-iters 10
  - elapsed_sec: 80.09

- summary.csv
  - extracted key metrics for quick comparison
- summary.md
  - markdown table view for human reading

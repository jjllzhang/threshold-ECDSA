# threshold_ecdsa

`threshold_ecdsa` 是一个基于 C++20 的 GG2019 阈值 ECDSA 实验性实现，目标是把多方密钥生成与多方签名流程拆解为可测试的状态机模块。项目当前重点是协议流程正确性与消息校验，而不是生产级部署。

## 项目能力概览

- 曲线与标量运算：基于 `libsecp256k1` 封装 `Scalar` / `ECPoint`
- Paillier 同态加密：基于 `libhcs` 封装 `PaillierProvider`
- 密码学基础组件：SHA-256/SHA-512、承诺、转录挑战、定长/变长编码
- STRICT 证明模块：square-free/aux 参数证明接口与 strict/dev 门禁
- 协议会话框架：统一 `Session` 生命周期（运行、完成、中止、超时）
- 网络抽象：`ITransport` + `InMemoryTransport` + `SessionRouter`
- 阈值密钥生成（Keygen）：3 阶段广播/点对点混合流程
- 阈值签名（Sign）：Phase1~Phase5E 全流程状态机
- Phase2 并行化：线程池并行处理 MtA/MtAwc 子实例初始化（A1 证明构造）

## 当前实现进度（按测试里程碑）

- `m0_tests`：基础密码学与编码组件
  - 大整数/标量/点编码
  - 点运算一致性
  - 哈希、承诺、随机数
  - Envelope 编解码
  - Paillier 加解密与同态性质
- `m2_tests`：协议框架与网络骨架
  - In-memory 传输
  - SessionRouter 过滤与分发
  - Keygen/Sign 骨架推进与超时处理
  - strict/dev 缺 proof 行为分流
- `m3_tests`：Keygen 完整流程
  - `n=3,t=1` 与 `n=5,t=2` 一致性
  - Feldman share 校验
  - Schnorr 证明校验
  - Paillier 公钥约束 `N > q^8`
  - Phase1 的 square-free/aux proof strict 校验
  - 篡改消息触发中止
- `m4_tests`：Sign 完整流程与故障路径
  - 端到端生成并验证 `(r,s)`
  - Phase2 附录 A 证明（A.1/A.2/A.3）校验
  - Phase5D 篡改导致失败
  - Phase2 instance id 不一致触发中止
  - Phase4/Phase5B 的 ZK proof 篡改触发中止
  - M9 对抗场景：错 commitment / 错 `δ_i` / 错 `Γ_i` / 错 `V_i` 触发中止且无结果泄露

## 协议流程摘要

### Keygen（`KeygenSession`）

1. Phase1：广播 `commit(Y_i)` 与 Paillier 公钥  
2. Phase2：广播 open + Feldman 承诺，点对点发送 share  
3. Phase3：广播 `X_i = g^{x_i}` 与 Schnorr 证明  
4. 完成：聚合得到本地私钥份额 `x_i`、群公钥 `y`、全体 `X_i` 与 Paillier 公钥集合

### Sign（`SignSession`）

1. Phase1：提交 `Gamma_i` 承诺  
2. Phase2：双向 MtA / MtAwc + 附录A证明（A.1/A.2/A.3）交互，得到 `delta_i`、`sigma_i` 相关份额  
3. Phase3：广播 `delta_i` 并聚合求逆  
4. Phase4：打开 `Gamma_i` + Schnorr 证明，计算 `R` 与 `r`  
5. Phase5A~5E：两轮承诺-打开（含 `A_i` Schnorr 与 `V_i=R^{s_i}g^{l_i}` 关系证明）与 `s_i` 揭示，最终聚合并本地验证 ECDSA 签名

## 代码结构

```text
include/tecdsa/
  crypto/      # 标量、点、Paillier、哈希、承诺、编码、转录
  net/         # Envelope、传输接口、内存网络
  protocol/    # Session、Router、KeygenSession、SignSession
src/
  crypto/
  net/
  protocol/
tests/
  m0_tests.cpp
  m2_tests.cpp
  m3_tests.cpp
  m4_tests.cpp
third_party/
  secp256k1/
  libhcs/
```

## 依赖

- CMake >= 3.22
- 支持 C++20 的编译器（clang++/g++）
- GMP / gmpxx（链接 `gmp`, `gmpxx`）
- OpenSSL `libcrypto`
- 子模块：
  - `third_party/secp256k1`
  - `third_party/libhcs`

## 构建与测试

```bash
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

也可以直接运行单项测试：

```bash
./build/m0_tests
./build/m2_tests
./build/m3_tests
./build/m4_tests
./build/m9_bench --n 5 --t 2 --keygen-iters 1 --sign-iters 20
```

## 使用边界与注意事项

- 当前网络层仅有内存传输实现，未包含真实网络协议、鉴权、重传或持久化。
- 代码主要面向研究与工程分层验证，未经过生产安全审计。
- 若用于真实系统，需要补齐传输安全、密钥托管、审计日志、对抗性测试与性能优化。

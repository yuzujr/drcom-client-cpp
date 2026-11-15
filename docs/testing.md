# 验证与故障注入

常规测试需要 CMake 3.16+、C++20 编译器和 Python 3.9+。测试只使用临时目录、
回环地址和临时 UDP 端口，不读取实际账号配置。

```sh
cmake -S . -B build-check -DCMAKE_BUILD_TYPE=Debug
cmake --build build-check -j 4
ctest --test-dir build-check --output-on-failure -j 4
```

Visual Studio 多配置生成器在 build 和 ctest 命令上增加 `--config Release` 和
`-C Release`。只构建客户端时可用 `-DBUILD_TESTING=OFF`，无需 Python。
Nix 开发环境提供上述工具，`nix build` 也会运行 CTest。

CTest 的覆盖范围：

| 测试 | 验证内容 | 平台 |
| --- | --- | --- |
| configuration | 配置边界、私密诊断、失败不覆盖旧值、保存重载 | 全平台 |
| protocol_oracle | Python 独立计算报文与 MD5/校验和 | 全平台 |
| fault_recovery | 截断响应、丢包、旧包、拒绝认证、取消等待 | 全平台 |
| runtime_control | 开关持久化、单实例、状态有效期、信号退出、自动重试 | POSIX |
| delayed_keepalive | 延迟 800ms 的响应不会导致重复登录 | POSIX |
| network_selection | Linux 路由解析、UDP 等待期限和中断 | Linux |

Windows 的故障测试通过控制命令验证暂停和取消；POSIX 信号退出测试只在
Linux/macOS 运行。CI 的三平台构建均运行 CTest，不以文件存在作为运行验证。

内存和未定义行为检查使用 GCC/Clang：

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DDRCOM_SANITIZERS=address,undefined
cmake --build build-asan -j 4
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build-asan --output-on-failure -j 4
```

Clang 可额外构建 libFuzzer。配置 harness 检查任意文件输入，并对有效输入验证
保存、重载后的登录报文不变；加密 harness 覆盖任意长度输入和校验和扩展输出。

```sh
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DDRCOM_BUILD_FUZZERS=ON
cmake --build build-fuzz -j 4
mkdir -p /tmp/drcom-config-corpus /tmp/drcom-crypto-corpus
cp config/*.conf /tmp/drcom-config-corpus/
build-fuzz/fuzz_config /tmp/drcom-config-corpus -max_total_time=60 -max_len=8192
build-fuzz/fuzz_crypto /tmp/drcom-crypto-corpus -max_total_time=60 -max_len=8192
```

CI 每个 harness 运行约 20 秒。较长运行可调整 `-max_total_time`，使用的语料须为
虚构配置。失败输入应先去除账号信息再作为回归样例提交。

这些测试验证本仓库的编码约定和故障行为；真实校园服务器兼容性仍需要脱敏的
独立报文证据或实际网络验证，详见 [protocol.md](protocol.md)。

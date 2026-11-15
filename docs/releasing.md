# 安装与发布验证

版本号唯一来源为仓库根目录 `VERSION`。CMake 项目版本和 `--version` 使用同一
文件。发布 tag 必须为 `v` 加文件内容，否则 CI 在构建前失败。

本地生成并验证当前平台的发行包：

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --config Release -j 4
ctest --test-dir build-release -C Release --output-on-failure -j 4
python3 scripts/package.py --build-dir build-release --output-dir dist
```

可传 `--tag v1.5.2` 等预期 tag；它必须和当前 `VERSION` 完全相符。脚本执行
CMake install，再打包、解压；从空工作目录执行解压后的客户端，核对二进制版本、
未知运行状态，运行独立故障恢复测试。POSIX 还会使用包内 mock 执行控制、恢复和
退出测试。发布的是已验证过的那个压缩包，而不是从构建目录重新拼装一份。

安装遵循 GNUInstallDirs，默认布局为：

```text
<prefix>/bin/drcom_client[.exe]
<prefix>/bin/mock_drcom_server[.exe]
<prefix>/bin/windows-autostart.ps1          # Windows
<prefix>/share/drcom-client-cpp/config/*.conf
<prefix>/share/doc/drcom-client-cpp/...
```

这是旧版 `<prefix>/drcom-client-cpp/bin` 布局的调整；脚本或服务如果写死旧路径，
升级时需同步改为新路径。配置模板只安装到共享数据目录，不会覆盖实际账号文件。
Nix 使用同一套 CMake 安装规则。

压缩包名包含 `VERSION`、平台和构建机器架构；每个包有相邻的 `.sha256` 文件。
Linux/macOS 下载后可用 `sha256sum --check <文件>.sha256`（或 macOS 的
`shasum -a 256 -c <文件>.sha256`）检查。Windows 可用
`Get-FileHash <文件>.zip -Algorithm SHA256` 和 `.sha256` 中的值比较。
CI 发布前再次校验下载的所有包；只有 release job 具有写 release 的权限。

CI 在 Linux、Windows、macOS 各自构建和验证，不能保证所有旧系统的 ABI 兼容。
例如本地 Nix 构建会引用 Nix store，不能当作通用 Linux 二进制分发；通用发行包
应使用对应 CI 的平台构建。协议测试不代替实际校园网认证验证。

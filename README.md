# DRCOM Client C++

一个用 C++ 编写的 DRCOM 校园网认证客户端，支持吉林大学校园网认证。
基于[jlu-drcom-client](https://github.com/AndrewLawrence80/jlu-drcom-client)，
主要改动：
- POSIX -> POSIX、Windows
- 硬编码 -> 配置文件
- C语言 -> C++20
- make -> cmake
- 增加模拟服务器用于测试

## 安装

### Release

在[Release](https://github.com/yuzujr/drcom-client-cpp/releases/latest)中下载Windows、MacOS、Linux版本。

### NixOS

在 `flake.nix` 中添加：

```nix
inputs.drcom-client-cpp.url = "github:yuzujr/drcom-client-cpp";
```

在 NixOS 配置中：

```nix
imports = [ inputs.drcom-client-cpp.nixosModules.default ];
services.drcom-client-cpp = {
  enable = true;
  configFile = "/etc/drcom.conf";
};
```

先将 `config/drcom_jlu.conf` 复制到 `/etc/drcom.conf`，填入账号信息并限制文件权限
（例如 `chmod 600 /etc/drcom.conf`）。密码配置文件应放在 Nix store 之外。
服务随系统启动；用 `systemctl status drcom-client-cpp` 查看状态，
用 `journalctl -u drcom-client-cpp` 查看日志。

### Windows 自动启动

将 `drcom_client.exe`、填好的 `drcom.conf` 和 `scripts/windows-autostart.ps1`
放在同一目录，在 PowerShell 中执行：

```powershell
.\windows-autostart.ps1
```

脚本为当前用户注册登录后启动的计划任务，并立即启动客户端。日志位于
`%LOCALAPPDATA%\DrcomClient\drcom.log`，最多保留当前文件和一个备份文件。
移除自动启动：

```powershell
.\windows-autostart.ps1 -Uninstall
```

### 临时运行

不安装直接运行：

```bash
nix run github:yuzujr/drcom-client-cpp -- -c /path/to/drcom.conf
```

## 构建步骤

### 系统要求

- CMake 3.16 或更高版本
- C++20 兼容的编译器（MSVC / GCC / Clang）

### 编译安装

```bash
# 创建构建目录
mkdir build && cd build

# 配置项目
cmake .. -DCMAKE_BUILD_TYPE=Release (-DCMAKE_INSTALL_PREFIX="安装目录")(可选)

# 编译
cmake --build . --config Release

# 安装（可选）
cmake --build . --target install
```

编译完成后，可执行文件位于：
- `build/src/drcom_client` - 主客户端程序
- `build/mock_server/mock_drcom_server` - 测试服务器

## 配置文件

项目提供了两个配置文件模板：

- `config/drcom_jlu.conf` - 吉林大学配置模板
- `config/drcom_test.conf` - 本地测试配置模板


## 使用方法
请参考配置文件中的注释。没有可用网卡时客户端等待网络；服务器无响应时逐步延长
重试间隔（最多 1 分钟），相同失败原因只在首次输出 warning。网卡、IP 或 MAC
变化时会重新认证，即使客户端正在等待重试。

Linux 默认按主路由表的最长匹配和路由优先级选择物理网卡，排除 TUN 等虚拟接口；
Windows/macOS 优先使用系统路由对应的物理网卡，路由指向虚拟接口时仅在物理网卡
唯一的情况下自动选择。`client_ip` 可以指定本地绑定地址，客户端会尊重这个设置。
绑定本地地址不等于绕过系统的 VPN 策略路由，也不代表认证服务器一定可达。

默认 `auto_identity=true`，认证包使用所选网卡的 IP/MAC；设为 `false` 时保留配置中
的 `ip` 和 `mac`。网络检测不会修改这些配置。心跳响应等待时间为 2 秒。
认证被明确拒绝时会退出并记录原因，修改配置后需重新启动服务或计划任务。
在 Linux 上默认只向标准输出写日志，由 systemd 管理日志；Windows 的文件日志会轮转。

# 故障排查与隐私

先运行与后台进程使用同一状态目录的命令：

```sh
drcom_client status --state-dir /path/to/state
```

状态命令不读取账号文件，也不会启动认证。默认目录、服务账号和 `--state-dir`
必须对应，详见 README。状态只记录本地客户端的判断，不能证明外网一定可用。

| 状态或症状 | 含义与处理 |
| --- | --- |
| `disabled` | 自动认证已暂停。执行相同目录下的 `enable`；仅启动服务不会清除此开关。 |
| `Runtime: unknown` | 此目录没有可读快照。核对用户和目录，再检查服务是否已启动。 |
| `Runtime: not running` | 快照里的进程已退出。检查最后一次失败及服务日志。 |
| `State: unknown (stale status)` | PID 仍存在，但状态超过 30 秒没有更新。可能是进程卡住或 PID 被复用；先核对进程，再决定是否重启。 |
| `waiting for network` | 没有可用的物理接口/源地址。检查网卡、链路、DHCP 和服务器路由。 |
| `authenticating` | 正在等待 challenge/login；每次交互最长约 15 秒，期间仍可暂停或退出。 |
| `waiting to retry` | 传输、格式或心跳失败，等待退避重试。查看 `Last failure` 和重试倒计时。 |
| `Authentication rejected with status ...` | 服务器明确拒绝认证，客户端退出。核对账号、密码、账号状态及当前网络后重启；程序不猜测未验证的状态码含义。 |
| `runtime lock` | 同一状态目录已有客户端。检查重复的手动运行、服务和计划任务；不要删锁文件绕过互斥。 |
| `Cannot open log file` | Windows 当前工作目录不可写。检查启动脚本的工作目录和访问权限。 |

`authenticated` 表示本地登录交互已成功，随后由心跳维持状态。认证成功而网络仍
不可用时，应检查地址、路由、DNS 和校园网络策略；不要仅凭在线状态反复改密码。

配置错误会报告文件、行号和键名，不回显配置值。数字必须完整合法，端口为
1–65535，布尔值支持 true/false、yes/no、on/off、1/0。重复键和未知键会拒绝
加载；这会让旧配置中被忽略的拼写错误显现出来。用户名上限为 36 字节、hostname
为 32 字节、os_info 为 54 字节，UTF-8 字符可能占多个字节。修改配置后重启进程，
`enable` 不重新读取文件。

Linux 可先检查：

```sh
systemctl status drcom-client-cpp
journalctl -u drcom-client-cpp -b --no-pager
ip -4 address
ip -4 route get <认证服务器IPv4>
```

显式 `client_ip` 必须是本机地址。VPN 的策略路由可能影响服务器可达性；绑定
物理网卡地址并不保证绕过 VPN。`auto_identity=true` 从选中接口取得认证 IP/MAC；
若校园环境要求固定身份，可使用 `false` 并核对配置。不要通过更严格的包序号规则
或未经验证的字段填充值尝试“修复”实际校园网，协议证据要求见 [protocol.md](protocol.md)。

可用本地 mock 排除配置、进程控制和 UDP 基础交互问题：

```sh
mock_drcom_server 61441
drcom_client -c config/drcom_test.conf --state-dir /tmp/drcom-test-state
```

只对 mock 使用测试账号。mock 不是完整服务器实现，不检查所有认证摘要，不能证明
校园网兼容性。自动化验证命令和覆盖边界见 [testing.md](testing.md)。

`debug=true` 会增加交互阶段、报文类型、长度和失败细节，但不会输出用户名、密码、
认证摘要、salt、会话 token 或原始认证报文。mock 的日志也只显示类型与长度。
日志仍可能包含 IP、接口名、时间、文件路径等环境信息；提交 issue 前按需隐藏。
原始抓包及旧版十六进制调试日志可能包含密码派生材料，不能仅隐藏明文密码后公开。
不要上传真实配置、状态目录或未经处理的完整抓包。

Windows 自动启动日志在 `%LOCALAPPDATA%\DrcomClient\drcom.log`（手动运行则为
当前工作目录），按约 1 MiB 轮转，保留一个 `.1` 备份。Linux/macOS 默认输出到
终端或服务日志。配置文件应仅允许运行账号读取；NixOS 账号配置不能放入 Nix store。

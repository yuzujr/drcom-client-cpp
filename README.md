# DRCOM Client C++

一个用 C++ 编写的 DRCOM 校园网认证客户端，支持吉林大学校园网认证。
基于[jlu-drcom-client](https://github.com/AndrewLawrence80/jlu-drcom-client)，
主要改动：
- POSIX -> POSIX、Windows
- 硬编码 -> 配置文件
- C语言 -> C++20
- make -> cmake
- 增加模拟服务器用于测试

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
cmake --build . --config Release -j

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
请参考配置文件中的注释。
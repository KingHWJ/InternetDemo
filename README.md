# C 网络报文学习框架

这是一个纯本机运行的 C 语言网络报文教学示例。程序在内存中构造 Ethernet II、IPv4、TCP 和 HTTP 字节数据，然后把同一块字节缓冲区交给解析器，按网络分层顺序打印处理日志。

它不打开网卡、不需要管理员权限，也不会把报文发到局域网或互联网。报文中的地址只用于学习。

## 快速开始

需要支持 C11 的 C 编译器和 GNU Make。在 macOS/Linux 终端进入项目目录后运行：

```sh
make run
```

清理生成的程序：

```sh
make clean
```

详细操作见[操作手册](docs/操作手册.md)，字段和处理路径见[代码设计](docs/code-design.md)，编译与环境说明见[技术指南](docs/technical-guide.md)。

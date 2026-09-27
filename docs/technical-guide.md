# 技术指南

## 构建与运行环境

- C11 编译器：macOS 的 Apple Clang 或 Linux 上的 GCC/Clang。
- Make。
- 仅使用 C/POSIX socket、`poll` 和标准库，无第三方依赖。
- 普通用户权限即可；只绑定本机 UDP loopback，不使用 raw socket。

```sh
make
./build/packet_demo --help
```

两个终端启动方式和命令参数见[操作手册](操作手册.md)。`make receiver`、`make sender` 可分别使用默认参数启动角色；`make run` 显示帮助；`make clean` 删除构建目录。

## 文件结构

```text
.
├── Makefile
├── README.md
├── docs/
│   ├── code-design.md
│   ├── technical-guide.md
│   └── 操作手册.md
└── src/main.c
```

## 通信边界

程序用 UDP socket 连接 `127.0.0.1`，将自构造的 Ethernet/IPv4/TCP 字节帧作为 UDP 数据报负载交给对端进程。这里的 Ethernet MAC、`10.0.0.1`/`10.0.0.2` 地址和 TCP 端口都是教学帧里的逻辑值。实际操作系统只处理外层 UDP/IP；不会发生内核 TCP 三次握手，也不会在真实网卡上出现这些合成 Ethernet 帧。

因此日志能准确展示程序构造的教学报文字段和本程序状态机收到的字节，但不能用来断言 Linux/macOS 内核 TCP 的具体实现行为。真实 TCP 抓包需要另开真实 TCP socket 并使用抓包工具观察。

## 可调限制

- 默认 UDP 端口：`9000`；自定义范围 `1024`–`65535`。
- 默认空闲关闭计时：`30` 秒；可设为 `1`–`120` 秒。
- 首次回复的 ACK 收到后开始计时；每个新消息和 ACK 都会刷新空闲计时。
- 单条消息长度：1–500 字节。
- 建立连接后支持双向持续发送消息，直到 `:quit` 或空闲超时。
- 只支持 IPv4、未分片帧、固定长度 IPv4/TCP 头和单连接正常路径。

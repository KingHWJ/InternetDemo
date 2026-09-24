# 技术指南

## 环境与启动

- 语言标准：C11。
- 编译器：支持 C11 的 `cc`、Clang 或 GCC。
- 构建工具：GNU Make。
- 外部依赖：无。
- 权限：普通用户权限即可；程序不使用 raw socket，也不依赖网卡。

在项目根目录运行 `make` 编译，生成 `build/packet_demo`；运行 `make run` 编译并启动示例；运行 `make clean` 删除 `build/`。

也可以不用 Make，手动编译：

```sh
cc -std=c11 -Wall -Wextra -Wpedantic -O2 -o packet_demo src/main.c
./packet_demo
```

## 目录结构

```text
.
├── Makefile
├── README.md
├── docs/
│   ├── code-design.md
│   ├── technical-guide.md
│   └── 操作手册.md
└── src/
    └── main.c
```

## 报文格式与范围

当前示例构造一帧 Ethernet II，其中 EtherType `0x0800` 表示 IPv4。IPv4 的 Protocol 字段为 `6`，表示 TCP。TCP 载荷是一条简短的 HTTP/1.1 GET 请求。

示例地址为 `192.0.2.10` 和 `198.51.100.20`，来自文档示例用途地址段；示例 MAC 是本地管理地址。它们是教学数据，不代表本机实际网卡地址。程序计算 IPv4 头部校验和与 TCP 校验和，并在解析时验证。

解析器会验证帧长度、IPv4 版本和长度、TCP 长度与偏移、协议号、分片标志，并拒绝当前示例不支持的分片和非 TCP 数据。它不是完整 TCP/IP 栈：不建立真实 TCP 连接、不重传、不处理拥塞控制、路由、ARP、IPv6、TCP 选项或 IP 分片重组。

## 日志层次

- `[TX]`：在内存中构造示例报文完成。
- `[RX]`：模拟网卡收到了字节帧，开始解析。
- `[L2 Ethernet]`：读取 MAC 地址和 EtherType。
- `[L3 IPv4]`：读取地址、总长度、TTL、协议号、分片字段和校验和。
- `[L4 TCP]`：读取端口、序号、确认号、窗口、标志和校验和。
- `[APP]`：将 TCP 载荷作为 HTTP 文本展示。
- `[DONE]`：完成用户态解析；未发生真实网络收发。

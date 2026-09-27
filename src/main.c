/* POSIX 网络地址、socket、poll、时间、文件描述符相关的系统头文件。 */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/*
 * 本程序用两个进程模拟 TCP 通信，方便在两个终端观察报文。
 * 真实传输只使用本机 UDP 回环地址；下面的 Ethernet、IPv4 和 TCP
 * 头部都是程序自己写入字节数组的“教学报文”，并非操作系统内核报文。
 *
 * 阅读顺序建议：先看 main 选择发送端/接收端，再看 build_packet 如何
 * 组装字节，inspect_packet 如何拆解字节，最后看 run_sender、
 * run_receiver 和 run_chat 如何按照 TCP 状态推进。
 */

/* 每层协议头的固定字节数。本例不生成 IP/TCP 可选字段。 */
#define ETHERNET_HEADER_SIZE 14U
#define IPV4_HEADER_SIZE 20U
#define TCP_HEADER_SIZE 20U
/* 限制一帧最大长度，避免无限制地使用栈内存。 */
#define PACKET_CAPACITY 1400U

/* 这些端口和地址属于教学 TCP 报文；操作系统实际看到的是 UDP 端口。 */
#define CLIENT_PORT 50000U
#define SERVER_PORT 8080U

/* 固定的初始序号便于对照日志手工计算 Ack。真实 TCP 会随机选择序号。 */
#define CLIENT_INITIAL_SEQ 1000U
#define SERVER_INITIAL_SEQ 7000U

/* TCP Flags 是一个按位组合值，一个字节里可以同时设置多个标志。 */
#define TCP_SYN 0x02U
#define TCP_ACK 0x10U
#define TCP_PSH 0x08U
#define TCP_FIN 0x01U

/*
 * 一帧在 packet 字节数组中的布局（偏移从 0 开始）：
 *   [0..13]  Ethernet II
 *   [14..33] IPv4（本例固定 20 字节）
 *   [34..53] TCP（本例固定 20 字节）
 *   [54..]   应用消息，可为空
 */
/*
 * 这是解析器整理出的 TCP 头信息。
 * payload 是“指针”，指向原始帧中 TCP 头后面的数据，并不复制数据；
 * payload_length 则记录这段数据有多少字节。原始帧的缓冲区必须仍有效。
 */
typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t flags;
    const uint8_t *payload;
    size_t payload_length;
} PacketView;

/* static 放在函数定义前，表示函数只在当前 main.c 文件内使用。 */
/* 从网络字节（大端序）读取 16 位整数。bytes[0] 是高 8 位。 */
static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

/* 从网络字节读取 32 位整数；逐字节移位，避免依赖 CPU 的本机字节序。 */
static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

/* 把 16 位整数按网络字节序写进已有缓冲区。 */
static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

/* 把 32 位整数按网络字节序写进已有缓冲区。 */
static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

/*
 * 将一段数据按 16 位大端整数相加，这是 Internet 校验和的第一步。
 * 如果长度是奇数，最后一个字节放在 16 位数的高 8 位，低 8 位补零。
 */
static uint32_t checksum_add(uint32_t sum, const uint8_t *bytes, size_t length)
{
    size_t index = 0U;
    while (index + 1U < length) {
        sum += read_be16(bytes + index);
        index += 2U;
    }
    if (index < length) {
        sum += (uint16_t)((uint16_t)bytes[index] << 8);
    }
    return sum;
}

/* 将加法产生的进位折回低 16 位，再按位取反得到校验和。 */
static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* IPv4 头部校验和：累加头部后执行校验和收尾步骤。 */
static uint16_t internet_checksum(const uint8_t *bytes, size_t length)
{
    return checksum_finish(checksum_add(0U, bytes, length));
}

/*
 * TCP 校验和除了 TCP 数据，还包含 IPv4 伪首部：源/目的 IP、协议号和
 * TCP 长度。伪首部仅参与计算，不会写进实际报文。
 */
static uint16_t tcp_checksum(const uint8_t *ip, const uint8_t *tcp,
                             size_t tcp_length)
{
    uint32_t sum = 0U;
    sum = checksum_add(sum, ip + 12U, 8U);
    sum += 6U;
    sum += (uint16_t)tcp_length;
    sum = checksum_add(sum, tcp, tcp_length);
    return checksum_finish(sum);
}

/* 打印 6 个 MAC 字节；%02x 表示十六进制、不足两位时在左侧补零。 */
static void print_mac(const uint8_t *bytes)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2],
           bytes[3], bytes[4], bytes[5]);
}

/* 把连续 4 个 IPv4 地址字节打印为点分十进制格式。 */
static void print_ipv4(const uint8_t *bytes)
{
    printf("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/* TCP 标志位可以同时出现，所以这里逐位判断，而不是用一个值比较。 */
static void print_flags(uint8_t flags)
{
    bool any = false;
    if ((flags & TCP_SYN) != 0U) { fputs(" SYN", stdout); any = true; }
    if ((flags & TCP_ACK) != 0U) { fputs(" ACK", stdout); any = true; }
    if ((flags & TCP_PSH) != 0U) { fputs(" PSH", stdout); any = true; }
    if ((flags & TCP_FIN) != 0U) { fputs(" FIN", stdout); any = true; }
    if ((flags & 0x04U) != 0U) { fputs(" RST", stdout); any = true; }
    if (!any) fputs(" (none)", stdout);
}

/*
 * 打印载荷时把回车、换行和控制字节转义，避免它们改变日志排版；
 * >=0x80 的字节原样写出，使终端能显示 UTF-8 中文消息。
 */
static void print_payload(const uint8_t *bytes, size_t length)
{
    size_t index;
    for (index = 0U; index < length; ++index) {
        if (bytes[index] == '\r') fputs("\\r", stdout);
        else if (bytes[index] == '\n') fputs("\\n\n", stdout);
        else if (bytes[index] >= 32U && bytes[index] <= 126U) putchar(bytes[index]);
        else if (bytes[index] >= 0x80U) putchar(bytes[index]); /* 保留 UTF-8 文本。 */
        else printf("\\x%02x", bytes[index]);
    }
    if (length == 0U || bytes[length - 1U] != '\n') putchar('\n');
}

/*
 * 在调用者提供的 packet 缓冲区里“从外向内”构造一帧：
 * Ethernet 头 | IPv4 头 | TCP 头 | 应用载荷。
 * capacity 是缓冲区可用空间；packet_length 是输出参数，成功时写入实际长度。
 * from_client 决定逻辑地址和 MAC 的方向，其余参数填写 TCP 头字段。
 */
static bool build_packet(uint8_t *packet, size_t capacity, bool from_client,
                         uint16_t source_port, uint16_t destination_port,
                         uint32_t sequence, uint32_t acknowledgement,
                         uint8_t flags, const uint8_t *payload,
                         size_t payload_length, size_t *packet_length)
{
    /* 本地管理的虚构 MAC，只写入教学帧，并未配置到真实网卡。 */
    static const uint8_t client_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t server_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    /* 每层的长度由“头部长度 + 下一层数据长度”算出。 */
    const size_t tcp_length = TCP_HEADER_SIZE + payload_length;
    const size_t ip_length = IPV4_HEADER_SIZE + tcp_length;
    const size_t frame_length = ETHERNET_HEADER_SIZE + ip_length;
    /* ip、tcp 是指向 packet 内部位置的指针，用它们按偏移填写字段。 */
    uint8_t *ip;
    uint8_t *tcp;

    /* 先检查容量，防止 memcpy 或字段写入越过 packet 缓冲区。 */
    if (frame_length > capacity || ip_length > UINT16_MAX || tcp_length > UINT16_MAX) {
        /* 返回 false 告诉调用者构造失败；绝不写出缓冲区边界。 */
        return false;
    }

    /* Ethernet II：0..5 目的 MAC，6..11 源 MAC，12..13 EtherType。 */
    memcpy(packet, from_client ? server_mac : client_mac, 6U);
    memcpy(packet + 6U, from_client ? client_mac : server_mac, 6U);
    write_be16(packet + 12U, 0x0800U); /* 0x0800 表示后面承载 IPv4。 */

    /* ip 指向 Ethernet 头之后，也就是 IPv4 头的第一个字节。 */
    ip = packet + ETHERNET_HEADER_SIZE;
    memset(ip, 0, ip_length);
    ip[0] = 0x45U; /* 高 4 位是 IPv4 版本 4，低 4 位 IHL=5（5*4=20 字节）。 */
    write_be16(ip + 2U, (uint16_t)ip_length); /* IPv4 总长度包含 IP 头和 TCP 段。 */
    write_be16(ip + 4U, 0x1234U); /* Identification：本例固定的报文标识。 */
    write_be16(ip + 6U, 0x4000U); /* Flags/Offset：DF=1（不分片），片偏移为 0。 */
    ip[8] = 64U; /* TTL：每经过一个路由器通常减 1；本例不经过路由器。 */
    ip[9] = 6U;  /* Protocol=6 表示 IPv4 载荷是 TCP。 */
    if (from_client) {
        /* 逻辑客户端 10.0.0.1 -> 逻辑服务端 10.0.0.2。 */
        ip[12] = 10U; ip[13] = 0U; ip[14] = 0U; ip[15] = 1U;
        ip[16] = 10U; ip[17] = 0U; ip[18] = 0U; ip[19] = 2U;
    } else {
        /* 回复方向的源地址和目的地址互换。 */
        ip[12] = 10U; ip[13] = 0U; ip[14] = 0U; ip[15] = 2U;
        ip[16] = 10U; ip[17] = 0U; ip[18] = 0U; ip[19] = 1U;
    }
    write_be16(ip + 10U, internet_checksum(ip, IPV4_HEADER_SIZE)); /* IPv4 头校验和。 */

    /* tcp 指向 IPv4 头之后；以下偏移对应 TCP 头字段。 */
    tcp = ip + IPV4_HEADER_SIZE;
    write_be16(tcp, source_port);             /* 0..1：源端口 */
    write_be16(tcp + 2U, destination_port);   /* 2..3：目的端口 */
    write_be32(tcp + 4U, sequence);           /* 4..7：发送序号 Seq */
    write_be32(tcp + 8U, acknowledgement);    /* 8..11：确认号 Ack */
    tcp[12] = 0x50U; /* 数据偏移 5，表示 TCP 头长 5*4=20 字节，无选项。 */
    tcp[13] = flags;  /* SYN/ACK/PSH/FIN 等控制标志的组合。 */
    write_be16(tcp + 14U, 4096U); /* 接收窗口：教学值，不实现实际窗口流控。 */
    /* TCP 头部固定为 20 字节，因此载荷从 tcp + TCP_HEADER_SIZE 开始。 */
    if (payload_length > 0U) memcpy(tcp + TCP_HEADER_SIZE, payload, payload_length);
    write_be16(tcp + 16U, tcp_checksum(ip, tcp, tcp_length));
    *packet_length = frame_length;
    return true;
}

/*
 * 按协议封装顺序的反方向解析 packet：先 Ethernet，再 IPv4，最后 TCP。
 * 每解析出一层的长度/类型，就能找到下一层的起点和长度。
 * 成功时把 TCP 字段整理到 view；view->payload 仍指向 packet 内部，不复制。
 */
static bool inspect_packet(const char *direction, const uint8_t *packet,
                           size_t packet_length, PacketView *view)
{
    const uint8_t *ip;
    const uint8_t *tcp;
    size_t ip_header_length;
    size_t ip_total_length;
    size_t tcp_header_length;
    size_t tcp_length;
    uint16_t ether_type;
    uint16_t fragment_field;
    bool ip_checksum_valid;
    bool tcp_checksum_valid;

    /* direction 只用于区分日志是本进程正在发，还是刚收到。 */
    if (strncmp(direction, "TX", 2U) == 0) {
        printf("\n[%s] 构造 Ethernet 帧，共 %zu 字节，逐层检查封装结果。\n",
               direction, packet_length);
    } else {
        printf("\n[%s] 收到 Ethernet 帧，共 %zu 字节，开始逐层解包。\n",
               direction, packet_length);
    }
    /* 先检查长度，再读字段；网络字节不能假设一定完整或可信。 */
    if (packet_length < ETHERNET_HEADER_SIZE) {
        puts("[ERROR] Ethernet 头部不完整。");
        return false;
    }
    ether_type = read_be16(packet + 12U);
    printf("[L2 Ethernet] 目的 MAC="); print_mac(packet);
    printf(" 源 MAC="); print_mac(packet + 6U);
    printf(" EtherType=0x%04x\n", ether_type);
    if (ether_type != 0x0800U || packet_length < ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE) {
        puts("[ERROR] 不是完整的 Ethernet/IPv4 帧。");
        return false;
    }

    /* Ethernet 头固定 14 字节，所以 IPv4 从 packet[14] 开始。 */
    ip = packet + ETHERNET_HEADER_SIZE;
    if ((ip[0] >> 4) != 4U) {
        puts("[ERROR] IP 版本不是 IPv4。");
        return false;
    }
    /* IHL 的单位是 4 字节；IPv4 总长度包含 IP 头和后面的 TCP 段。 */
    ip_header_length = (size_t)(ip[0] & 0x0fU) * 4U;
    ip_total_length = read_be16(ip + 2U);
    /* 所有判断都先验证长度，再根据长度字段计算指针偏移。 */
    if (ip_header_length < IPV4_HEADER_SIZE ||
        ip_header_length > packet_length - ETHERNET_HEADER_SIZE ||
        ip_total_length < ip_header_length ||
        ip_total_length > packet_length - ETHERNET_HEADER_SIZE) {
        puts("[ERROR] IPv4 长度字段越界或不合法。");
        return false;
    }
    ip_checksum_valid = internet_checksum(ip, ip_header_length) == 0U;
    printf("[L3 IPv4] 版本=4 头长=%zu 总长=%zu TTL=%u 协议号=%u 源 IP=",
           ip_header_length, ip_total_length, ip[8], ip[9]);
    print_ipv4(ip + 12U); printf(" -> 目的 IP="); print_ipv4(ip + 16U);
    printf(" 头部校验和=%s\n",
           ip_checksum_valid ? "正确" : "错误");
    if (!ip_checksum_valid) {
        puts("[ERROR] IPv4 头部校验和错误，丢弃此帧。");
        return false;
    }
    /* 本解析器不做 IP 分片重组，所以遇到分片或非 TCP 协议就停止。 */
    fragment_field = read_be16(ip + 6U);
    if ((fragment_field & 0x3fffU) != 0U || ip[9] != 6U) {
        puts("[ERROR] 示例只解析未分片的 TCP/IPv4 报文。");
        return false;
    }

    /* TCP 起点由 IPv4 IHL 决定，不硬编码为固定的 packet 偏移。 */
    tcp = ip + ip_header_length;
    tcp_length = ip_total_length - ip_header_length;
    if (tcp_length < TCP_HEADER_SIZE) {
        puts("[ERROR] TCP 头部不完整。");
        return false;
    }
    /* TCP 数据偏移字段位于 TCP 头第 12 字节的高 4 位，单位也是 4 字节。 */
    tcp_header_length = (size_t)(tcp[12] >> 4) * 4U;
    if (tcp_header_length < TCP_HEADER_SIZE || tcp_header_length > tcp_length) {
        puts("[ERROR] TCP 数据偏移字段不合法。");
        return false;
    }
    view->source_port = read_be16(tcp);
    view->destination_port = read_be16(tcp + 2U);
    view->sequence = read_be32(tcp + 4U);
    view->acknowledgement = read_be32(tcp + 8U);
    view->flags = tcp[13];
    /* 载荷紧跟 TCP 头；指针引用原帧，长度用 IPv4 总长度计算出来。 */
    view->payload = tcp + tcp_header_length;
    view->payload_length = tcp_length - tcp_header_length;
    tcp_checksum_valid = tcp_checksum(ip, tcp, tcp_length) == 0U;
    printf("[L4 TCP] 端口=%u -> %u Seq=%u Ack=%u 窗口=%u 标志=",
           view->source_port, view->destination_port, view->sequence,
           view->acknowledgement, read_be16(tcp + 14U));
    print_flags(view->flags);
    printf(" 校验和=%s\n",
           tcp_checksum_valid ? "正确" : "错误");
    if (!tcp_checksum_valid) {
        puts("[ERROR] TCP 校验和错误，丢弃此帧。");
        return false;
    }
    if (view->payload_length > 0U) {
        printf("[APP] TCP 载荷 %zu 字节：\n", view->payload_length);
        print_payload(view->payload, view->payload_length);
    }
    fflush(stdout);
    return true;
}

/*
 * 一次完整的“发送一段 TCP 教学数据”操作：构造整帧、打印封装日志，
 * 再通过 UDP sendto 把字节送给另一进程。socket_fd 是 socket() 返回的句柄；
 * peer 保存本机接收端的 UDP 地址。
 */
static bool send_packet(int socket_fd, const struct sockaddr_in *peer,
                        bool from_client, uint32_t sequence,
                        uint32_t acknowledgement, uint8_t flags,
                        const uint8_t *payload, size_t payload_length)
{
    uint8_t packet[PACKET_CAPACITY];
    size_t packet_length;
    PacketView view;
    /* 根据方向反转 TCP 端口。注意这两个是教学 TCP 头字段，不是 UDP 端口。 */
    uint16_t source_port = from_client ? CLIENT_PORT : SERVER_PORT;
    uint16_t destination_port = from_client ? SERVER_PORT : CLIENT_PORT;

    if (!build_packet(packet, sizeof(packet), from_client, source_port,
                      destination_port, sequence, acknowledgement, flags,
                      payload, payload_length, &packet_length)) {
        fputs("[ERROR] 无法构造报文：载荷超过缓冲区。\n", stderr);
        return false;
    }
    /* 发送前也解析一次，让发送方能看到自己实际构造了哪些字段。 */
    if (!inspect_packet("TX 封装", packet, packet_length, &view)) return false;
    /* sendto 只传送 packet_length 个字节，不会发送整个 1400 字节数组。 */
    if (sendto(socket_fd, packet, packet_length, 0,
               (const struct sockaddr *)peer, sizeof(*peer)) != (ssize_t)packet_length) {
        perror("sendto");
        return false;
    }
    return true;
}

/*
 * 等待一个 UDP 数据报并把它当作教学 Ethernet 帧解析。
 * packet 特意声明为 static：inspect_packet 返回的 payload 指针指向 packet，
 * 若它是普通局部数组，函数返回后内存就失效。调用者须在下一次
 * receive_packet 调用前用完或复制 payload。
 */
static bool receive_packet(int socket_fd, int timeout_ms,
                           struct sockaddr_in *peer, PacketView *view)
{
    struct pollfd descriptor;
    static uint8_t packet[PACKET_CAPACITY];
    socklen_t peer_length = sizeof(*peer);
    ssize_t received;
    int result;

    /* poll 可带超时等待 socket 可读；超时返回 0，出错返回 -1。 */
    descriptor.fd = socket_fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    do {
        result = poll(&descriptor, 1U, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result == 0) return false; /* 等待时间内没有包，调用者可当作超时处理。 */
    if (result < 0) {
        perror("poll");
        return false;
    }
    /* recvfrom 把 UDP 负载写入 packet，并把发送方地址写入 peer。 */
    received = recvfrom(socket_fd, packet, sizeof(packet), 0,
                        (struct sockaddr *)peer, &peer_length);
    if (received < 0) {
        perror("recvfrom");
        return false;
    }
    return inspect_packet("RX 解包", packet, (size_t)received, view);
}

/* 用单调时钟算超时；系统时钟被用户调快/调慢时它仍按经过时间前进。 */
static int64_t monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/*
 * 本端主动关闭时完成 TCP 四次挥手：
 * 1) 发 FIN；2) 收对端 ACK；3) 收对端 FIN；4) 回最终 ACK。
 * send_next/receive_next 是调用者维护的两个方向的“下一个序号”，
 * 通过指针传入，因此本函数递增后调用者也能看到新值。
 */
static bool initiate_close(int socket_fd, const struct sockaddr_in *peer,
                           bool from_client, uint32_t *send_next,
                           uint32_t *receive_next)
{
    PacketView packet;
    struct sockaddr_in source = *peer;

    puts("[TIMEOUT/QUIT] 发起方发送 FIN（第 1 次挥手）。");
    if (!send_packet(socket_fd, peer, from_client, *send_next, *receive_next,
                     TCP_FIN | TCP_ACK, NULL, 0U)) return false;
    (*send_next)++; /* FIN 和 SYN 一样，各占用一个序号。 */
    if (!receive_packet(socket_fd, 5000, &source, &packet) ||
        packet.flags != TCP_ACK || packet.acknowledgement != *send_next) {
        puts("[ERROR] 等待对端确认 FIN 超时或序号不匹配。");
        return false;
    }
    puts("[STATE] 收到第 2 次挥手 ACK；等待对端 FIN。");
    if (!receive_packet(socket_fd, 5000, &source, &packet) ||
        packet.flags != (TCP_FIN | TCP_ACK) ||
        packet.sequence != *receive_next ||
        packet.acknowledgement != *send_next) {
        puts("[ERROR] 等待对端 FIN 超时或序号不匹配。");
        return false;
    }
    (*receive_next)++; /* 对端 FIN 也占用对端方向的一个序号。 */
    puts("[STATE] 收到第 3 次挥手 FIN，回复最终 ACK。");
    if (!send_packet(socket_fd, peer, from_client, *send_next,
                     *receive_next, TCP_ACK, NULL, 0U)) return false;
    puts("[STATE] CLOSED：四次挥手完成。");
    return true;
}

/* 对端先发 FIN 时的关闭流程：回 ACK，再发自己的 FIN，最后收 ACK。 */
static bool respond_to_close(int socket_fd, const struct sockaddr_in *peer,
                             bool from_client, PacketView *received,
                             uint32_t *send_next, uint32_t *receive_next)
{
    struct sockaddr_in source = *peer;
    PacketView packet;

    if (received->sequence != *receive_next ||
        received->acknowledgement != *send_next) {
        puts("[ERROR] FIN 的序号或确认号不匹配。");
        return false;
    }
    (*receive_next)++;
    puts("[STATE] 收到第 1 次挥手 FIN，回复 ACK（第 2 次挥手）。");
    if (!send_packet(socket_fd, peer, from_client, *send_next,
                     *receive_next, TCP_ACK, NULL, 0U)) return false;
    puts("[STATE] 发送自己的 FIN（第 3 次挥手）。");
    if (!send_packet(socket_fd, peer, from_client, *send_next,
                     *receive_next, TCP_FIN | TCP_ACK, NULL, 0U)) return false;
    (*send_next)++;
    if (!receive_packet(socket_fd, 5000, &source, &packet) ||
        packet.flags != TCP_ACK || packet.acknowledgement != *send_next) {
        puts("[ERROR] 等待最终 ACK 超时或序号不匹配。");
        return false;
    }
    puts("[STATE] CLOSED：收到第 4 次挥手 ACK，连接关闭。");
    return true;
}

/*
 * 建连并完成第一轮自动请求/回复后，双方都进入此聊天循环。
 * poll 同时等待键盘输入和 socket 数据，因此任一端都可随时发消息。
 * from_client=true 表示本端是发送端；空闲超时由服务端发起 FIN，
 * 客户端多等 15 秒给服务端的 FIN 留出传输和处理时间。
 */
static bool run_chat(int socket_fd, const struct sockaddr_in *peer,
                     bool from_client, unsigned int idle_seconds,
                     uint32_t *send_next, uint32_t *receive_next)
{
    struct sockaddr_in source = *peer;
    PacketView packet;
    struct pollfd descriptors[2];
    bool stdin_open = true;
    /* 活动窗口：任一报文或本地发消息都会重新计算这个截止时间。 */
    const int64_t activity_window_ms =
        ((int64_t)idle_seconds + (from_client ? 15 : 0)) * 1000;
    int64_t idle_deadline = monotonic_milliseconds() + activity_window_ms;

    puts("[CHAT] 现在可以在任一终端输入消息并回车；输入 :quit 可主动关闭。\n"
         "       接收端空闲超时后也会发起关闭。");
    fflush(stdout);
    for (;;) {
        int64_t now = monotonic_milliseconds();
        int64_t remaining = idle_deadline - now;
        int timeout_ms;
        int result;

        if (remaining <= 0) {
            if (!from_client) {
                puts("[TIMEOUT] 接收端空闲计时到期。");
                return initiate_close(socket_fd, peer, from_client,
                                      send_next, receive_next);
            }
            puts("[ERROR] 等待接收端空闲超时关闭。");
            return false;
        }
        timeout_ms = remaining > 2147483647 ? 2147483647 : (int)remaining;
        /* fd 0 是标准输入（键盘）；-1 表示当前不再监听输入。 */
        descriptors[0].fd = stdin_open ? STDIN_FILENO : -1;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        /* 第二个描述符是网络 socket，两个事件交给同一次 poll 等待。 */
        descriptors[1].fd = socket_fd;
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;
        /* poll 一次等待键盘或网络；EINTR 表示系统调用被信号打断，可重试。 */
        do {
            result = poll(descriptors, 2U, timeout_ms);
        } while (result < 0 && errno == EINTR);
        if (result < 0) {
            perror("poll");
            return false;
        }
        if (result == 0) continue;

        /* 先处理网络输入：收到 FIN 时不应再发送用户刚输入的普通消息。 */
        if ((descriptors[1].revents & POLLIN) != 0) {
            if (!receive_packet(socket_fd, 0, &source, &packet)) {
                puts("[ERROR] 收到无法解析的报文。");
                return false;
            }
            /* 收到任意有效报文都会证明连接仍有活动，重置空闲计时。 */
            idle_deadline = monotonic_milliseconds() + activity_window_ms;
            /* PSH+ACK 表示有应用数据；纯 ACK 只确认数据，不携带应用内容。 */
            if ((packet.flags & (TCP_PSH | TCP_ACK)) == (TCP_PSH | TCP_ACK)) {
                if (packet.sequence != *receive_next || packet.payload_length == 0U) {
                    puts("[ERROR] 数据段序号不连续或载荷为空。");
                    return false;
                }
                /* TCP Ack 按字节计数：收到 N 字节，下一期待序号就加 N。 */
                *receive_next += (uint32_t)packet.payload_length;
                printf("[CHAT] 收到 %zu 字节；累计确认号=%u。\n",
                       packet.payload_length, *receive_next);
                if (!send_packet(socket_fd, peer, from_client, *send_next,
                                 *receive_next, TCP_ACK, NULL, 0U)) return false;
                idle_deadline = monotonic_milliseconds() + activity_window_ms;
            } else if (packet.flags == (TCP_FIN | TCP_ACK)) {
                return respond_to_close(socket_fd, peer, from_client, &packet,
                                        send_next, receive_next);
            } else if (packet.flags == TCP_ACK) {
                if (packet.acknowledgement > *send_next) {
                    puts("[ERROR] 对端确认号超出已发送数据范围。");
                    return false;
                }
                printf("[CHAT] 收到 ACK，确认号=%u。\n", packet.acknowledgement);
            } else {
                puts("[ERROR] 当前聊天阶段收到不支持的 TCP 标志组合。");
                return false;
            }
        }

        if (stdin_open && (descriptors[0].revents & POLLIN) != 0) {
            char line[502];
            size_t length;
            /* fgets 最多读取数组长度减一字节，并自动在末尾补 '\0'。 */
            if (fgets(line, sizeof(line), stdin) == NULL) {
                stdin_open = false;
                continue;
            }
            /* 先去掉 fgets 保留的行尾，再把余下字节作为一段 TCP 载荷发送。 */
            length = strlen(line);
            if (length > 0U && line[length - 1U] == '\n') {
                line[--length] = '\0';
            } else if (!feof(stdin)) {
                /* 行太长时把剩余字符读到换行，避免下一轮误当成新消息。 */
                int character;
                while ((character = getchar()) != '\n' && character != EOF) {}
                fputs("[CHAT] 消息超过 500 字节，已丢弃。\n", stdout);
                continue;
            }
            if (length > 0U && line[length - 1U] == '\r') line[--length] = '\0';
            if (strcmp(line, ":quit") == 0) {
                return initiate_close(socket_fd, peer, from_client,
                                      send_next, receive_next);
            }
            if (length == 0U) continue;
            if (length > 500U) {
                fputs("[CHAT] 消息超过 500 字节，已丢弃。\n", stdout);
                continue;
            }
            if (!send_packet(socket_fd, peer, from_client, *send_next,
                             *receive_next, TCP_PSH | TCP_ACK,
                             (const uint8_t *)line, length)) return false;
            /* 发送序号按字节前进；strlen 得到的是字节数，不是汉字个数。 */
            *send_next += (uint32_t)length;
            idle_deadline = monotonic_milliseconds() + activity_window_ms;
        } else if (stdin_open &&
                   (descriptors[0].revents & (POLLHUP | POLLERR)) != 0) {
            stdin_open = false;
        }
    }
}

/* 把命令行字符串转为整数，并拒绝空字符串、非数字和超出范围的值。 */
static bool parse_uint(const char *text, unsigned long minimum,
                       unsigned long maximum, unsigned long *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    /* strtoul 转换数字；end 指向第一个未能转换的字符。 */
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum || parsed > maximum) {
        return false;
    }
    *value = parsed;
    return true;
}

/* 创建 IPv4 UDP socket；返回值是后续收发数据使用的文件描述符。 */
static int make_socket(void)
{
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) perror("socket");
    return socket_fd;
}

/* 服务端：绑定本机端口、完成握手、自动回复首次消息，再进入持续聊天。 */
static bool run_receiver(uint16_t port, unsigned int idle_seconds)
{
    struct sockaddr_in local_address;
    struct sockaddr_in peer;
    PacketView packet;
    uint32_t client_next = 0U;
    uint32_t server_next = SERVER_INITIAL_SEQ;
    char request[501];
    char response[700];
    int socket_fd = make_socket();

    if (socket_fd < 0) return false;
    /* sockaddr_in 是 IPv4 地址结构；本示例只监听本机回环地址。 */
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local_address.sin_port = htons(port);
    if (bind(socket_fd, (struct sockaddr *)&local_address, sizeof(local_address)) < 0) {
        perror("bind");
        close(socket_fd);
        return false;
    }
    printf("[RECEIVER] 监听 127.0.0.1:%u；等待发送端（空闲 %u 秒后开始挥手）。\n",
           port, idle_seconds);
    fflush(stdout);

    if (!receive_packet(socket_fd, 60000, &peer, &packet) ||
        packet.flags != TCP_SYN || packet.sequence != CLIENT_INITIAL_SEQ) {
        puts("[ERROR] 等待 SYN 超时或收到的首包不是预期 SYN。");
        close(socket_fd);
        return false;
    }
    /* SYN 会占用一个序号，因此下一个客户端字节序号是当前 Seq+1。 */
    client_next = packet.sequence + 1U;
    puts("[STATE] LISTEN -> SYN-RECEIVED：收到 SYN，回复 SYN+ACK。");
    if (!send_packet(socket_fd, &peer, false, server_next, client_next,
                     TCP_SYN | TCP_ACK, NULL, 0U)) goto failed;
    server_next++; /* 服务端发送的 SYN 也占用一个序号。 */

    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        packet.flags != TCP_ACK || packet.acknowledgement != server_next) {
        puts("[ERROR] 三次握手最后一个 ACK 超时或序号不匹配。");
        goto failed;
    }
    puts("[STATE] ESTABLISHED：三次握手完成。");

    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        (packet.flags & (TCP_PSH | TCP_ACK)) != (TCP_PSH | TCP_ACK) ||
        packet.sequence != client_next || packet.payload_length > 500U) {
        puts("[ERROR] 等待数据段超时或序号不匹配。");
        goto failed;
    }
    /* payload 指向 receive_packet 的静态缓冲区；这里复制后再接收其他报文。 */
    memcpy(request, packet.payload, packet.payload_length);
    request[packet.payload_length] = '\0';
    client_next += (uint32_t)packet.payload_length;
    printf("[STATE] 收到应用数据，累计确认号更新为 %u。\n", client_next);
    if (!send_packet(socket_fd, &peer, false, server_next, client_next,
                     TCP_ACK, NULL, 0U)) goto failed;

    /* %.*s 用指定字节数读取载荷，不要求它本身以 '\0' 结尾。 */
    if (snprintf(response, sizeof(response), "接收方已收到：%.*s",
                 (int)strlen(request), request) < 0) {
        fputs("[ERROR] 生成回复失败。\n", stderr);
        goto failed;
    }
    {
        size_t response_length = strlen(response);
        if (!send_packet(socket_fd, &peer, false, server_next, client_next,
                         TCP_PSH | TCP_ACK, (const uint8_t *)response,
                         response_length)) goto failed;
        server_next += (uint32_t)response_length;
    }
    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        packet.flags != TCP_ACK || packet.acknowledgement != server_next) {
        puts("[ERROR] 回复数据的 ACK 超时或序号不匹配。");
        goto failed;
    }
    if (!run_chat(socket_fd, &peer, false, idle_seconds,
                  &server_next, &client_next)) goto failed;
    close(socket_fd);
    return true;

failed:
    /* 所有中途失败的路径共用清理逻辑，关闭 socket 并释放文件描述符。 */
    close(socket_fd);
    return false;
}

/* 客户端：发 SYN、完成握手、发送首次消息并等待服务端自动回复。 */
static bool run_sender(const char *host, uint16_t port,
                       unsigned int idle_seconds, const char *message)
{
    struct sockaddr_in peer;
    PacketView packet;
    uint32_t client_next = CLIENT_INITIAL_SEQ;
    uint32_t server_next = 0U;
    size_t message_length = strlen(message);
    int socket_fd;

    /* strlen 返回字节数；UTF-8 中文通常每个字符占多个字节。 */
    if (message_length == 0U || message_length > 500U) {
        fputs("消息长度必须为 1 到 500 字节。\n", stderr);
        return false;
    }
    socket_fd = make_socket();
    if (socket_fd < 0) return false;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    /* inet_pton 把点分十进制地址转为 socket 使用的二进制 IPv4 地址。 */
    if (inet_pton(AF_INET, host, &peer.sin_addr) != 1) {
        fputs("接收端地址必须是 IPv4 回环地址 127.0.0.1。\n", stderr);
        close(socket_fd);
        return false;
    }
    if (ntohl(peer.sin_addr.s_addr) != INADDR_LOOPBACK) {
        fputs("本示例只允许连接本机 127.0.0.1。\n", stderr);
        close(socket_fd);
        return false;
    }
    printf("[SENDER] 向 %s:%u 发起连接；接收端空闲超时设为 %u 秒。\n",
           host, port, idle_seconds);
    fflush(stdout);

    puts("[STATE] CLOSED -> SYN-SENT：发送 SYN。");
    if (!send_packet(socket_fd, &peer, true, client_next, 0U,
                     TCP_SYN, NULL, 0U)) goto failed;
    client_next++; /* SYN 占用一个序号，所以首段应用数据从 1001 开始。 */
    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        packet.flags != (TCP_SYN | TCP_ACK) ||
        packet.acknowledgement != client_next) {
        puts("[ERROR] SYN+ACK 超时或序号不匹配；确认接收端已先启动。");
        goto failed;
    }
    server_next = packet.sequence + 1U; /* SYN+ACK 中服务端 SYN 占一个序号。 */
    if (!send_packet(socket_fd, &peer, true, client_next, server_next,
                     TCP_ACK, NULL, 0U)) goto failed;
    puts("[STATE] ESTABLISHED：三次握手完成。");

    if (!send_packet(socket_fd, &peer, true, client_next, server_next,
                     TCP_PSH | TCP_ACK, (const uint8_t *)message,
                     message_length)) goto failed;
    client_next += (uint32_t)message_length; /* TCP 确认号按字节数递增。 */
    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        packet.flags != TCP_ACK || packet.acknowledgement != client_next) {
        puts("[ERROR] 发送数据后没有收到正确 ACK。");
        goto failed;
    }
    puts("[STATE] 发送的数据已被累计确认；等待接收端回复。");
    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        (packet.flags & (TCP_PSH | TCP_ACK)) != (TCP_PSH | TCP_ACK) ||
        packet.sequence != server_next) {
        puts("[ERROR] 接收端回复超时或序号不匹配。");
        goto failed;
    }
    server_next += (uint32_t)packet.payload_length;
    if (!send_packet(socket_fd, &peer, true, client_next, server_next,
                     TCP_ACK, NULL, 0U)) goto failed;
    if (!run_chat(socket_fd, &peer, true, idle_seconds,
                  &client_next, &server_next)) goto failed;
    close(socket_fd);
    return true;

failed:
    /* 统一关闭 socket；close 后系统可以回收这个文件描述符。 */
    close(socket_fd);
    return false;
}

/* 显示命令用法；program 通常是用户启动程序时输入的文件名或路径。 */
static void print_usage(const char *program)
{
    printf("用法：\n"
           "  %s receive [端口=9000] [空闲秒数=30]\n"
           "  %s send [接收端IPv4=127.0.0.1] [端口=9000] [空闲秒数=30] [消息]\n",
           program, program);
}

/* C 程序入口：argc 是参数个数，argv 是每个参数对应的字符串数组。 */
int main(int argc, char **argv)
{
    unsigned long port = 9000UL;
    unsigned long idle_seconds = 30UL;
    bool success;

    /* argv[0] 是程序名；argv[1] 应为 receive 或 send 子命令。 */
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return argc < 2 ? 2 : 0;
    }
    /* 先按角色分支，再读取端口和超时等可选参数。 */
    if (strcmp(argv[1], "receive") == 0) {
        if (argc > 4 || (argc >= 3 && !parse_uint(argv[2], 1024UL, 65535UL, &port)) ||
            (argc >= 4 && !parse_uint(argv[3], 1UL, 120UL, &idle_seconds))) {
            print_usage(argv[0]);
            return 2;
        }
        success = run_receiver((uint16_t)port, (unsigned int)idle_seconds);
    } else if (strcmp(argv[1], "send") == 0) {
        const char *host = argc >= 3 ? argv[2] : "127.0.0.1";
        const char *message = argc >= 6 ? argv[5] : "你好，接收方！";
        if (argc > 6 || (argc >= 4 && !parse_uint(argv[3], 1024UL, 65535UL, &port)) ||
            (argc >= 5 && !parse_uint(argv[4], 1UL, 120UL, &idle_seconds))) {
            print_usage(argv[0]);
            return 2;
        }
        success = run_sender(host, (uint16_t)port,
                             (unsigned int)idle_seconds, message);
    } else {
        print_usage(argv[0]);
        return 2;
    }
    return success ? 0 : 1;
}

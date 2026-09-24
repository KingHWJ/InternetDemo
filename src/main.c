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

#define ETHERNET_HEADER_SIZE 14U
#define IPV4_HEADER_SIZE 20U
#define TCP_HEADER_SIZE 20U
#define PACKET_CAPACITY 1400U
#define CLIENT_PORT 50000U
#define SERVER_PORT 8080U
#define CLIENT_INITIAL_SEQ 1000U
#define SERVER_INITIAL_SEQ 7000U
#define TCP_SYN 0x02U
#define TCP_ACK 0x10U
#define TCP_PSH 0x08U
#define TCP_FIN 0x01U

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t flags;
    const uint8_t *payload;
    size_t payload_length;
} PacketView;

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

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

static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t internet_checksum(const uint8_t *bytes, size_t length)
{
    return checksum_finish(checksum_add(0U, bytes, length));
}

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

static void print_mac(const uint8_t *bytes)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2],
           bytes[3], bytes[4], bytes[5]);
}

static void print_ipv4(const uint8_t *bytes)
{
    printf("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

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

static bool build_packet(uint8_t *packet, size_t capacity, bool from_client,
                         uint16_t source_port, uint16_t destination_port,
                         uint32_t sequence, uint32_t acknowledgement,
                         uint8_t flags, const uint8_t *payload,
                         size_t payload_length, size_t *packet_length)
{
    static const uint8_t client_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t server_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    const size_t tcp_length = TCP_HEADER_SIZE + payload_length;
    const size_t ip_length = IPV4_HEADER_SIZE + tcp_length;
    const size_t frame_length = ETHERNET_HEADER_SIZE + ip_length;
    uint8_t *ip;
    uint8_t *tcp;

    if (frame_length > capacity || ip_length > UINT16_MAX || tcp_length > UINT16_MAX) {
        return false;
    }
    memcpy(packet, from_client ? server_mac : client_mac, 6U);
    memcpy(packet + 6U, from_client ? client_mac : server_mac, 6U);
    write_be16(packet + 12U, 0x0800U);

    ip = packet + ETHERNET_HEADER_SIZE;
    memset(ip, 0, ip_length);
    ip[0] = 0x45U;
    write_be16(ip + 2U, (uint16_t)ip_length);
    write_be16(ip + 4U, 0x1234U);
    write_be16(ip + 6U, 0x4000U);
    ip[8] = 64U;
    ip[9] = 6U;
    if (from_client) {
        ip[12] = 10U; ip[13] = 0U; ip[14] = 0U; ip[15] = 1U;
        ip[16] = 10U; ip[17] = 0U; ip[18] = 0U; ip[19] = 2U;
    } else {
        ip[12] = 10U; ip[13] = 0U; ip[14] = 0U; ip[15] = 2U;
        ip[16] = 10U; ip[17] = 0U; ip[18] = 0U; ip[19] = 1U;
    }
    write_be16(ip + 10U, internet_checksum(ip, IPV4_HEADER_SIZE));

    tcp = ip + IPV4_HEADER_SIZE;
    write_be16(tcp, source_port);
    write_be16(tcp + 2U, destination_port);
    write_be32(tcp + 4U, sequence);
    write_be32(tcp + 8U, acknowledgement);
    tcp[12] = 0x50U;
    tcp[13] = flags;
    write_be16(tcp + 14U, 4096U);
    if (payload_length > 0U) memcpy(tcp + TCP_HEADER_SIZE, payload, payload_length);
    write_be16(tcp + 16U, tcp_checksum(ip, tcp, tcp_length));
    *packet_length = frame_length;
    return true;
}

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

    if (strncmp(direction, "TX", 2U) == 0) {
        printf("\n[%s] 构造 Ethernet 帧，共 %zu 字节，逐层检查封装结果。\n",
               direction, packet_length);
    } else {
        printf("\n[%s] 收到 Ethernet 帧，共 %zu 字节，开始逐层解包。\n",
               direction, packet_length);
    }
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

    ip = packet + ETHERNET_HEADER_SIZE;
    if ((ip[0] >> 4) != 4U) {
        puts("[ERROR] IP 版本不是 IPv4。");
        return false;
    }
    ip_header_length = (size_t)(ip[0] & 0x0fU) * 4U;
    ip_total_length = read_be16(ip + 2U);
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
    fragment_field = read_be16(ip + 6U);
    if ((fragment_field & 0x3fffU) != 0U || ip[9] != 6U) {
        puts("[ERROR] 示例只解析未分片的 TCP/IPv4 报文。");
        return false;
    }

    tcp = ip + ip_header_length;
    tcp_length = ip_total_length - ip_header_length;
    if (tcp_length < TCP_HEADER_SIZE) {
        puts("[ERROR] TCP 头部不完整。");
        return false;
    }
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

static bool send_packet(int socket_fd, const struct sockaddr_in *peer,
                        bool from_client, uint32_t sequence,
                        uint32_t acknowledgement, uint8_t flags,
                        const uint8_t *payload, size_t payload_length)
{
    uint8_t packet[PACKET_CAPACITY];
    size_t packet_length;
    PacketView view;
    uint16_t source_port = from_client ? CLIENT_PORT : SERVER_PORT;
    uint16_t destination_port = from_client ? SERVER_PORT : CLIENT_PORT;

    if (!build_packet(packet, sizeof(packet), from_client, source_port,
                      destination_port, sequence, acknowledgement, flags,
                      payload, payload_length, &packet_length)) {
        fputs("[ERROR] 无法构造报文：载荷超过缓冲区。\n", stderr);
        return false;
    }
    if (!inspect_packet("TX 封装", packet, packet_length, &view)) return false;
    if (sendto(socket_fd, packet, packet_length, 0,
               (const struct sockaddr *)peer, sizeof(*peer)) != (ssize_t)packet_length) {
        perror("sendto");
        return false;
    }
    return true;
}

static bool receive_packet(int socket_fd, int timeout_ms,
                           struct sockaddr_in *peer, PacketView *view)
{
    struct pollfd descriptor;
    static uint8_t packet[PACKET_CAPACITY];
    socklen_t peer_length = sizeof(*peer);
    ssize_t received;
    int result;

    descriptor.fd = socket_fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    do {
        result = poll(&descriptor, 1U, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result == 0) return false;
    if (result < 0) {
        perror("poll");
        return false;
    }
    received = recvfrom(socket_fd, packet, sizeof(packet), 0,
                        (struct sockaddr *)peer, &peer_length);
    if (received < 0) {
        perror("recvfrom");
        return false;
    }
    return inspect_packet("RX 解包", packet, (size_t)received, view);
}

static int64_t monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool initiate_close(int socket_fd, const struct sockaddr_in *peer,
                           bool from_client, uint32_t *send_next,
                           uint32_t *receive_next)
{
    PacketView packet;
    struct sockaddr_in source = *peer;

    puts("[TIMEOUT/QUIT] 发起方发送 FIN（第 1 次挥手）。");
    if (!send_packet(socket_fd, peer, from_client, *send_next, *receive_next,
                     TCP_FIN | TCP_ACK, NULL, 0U)) return false;
    (*send_next)++;
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
    (*receive_next)++;
    puts("[STATE] 收到第 3 次挥手 FIN，回复最终 ACK。");
    if (!send_packet(socket_fd, peer, from_client, *send_next,
                     *receive_next, TCP_ACK, NULL, 0U)) return false;
    puts("[STATE] CLOSED：四次挥手完成。");
    return true;
}

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

static bool run_chat(int socket_fd, const struct sockaddr_in *peer,
                     bool from_client, unsigned int idle_seconds,
                     uint32_t *send_next, uint32_t *receive_next)
{
    struct sockaddr_in source = *peer;
    PacketView packet;
    struct pollfd descriptors[2];
    bool stdin_open = true;
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
        descriptors[0].fd = stdin_open ? STDIN_FILENO : -1;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = socket_fd;
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;
        do {
            result = poll(descriptors, 2U, timeout_ms);
        } while (result < 0 && errno == EINTR);
        if (result < 0) {
            perror("poll");
            return false;
        }
        if (result == 0) continue;

        if ((descriptors[1].revents & POLLIN) != 0) {
            if (!receive_packet(socket_fd, 0, &source, &packet)) {
                puts("[ERROR] 收到无法解析的报文。");
                return false;
            }
            idle_deadline = monotonic_milliseconds() + activity_window_ms;
            if ((packet.flags & (TCP_PSH | TCP_ACK)) == (TCP_PSH | TCP_ACK)) {
                if (packet.sequence != *receive_next || packet.payload_length == 0U) {
                    puts("[ERROR] 数据段序号不连续或载荷为空。");
                    return false;
                }
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
            if (fgets(line, sizeof(line), stdin) == NULL) {
                stdin_open = false;
                continue;
            }
            length = strlen(line);
            if (length > 0U && line[length - 1U] == '\n') {
                line[--length] = '\0';
            } else if (!feof(stdin)) {
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
            *send_next += (uint32_t)length;
            idle_deadline = monotonic_milliseconds() + activity_window_ms;
        } else if (stdin_open &&
                   (descriptors[0].revents & (POLLHUP | POLLERR)) != 0) {
            stdin_open = false;
        }
    }
}

static bool parse_uint(const char *text, unsigned long minimum,
                       unsigned long maximum, unsigned long *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum || parsed > maximum) {
        return false;
    }
    *value = parsed;
    return true;
}

static int make_socket(void)
{
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) perror("socket");
    return socket_fd;
}

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
    client_next = packet.sequence + 1U;
    puts("[STATE] LISTEN -> SYN-RECEIVED：收到 SYN，回复 SYN+ACK。");
    if (!send_packet(socket_fd, &peer, false, server_next, client_next,
                     TCP_SYN | TCP_ACK, NULL, 0U)) goto failed;
    server_next++;

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
    memcpy(request, packet.payload, packet.payload_length);
    request[packet.payload_length] = '\0';
    client_next += (uint32_t)packet.payload_length;
    printf("[STATE] 收到应用数据，累计确认号更新为 %u。\n", client_next);
    if (!send_packet(socket_fd, &peer, false, server_next, client_next,
                     TCP_ACK, NULL, 0U)) goto failed;

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
    close(socket_fd);
    return false;
}

static bool run_sender(const char *host, uint16_t port,
                       unsigned int idle_seconds, const char *message)
{
    struct sockaddr_in peer;
    PacketView packet;
    uint32_t client_next = CLIENT_INITIAL_SEQ;
    uint32_t server_next = 0U;
    size_t message_length = strlen(message);
    int socket_fd;

    if (message_length == 0U || message_length > 500U) {
        fputs("消息长度必须为 1 到 500 字节。\n", stderr);
        return false;
    }
    socket_fd = make_socket();
    if (socket_fd < 0) return false;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
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
    client_next++;
    if (!receive_packet(socket_fd, 5000, &peer, &packet) ||
        packet.flags != (TCP_SYN | TCP_ACK) ||
        packet.acknowledgement != client_next) {
        puts("[ERROR] SYN+ACK 超时或序号不匹配；确认接收端已先启动。");
        goto failed;
    }
    server_next = packet.sequence + 1U;
    if (!send_packet(socket_fd, &peer, true, client_next, server_next,
                     TCP_ACK, NULL, 0U)) goto failed;
    puts("[STATE] ESTABLISHED：三次握手完成。");

    if (!send_packet(socket_fd, &peer, true, client_next, server_next,
                     TCP_PSH | TCP_ACK, (const uint8_t *)message,
                     message_length)) goto failed;
    client_next += (uint32_t)message_length;
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
    close(socket_fd);
    return false;
}

static void print_usage(const char *program)
{
    printf("用法：\n"
           "  %s receive [端口=9000] [空闲秒数=30]\n"
           "  %s send [接收端IPv4=127.0.0.1] [端口=9000] [空闲秒数=30] [消息]\n",
           program, program);
}

int main(int argc, char **argv)
{
    unsigned long port = 9000UL;
    unsigned long idle_seconds = 30UL;
    bool success;

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return argc < 2 ? 2 : 0;
    }
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ETHERNET_HEADER_SIZE 14U
#define IPV4_MIN_HEADER_SIZE 20U
#define TCP_MIN_HEADER_SIZE 20U
#define PACKET_CAPACITY 1500U

static const uint8_t http_request[] =
    "GET / HTTP/1.1\r\n"
    "Host: example.local\r\n"
    "Connection: close\r\n"
    "\r\n";

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
    size_t index = 0;
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

static uint16_t tcp_checksum(const uint8_t *ip_header,
                             const uint8_t *tcp_segment,
                             size_t tcp_length)
{
    uint32_t sum = 0U;
    sum = checksum_add(sum, ip_header + 12U, 8U); /* IPv4 源、目的地址 */
    sum += 6U;                                    /* TCP 协议号 */
    sum += (uint16_t)tcp_length;                  /* TCP 长度 */
    sum = checksum_add(sum, tcp_segment, tcp_length);
    return checksum_finish(sum);
}

static void set_ipv4(uint8_t *bytes, unsigned int a, unsigned int b,
                     unsigned int c, unsigned int d)
{
    bytes[0] = (uint8_t)a;
    bytes[1] = (uint8_t)b;
    bytes[2] = (uint8_t)c;
    bytes[3] = (uint8_t)d;
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

static void print_payload(const uint8_t *bytes, size_t length)
{
    size_t index;
    for (index = 0; index < length; ++index) {
        if (bytes[index] == '\r') {
            fputs("\\r", stdout);
        } else if (bytes[index] == '\n') {
            fputs("\\n\n", stdout);
        } else if (bytes[index] >= 32U && bytes[index] <= 126U) {
            putchar((int)bytes[index]);
        } else {
            printf("\\x%02x", bytes[index]);
        }
    }
    if (length == 0U || bytes[length - 1U] != '\n') {
        putchar('\n');
    }
}

static bool build_packet(uint8_t *packet, size_t capacity, size_t *packet_length)
{
    const size_t payload_length = sizeof(http_request) - 1U;
    const size_t tcp_length = TCP_MIN_HEADER_SIZE + payload_length;
    const size_t ip_length = IPV4_MIN_HEADER_SIZE + tcp_length;
    const size_t total_length = ETHERNET_HEADER_SIZE + ip_length;
    uint8_t *ip;
    uint8_t *tcp;

    if (capacity < total_length) {
        return false;
    }

    /* Ethernet II：目的 MAC、源 MAC、IPv4 类型。 */
    {
        static const uint8_t destination_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
        static const uint8_t source_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        memcpy(packet, destination_mac, sizeof(destination_mac));
        memcpy(packet + 6U, source_mac, sizeof(source_mac));
        write_be16(packet + 12U, 0x0800U);
    }

    ip = packet + ETHERNET_HEADER_SIZE;
    memset(ip, 0, ip_length);
    ip[0] = 0x45U; /* IPv4，IHL=5，即 20 字节且无选项。 */
    ip[1] = 0U;    /* DSCP/ECN */
    write_be16(ip + 2U, (uint16_t)ip_length);
    write_be16(ip + 4U, 0x1234U);
    write_be16(ip + 6U, 0x4000U); /* DF：禁止分片。 */
    ip[8] = 64U;
    ip[9] = 6U; /* TCP */
    set_ipv4(ip + 12U, 192U, 0U, 2U, 10U);
    set_ipv4(ip + 16U, 198U, 51U, 100U, 20U);
    write_be16(ip + 10U, internet_checksum(ip, IPV4_MIN_HEADER_SIZE));

    tcp = ip + IPV4_MIN_HEADER_SIZE;
    write_be16(tcp, 51514U);
    write_be16(tcp + 2U, 80U);
    write_be32(tcp + 4U, 1001U);
    write_be32(tcp + 8U, 7001U);
    tcp[12] = 0x50U; /* 数据偏移 5，即 20 字节且无选项。 */
    tcp[13] = 0x18U; /* PSH + ACK */
    write_be16(tcp + 14U, 64240U);
    memcpy(tcp + TCP_MIN_HEADER_SIZE, http_request, payload_length);
    write_be16(tcp + 16U, tcp_checksum(ip, tcp, tcp_length));

    *packet_length = total_length;
    return true;
}

static bool parse_packet(const uint8_t *packet, size_t packet_length)
{
    const uint8_t *ip;
    const uint8_t *tcp;
    size_t ip_header_length;
    size_t ip_total_length;
    size_t tcp_header_length;
    size_t tcp_length;
    size_t payload_length;
    uint16_t ether_type;
    uint16_t fragment_field;
    uint8_t tcp_flags;

    puts("[RX] 模拟网卡收到一帧；开始从链路层向上解析。");
    if (packet_length < ETHERNET_HEADER_SIZE) {
        puts("[ERROR] 数据不足以包含 Ethernet II 头部。");
        return false;
    }

    ether_type = read_be16(packet + 12U);
    printf("[L2 Ethernet] 帧长=%zu 字节\n", packet_length);
    printf("  目的 MAC: "); print_mac(packet); putchar('\n');
    printf("  源 MAC:   "); print_mac(packet + 6U); putchar('\n');
    printf("  EtherType: 0x%04x", ether_type);
    if (ether_type != 0x0800U) {
        puts(" (不是 IPv4，停止解析)");
        return false;
    }
    puts(" (IPv4，交给网络层)");

    if (packet_length < ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE) {
        puts("[ERROR] 数据不足以包含最小 IPv4 头部。");
        return false;
    }
    ip = packet + ETHERNET_HEADER_SIZE;
    if ((ip[0] >> 4) != 4U) {
        puts("[ERROR] IP 版本不是 IPv4。");
        return false;
    }
    ip_header_length = (size_t)(ip[0] & 0x0fU) * 4U;
    ip_total_length = read_be16(ip + 2U);
    if (ip_header_length < IPV4_MIN_HEADER_SIZE ||
        packet_length < ETHERNET_HEADER_SIZE + ip_header_length ||
        ip_total_length < ip_header_length ||
        ip_total_length > packet_length - ETHERNET_HEADER_SIZE) {
        puts("[ERROR] IPv4 头长或总长度字段越界/不合法。");
        return false;
    }

    printf("[L3 IPv4] 版本=%u 头长=%zu 字节 总长=%zu 字节 TTL=%u 协议号=%u\n",
           ip[0] >> 4, ip_header_length, ip_total_length, ip[8], ip[9]);
    printf("  源 IP: "); print_ipv4(ip + 12U);
    printf("  -> 目的 IP: "); print_ipv4(ip + 16U); putchar('\n');
    printf("  标识=0x%04x 分片字段=0x%04x 头部校验和=%s\n",
           read_be16(ip + 4U), read_be16(ip + 6U),
           internet_checksum(ip, ip_header_length) == 0U ? "正确" : "错误");
    fragment_field = read_be16(ip + 6U);
    if ((fragment_field & 0x3fffU) != 0U) {
        puts("[ERROR] 示例解析器不处理分片报文。");
        return false;
    }
    if (ip[9] != 6U) {
        printf("[ERROR] IPv4 上层协议号为 %u，本示例只处理 TCP(6)。\n", ip[9]);
        return false;
    }
    tcp = ip + ip_header_length;
    tcp_length = ip_total_length - ip_header_length;
    if (tcp_length < TCP_MIN_HEADER_SIZE) {
        puts("[ERROR] IPv4 载荷不足以包含最小 TCP 头部。");
        return false;
    }
    tcp_header_length = (size_t)(tcp[12] >> 4) * 4U;
    if (tcp_header_length < TCP_MIN_HEADER_SIZE || tcp_header_length > tcp_length) {
        puts("[ERROR] TCP 数据偏移字段不合法。");
        return false;
    }
    payload_length = tcp_length - tcp_header_length;
    tcp_flags = tcp[13];

    printf("[L4 TCP] 源端口=%u -> 目的端口=%u\n",
           read_be16(tcp), read_be16(tcp + 2U));
    printf("  Seq=%u Ack=%u 头长=%zu 字节 窗口=%u\n",
           read_be32(tcp + 4U), read_be32(tcp + 8U), tcp_header_length,
           read_be16(tcp + 14U));
    printf("  标志:");
    if ((tcp_flags & 0x02U) != 0U) fputs(" SYN", stdout);
    if ((tcp_flags & 0x10U) != 0U) fputs(" ACK", stdout);
    if ((tcp_flags & 0x08U) != 0U) fputs(" PSH", stdout);
    if ((tcp_flags & 0x01U) != 0U) fputs(" FIN", stdout);
    if ((tcp_flags & 0x04U) != 0U) fputs(" RST", stdout);
    printf(" 校验和=%s\n",
           tcp_checksum(ip, tcp, tcp_length) == 0U ? "正确" : "错误");

    printf("[APP] TCP 载荷=%zu 字节；按 HTTP 文本查看：\n", payload_length);
    print_payload(tcp + tcp_header_length, payload_length);
    puts("[DONE] 解析完成。此处是用户态模拟，不会发送到真实网络。");
    return true;
}

int main(void)
{
    uint8_t packet[PACKET_CAPACITY];
    size_t packet_length = 0U;

    puts("=== 本机 TCP/IP 报文处理演示 ===");
    if (!build_packet(packet, sizeof(packet), &packet_length)) {
        fputs("[ERROR] 报文缓冲区不足，无法构造示例报文。\n", stderr);
        return 1;
    }
    printf("[TX] 构造完成：Ethernet + IPv4 + TCP + HTTP，共 %zu 字节。\n",
           packet_length);
    if (!parse_packet(packet, packet_length)) {
        return 1;
    }
    return 0;
}

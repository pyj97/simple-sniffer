#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
typedef struct{
    u_char destination_mac[6];       // 目的 MAC
    u_char source_mac[6];            // 源 MAC
    u_char type[2];                  // 上层协议类型
}ETHERNET_HEADER;                    // 以太网头部, 14 Bytes

typedef struct{
    u_int version_and_header_length: 8;            // IPv4 or IPv6 和 头部长度, 真实长度 = header_len * 4
    u_int tos: 8;                   // 服务类型
    u_int total_length: 16;            // 包括 IP 报头 的 IP 报文总长度(Byte)
    u_int identifier: 16;              // 并不知道有啥用
    u_int flags: 16;                   // 并不知道有啥用
    u_int ttl: 8;                   // 生存时间
    u_int proto: 8;                 // 上层协议
    u_int checksum: 16;                // IP 头部校验信息
    u_char source_ip[4];             // 源 IP
    u_char destination_ip[4];        // 目的 IP
}IP_HEADER;                          // IP 头部, 20 Bytes

typedef struct{
    int hardware_type: 16;           // 硬件类型
    int protocol_type: 16;           // 协议类型
    int hardware_length: 8;          // 硬件地址长度
    int protocol_length: 8;          // 协议地址长度
    int opercation_code: 16;         // op
    u_char sender_mac[6];            // 发送端 MAC
    u_char sender_ip[4];             // 发送端 IP
    u_char destination_mac[6];       // 目的 MAC
    u_char destination_ip[4];        // 目的 IP
}ARP_HEADER;                         // ARP 头部, 18 Bytes

typedef struct{
    u_char type: 8;                  // 类型
    u_char code: 8;                  // 代码
    u_int checksum: 16;              // 校验和
}ICMP_HEADER;                        // ICMP 头部, 3 Bytes

typedef struct{
    uint16_t source_port: 16;        // 源端口号
    uint16_t destination_port: 16;   // 目的端口号
    u_int sequence_number: 32;       // 序列号
    u_int acknowledge_number: 32;    // 确认序号
    u_int header_length_and_flag: 16;          // 头部长度, 真实长度 = header_length * 4 和 标志位
    u_int windows_size: 16;          // 窗口大小
    u_int checksum: 16;              // 校验和, 不仅对头部校验, 而且对内容校验
    u_int urgent_pointer: 16;        // 紧急指针
}TCP_HEADER;                         // TCP 头部, 20 Bytes

typedef struct{
    uint16_t source_port: 16;        // 源端口号
    uint16_t destination_port: 16;   // 目的端口号
    unsigned short int length: 16;   // 封包长度
    unsigned short int checksum: 16; // 校验和
}UDP_HEADER;                         // UDP 头部, 8 Bytes

void get_packet(u_char * userarg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
void hex_to_ascii(const u_char * packet, int length, char * ascii_char);
int if_is_displayable(char c);
void print_two_data(const u_char * packet, char * ascii_char, int length);
void print_ethernet(ETHERNET_HEADER * ethernet_header);
void print_ipv4(IP_HEADER * ip_header);
void print_arp(ARP_HEADER * arp_header);
void print_icmp(ICMP_HEADER * icmp_header);
void print_tcp(TCP_HEADER * tcp_header);
void print_udp(UDP_HEADER * udp_header);
void input_str(char * str, int length);
void filter(pcap_t *device, bpf_u_int32 maskp);

int main(){
    char *device_name;             // 设备名称
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息

    device_name = pcap_lookupdev(errbuf);          // 获取设备名称
    if(device_name == NULL){                       // 设备查找不到
        printf("find device error: %s\n", errbuf); // 提示错误
        return 1;                                  // 退出
    }
    else{                                          // 找到设备
        printf("找到设备 -> %s\n", device_name);    // 输出设备名称
    }

    pcap_t *device = pcap_open_live(device_name, 65535, 0, 0, errbuf);    // 打开设备
    if(device == NULL){                                                   // 不能打开设备
        printf("can't open the device -> %s: %s\n", device_name, errbuf); // 错误信息提示
        return 1;                                                         // 退出
    }
    else{                                                                 // 成功打开设备
        printf("成功打开设备 -> %s\n", device_name);                        // 提示成功打开
    }

    bpf_u_int32 netp;                                                                  // 网络号
    bpf_u_int32 maskp;                                                                 // 掩码
    if(pcap_lookupnet(device_name, &netp, &maskp, errbuf) == -1){                      // 获取网络号和掩码失败
        printf("pcap_lookupnet error: %s\n", errbuf);                                  // 提示错误信息
        return 1;                                                                      // 退出
    }
    else{                                                                              // 获取网络号和掩码成功
        char network_number[INET_ADDRSTRLEN], net_mask[INET_ADDRSTRLEN];               // 网络号, 掩码
        if(inet_ntop(AF_INET, &netp, network_number, sizeof(network_number)) == NULL){ // 将网络号从二进制整数转换为点分十进制失败
            perror("inet_ntop netp error");                                            // 错误提示
            return 1;
        }
        else if(inet_ntop(AF_INET, &maskp, net_mask, sizeof(net_mask)) == NULL){       // 将掩码从二进制整数转换为点分十进制失败
            perror("inet_ntop maskp error");                                           // 错误提示
        }
        printf("网络号: %s, 子网掩码: %s\n", network_number, net_mask);                  // 输出网络号和掩码
    }

    if(pcap_datalink(device) != 1){ // 检查是否是以太网的数据包
        printf("本程序不支持解析非以太网协议的数据包!\n");
        return 1;
    }

    filter(device, maskp); // 过滤器

    int id = 0; // 数据包序号
    pcap_loop(device, -1, get_packet, (u_char*)&id);

    return 0;
}

void get_packet(u_char * userarg, const struct pcap_pkthdr * pkthdr, const u_char * packet){
    printf("=====================================================================\n");
    printf("序号: %d ", ++(*userarg));                                                                                   // 打印数据包序号 
    printf("长度: %d ", pkthdr->len);                                                                                    // 打印数据包长度
    printf("大小: %d Bytes ", pkthdr->caplen);                                                                           // 打印数据包大小
    printf("收到时间: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));                                                    // 打印数据包收到时间

    if(pkthdr->len >= 14){
        ETHERNET_HEADER * ethernet_header = (ETHERNET_HEADER *)packet;
        print_ethernet(ethernet_header);                                                                               // 打印以太网头部信息
        if((pkthdr->len >= 14 + 20) && (ethernet_header->type[0] == 0x08) && (ethernet_header->type[1] == 0x00)){      // IPv4
            IP_HEADER * ip_header = (IP_HEADER *)(packet + 14);
            print_ipv4(ip_header);                                                                                     // 打印 IPv4 头部信息
            if((pkthdr->len >= 14 + 20 + 3) && (ip_header->proto == 0x01)){
                ICMP_HEADER * icmp_header = (ICMP_HEADER *)(packet + 14 + 20);
                print_icmp(icmp_header);                                                                               // 打印 ICMP 头部信息
            }
            else if((pkthdr->len >= 14 + 20 + 20) && (ip_header->proto == 0x06)){
                TCP_HEADER * tcp_header = (TCP_HEADER *)(packet + 14 + 20);
                print_tcp(tcp_header);                                                                                 // 打印 TCP 头部信息
            }
            else if((pkthdr->len >= 14 + 20 + 8) && (ip_header->proto == 0x11)){
                UDP_HEADER * udp_header = (UDP_HEADER *)(packet + 14 + 20);
                print_udp(udp_header);                                                                                 // 打印 UDP 头部信息
            }
            else{
                printf("不支持解析的协议\n");
            }
        }
        else if((pkthdr->len >= 14 + 18) && (ethernet_header->type[0] == 0x08) && (ethernet_header->type[1] == 0x06)){ // ARP
            ARP_HEADER * arp_header = (ARP_HEADER *)(packet + 14);
            print_arp(arp_header);                                                                                     // 打印 ARP 头部信息
        }
        else{
            printf("不支持解析的协议\n");
        }
    }

    char ascii_char[pkthdr->len];                    // 存储转换成可显示的数据
    hex_to_ascii(packet, pkthdr->len, ascii_char);   // 转换包内容为可显示的
    print_two_data(packet, ascii_char, pkthdr->len); // 打印未处理数据和处理后可显示的数据
}

void hex_to_ascii(const u_char * packet, int length, char * ascii_char){
    // 将输入的十六进制数组转化成能显示的字符
    for(int i = 0; i < length; ++i){
        if(isprint(packet[i]) == 0){   // 如果不可以显示
            ascii_char[i] = '.';       // 赋值为'.'
        }
        else{                          // 如果可以显示
            ascii_char[i] = packet[i]; // 赋予原值
        }
    }
}

void print_two_data(const u_char * packet, char * ascii_char, int length){
    int i = 0;                                       // 未处理数据的索引
    int j = 0;                                       // 处理后数据的索引
    int num = 0;                                     // 每行显示时的索引
    int r_top;                                       // 行数
    if(length % 16 == 0){
        r_top = length / 16;
    }
    else{
        r_top = length / 16 + 1;
    }
    for(int r = 0; r < r_top; ++r){                  // 一行一行打印
        printf(" %04x  ", i);                        // 打印行首索引值
        while(num < 16 && i < length){               // 先打印未处理数据
            printf(" %02x", packet[i]);              // 打印十六进制的形式
            i++;
            num++;
        }
        num = 0;
        if(r == length / 16){                        // 打印最后一行时, 由于可能不足 16 个, 控制显示效果
            int space = ((r + 1) * 16 - length) * 3; // 计算空格个数
            for(int i = 0; i < space; ++i){
                printf(" ");
            }
        }
        printf("   ");
        while(num < 16 && j < length){               // 后打印处理后数据
            printf("%c", ascii_char[j]);             // 打印 ASCII 形式
            j++;
            num++;
        }
        num = 0;
        printf("\n");
    }
    printf("\n");
}

void print_ethernet(ETHERNET_HEADER * ethernet_header){
    printf("|--Ethernet:\n");
    printf("|  +Destination: ");
    for(int i = 0; i < 6; ++i){
        printf("%02X", ethernet_header->destination_mac[i]);
        if(i != 5){
            printf("-");
        }
        else{
            printf("\n");
        }
    }
    printf("|  +Source: ");
    for(int i = 0; i < 6; ++i){
        printf("%02X", ethernet_header->source_mac[i]);
        if(i != 5){
            printf("-");
        }
        else{
            printf("\n");
        }
    }
    printf("|  +Type: ");
    int temp_type = (int)(ethernet_header->type[0]) * 256 + (int)(ethernet_header->type[1]);
    switch(temp_type){
        case 0x0800:
            printf("IPv4 (0x%04x)\n", temp_type);
            break;
        case 0x86dd:
            printf("IPv5 (0x%04x)\n", temp_type);
            break;
        case 0x0806:
            printf("ARP (0x%04x)\n", temp_type);
            break;
        default:
            printf("unknown (0x%04x)\n", temp_type);
    }
}

void print_ipv4(IP_HEADER * ip_header){
    printf("|---|--Internet Protocol Version 4:\n");
    unsigned short temp_version_and_header_length = ip_header->version_and_header_length;
    printf("    |  +Version: %d\n", (temp_version_and_header_length & 0xF0) >> 4); // 版本信息
    printf("    |  +Header Length: %d bytes\n", temp_version_and_header_length & 0x0F);
    printf("    |  +Differentiated Services Field: 0x%02x\n", ip_header->tos); // 区分服务字段
    printf("    |     ");
    for(int i = 7; i >= 2; i--){
        if(i == 3){
            printf(" ");
        }
        printf("%d", (ip_header->tos>>i) % 2);
    }
    printf(".. = Differentiated Services Codepoint\n");
    printf("    |     .... ..");
    printf("%d", (ip_header->tos>>1) % 2);
    printf("%d", ip_header->tos % 2);
    printf(" = Explicit Congestion Notification\n");
    printf("    |  +Total Length: %d\n", htons(ip_header->total_length));
    printf("    |  +Identification: 0x%04x\n", htons(ip_header->identifier));
    unsigned short temp_flags = htons(ip_header->flags); // 计算 Flags 两个字节的内容
    printf("    |  +Flags: 0x%02x\n", temp_flags>>13); // 输出标志位的值
    if(temp_flags>>15 == 0){ // 输出保留位的值
        printf("    |     0... .... = Reserved bit: Not set\n");
    }
    if((temp_flags>>14) % 2 == 1){ // 输出 DF 标志位的值
        printf("    |     .1.. .... = Don't fragment: Set\n");
    }
    else{
        printf("    |     .0.. .... = Don't fragment: Not set\n");
    }
    if((temp_flags>>13) % 2 == 0){ // 输出 MF 的标志位的值
        printf("    |     ..0. .... = More fragment: Not set\n");
    }
    else{
        printf("    |     ..1. .... = More fragment: Set\n");
    }
    printf("    |     Fragment offset: %d\n", temp_flags&0x1FFF); // 输出分段偏移量的值
    printf("    |  +Time to live: %d\n", ip_header->ttl);
    printf("    |  +Protocol: ");
    switch(ip_header->proto){
        case 0x06:
            printf("TCP (6)\n");
            break;
        case 0x01:
            printf("ICMP (1)\n");
            break;
        case 0x11:
            printf("UDP (11)\n");
            break;
        default:
            printf("unknown (%d)\n", ip_header->proto);
    }
    printf("    |  +Header checksum: 0x%04x\n", htons(ip_header->checksum));
    printf("    |  +Source: ");
    for(int i = 0; i < 4; ++i){
        printf("%u", ip_header->source_ip[i]);
        if(i != 3){
            printf(".");
        }
        else{
            printf("\n");
        }
    }
    printf("    |  +Destination: ");
    for(int i = 0; i < 4; ++i){
        printf("%d", ip_header->destination_ip[i]);
        if(i != 3){
            printf(".");
        }
        else{
            printf("\n");
        }
    }
}

void print_arp(ARP_HEADER * arp_header){

}

void print_icmp(ICMP_HEADER * icmp_header){
    printf("    |---|--Internet Control Message Protocol:\n");
    printf("        |  +Type: %d\n", icmp_header->type);
    printf("        |  +Code: %d\n", icmp_header->code);
    printf("        |  +Checksum: 0x%04x\n", ntohs(icmp_header->type));
}

void print_tcp(TCP_HEADER * tcp_header){
    printf("    |---|--Transmission Control Protocol:\n");
    printf("        |  +Source Port: %d\n", ntohs(tcp_header->source_port));
    printf("        |  +Destination Port: %d\n", ntohs(tcp_header->destination_port));
    printf("        |  +Sequence number: 0x%08x\n", ntohl(tcp_header->sequence_number));
    printf("        |  +Acknowledgment number: 0x%08x\n", ntohl(tcp_header->acknowledge_number));
    unsigned short temp_header_length_and_flag = ntohs(tcp_header->header_length_and_flag);
    printf("        |  +Header Length: %d bytes\n", (temp_header_length_and_flag>>12) * 4);
    printf("        |  +Flags:\n");
    if((temp_header_length_and_flag>>5) % 2 == 0){
        printf("        |     .... ..0. .... = Urgent: Not set\n");
    }
    else{
        printf("        |     .... ..1. .... = Urgent: Set\n");
    }
    if((temp_header_length_and_flag>>4) % 2 == 0){
        printf("        |     .... ...0 .... = Acknowledgment: Not set\n");
    }
    else{
        printf("        |     .... ...1 .... = Acknowledgment: Set\n");
    }
    if((temp_header_length_and_flag>>3) % 2 == 0){
        printf("        |     .... .... 0... = Push: Not set\n");
    }
    else{
        printf("        |     .... .... 1... = Push: Set\n");
    }
    if((temp_header_length_and_flag>>2) % 2 == 0){
        printf("        |     .... .... .0.. = Reset: Not set\n");
    }
    else{
        printf("        |     .... .... .1.. = Reset: Set\n");
    }
    if((temp_header_length_and_flag>>1) % 2 == 0){
        printf("        |     .... .... ..0. = Syn: Not set\n");
    }
    else{
        printf("        |     .... .... ..1. = Syn: Set\n");
    }
    if((temp_header_length_and_flag) % 2 == 0){
        printf("        |     .... .... ...0 = Fin: Not set\n");
    }
    else{
        printf("        |     .... .... ...1 = Fin: Set\n");
    }
    printf("        |  +Window size value: %d\n", ntohs(tcp_header->windows_size));
    printf("        |  +Checksum: 0x%04x\n", ntohs(tcp_header->checksum));
    printf("        |  +Urgent pointer: 0x%04x\n", ntohs(tcp_header->urgent_pointer));
}

void print_udp(UDP_HEADER * udp_header){
    printf("    |---|--User Datagram Protocol:\n");
    printf("        |  +Source Port: %d\n", ntohs(udp_header->source_port));
    printf("        |  +Destination Port: %d\n", ntohs(udp_header->destination_port));
    printf("        |  +Length: %d\n", ntohs(udp_header->length));
    printf("        |  +Checksum: 0x%04x\n", ntohs(udp_header->checksum));
}

void input_str(char * str, int length){
    for(int i = 0; i < length; ++i){
        scanf("%c", &str[i]); // 依次获取字符
        if(str[i] == '\n'){   // 输入换行符
            str[i] = '\0';    // 替换为字符串结束符
            break;
        }
    }
}

void filter(pcap_t *device, bpf_u_int32 maskp){
    struct bpf_program fp;                                  // 编译后的过滤表达式
    char str[200];                                          // 编译前的过滤表达式
    while(1){
        printf("过滤表达式: ");
        input_str(str, 200);                                // 获取用户输入
        if(pcap_compile(device, &fp, str, 0, maskp) == -1){ // 编译失败
            perror("pcap_compile error");                   // 报错
        }
        else{                                               // 编译成功
            pcap_setfilter(device, &fp);                    // 应用过滤
            if(str[0] == '\0'){
                printf("过滤表达式为空, 不进行数据包过滤.\n");
            }
            else{
                printf("应用过滤表达式 \"%s\" 成功!\n", str);
            }
            break;
        }
    }
}

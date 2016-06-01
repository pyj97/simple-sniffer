# simple-sniffer

[![](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![](https://img.shields.io/badge/License-MIT-blue.svg)]()
[![](https://img.shields.io/badge/C-11-yellow.svg)]()

simple-sniffer 是一个简单的嗅探器, 由 C 语言使用 libpcap 库实现, 具有抓取过滤功能, 可以对抓取的数据包进行还算详细的分析. 该工具在 Mac OS X 上实现, 没有图形化界面, 在 Linux 上应该也可以运行, 但并没有在 Linux 上进行测试.

## 编译运行

### 环境
* GCC
* libpcap

### 编译

`gcc simple_sniffer.c -lpcap -o simple_sniffer.out`

### 运行

`./simple_sniffer.out`

## 功能

能捕获以太网数据包, 能够分析 ipv4 数据包(包括 ICMP, TCP, UDP) 和 ARP 数据包, 分析数据包各部分头部非常详细, 分析展示部分参考了 Wireshark. 虽然本程序没有图形化界面, 但是我也对输出进行了格式化, 使其尽可能的美观, 直观, 清晰明了.

运行程序后, 首先寻找设备, 成功后会返回网络号和子网掩码, 并提示用户输入过滤表达式, 这里的过滤是抓取过滤而不是显示过滤, 过滤功能的实现是直接调用了 Libpcap 库中的 BPF 功能, 表达式可以为空, 即不过滤, 如果表达式不合法会提示用户重新输入, 应用表达式成功后会开始抓包并分析, 每个包的展示分三部分, 第一部分是数据包的简略信息, 包括序号, 长度, 大小, 接收时间; 第二部分是数据包的分析, 本程序对支持的数据包类型分析的十分详细; 第三部分就是数据包的原始十六进制表示, 在其右侧是原始数据包每个字节对应的 ASCII 字符, 如果不能转换成可显示字符, 就用点来代替.

## 介绍

* 部分输出, 只展示了抓取的两个包:

```
> gcc simple_sniffer.c -lpcap -o simple_sniffer.out;./simple_sniffer.out
Found device: en0
Succeed open device: en0
Network Number: 192.168.1.0, Subnet Mask: 255.255.255.0
Enter a capture filter: 
Capture filter is null, don't enable filter.
=====================================================================
Number: 1 Length: 62 Size: 62 Bytes Received Time: Wed Jun  1 21:24:33 2016
|--Ethernet:
|  +Destination: A8-66-7F-17-C7-BF
|  +Source: CC-34-29-96-2D-26
|  +Type: IPv4 (0x0800)
|---|--Internet Protocol Version 4:
    |  +Version: 4
    |  +Header Length: 5 bytes
    |  +Differentiated Services Field: 0x00
    |     0000 00.. = Differentiated Services Codepoint
    |     .... ..00 = Explicit Congestion Notification
    |  +Total Length: 48
    |  +Identification: 0x3ecf
    |  +Flags: 0x00
    |     0... .... = Reserved bit: Not set
    |     .0.. .... = Don't fragment: Not set
    |     ..0. .... = More fragment: Not set
    |     Fragment offset: 0
    |  +Time to live: 62
    |  +Protocol: UDP (11)
    |  +Header checksum: 0x696d
    |  +Source: 10.170.7.202
    |  +Destination: 192.168.1.101
    |---|--User Datagram Protocol:
        |  +Source Port: 33984
        |  +Destination Port: 51413
        |  +Length: 28
        |  +Checksum: 0x9467
 0000   a8 66 7f 17 c7 bf cc 34 29 96 2d 26 08 00 45 00   .f.....4).-&..E.
 0010   00 30 3e cf 00 00 3e 11 69 6d 0a aa 07 ca c0 a8   .0>...>.im......
 0020   01 65 84 c0 c8 d5 00 1c 94 67 21 00 41 09 34 b8   .e.......g!.A.4.
 0030   8f 08 bf 8b ca 51 00 00 f0 00 bc 2f ed 5e         .....Q...../.^

=====================================================================
Number: 2 Length: 62 Size: 62 Bytes Received Time: Wed Jun  1 21:24:34 2016
|--Ethernet:
|  +Destination: CC-34-29-96-2D-26
|  +Source: A8-66-7F-17-C7-BF
|  +Type: IPv4 (0x0800)
|---|--Internet Protocol Version 4:
    |  +Version: 4
    |  +Header Length: 5 bytes
    |  +Differentiated Services Field: 0x00
    |     0000 00.. = Differentiated Services Codepoint
    |     .... ..00 = Explicit Congestion Notification
    |  +Total Length: 48
    |  +Identification: 0x0f82
    |  +Flags: 0x00
    |     0... .... = Reserved bit: Not set
    |     .0.. .... = Don't fragment: Not set
    |     ..0. .... = More fragment: Not set
    |     Fragment offset: 0
    |  +Time to live: 64
    |  +Protocol: UDP (11)
    |  +Header checksum: 0x91e9
    |  +Source: 192.168.1.101
    |  +Destination: 10.170.12.155
    |---|--User Datagram Protocol:
        |  +Source Port: 51413
        |  +Destination Port: 42379
        |  +Length: 28
        |  +Checksum: 0x74d2
 0000   cc 34 29 96 2d 26 a8 66 7f 17 c7 bf 08 00 45 00   .4).-&.f......E.
 0010   00 30 0f 82 00 00 40 11 91 e9 c0 a8 01 65 0a aa   .0....@......e..
 0020   0c 9b c8 d5 a5 8b 00 1c 74 d2 21 00 3c 6d 75 2d   ........t.!.<mu-
 0030   93 0b 26 da 26 d3 00 04 00 00 db 11 b4 c6         ..&.&.........
```

* TCP 包分析展示:

```
Number: 170 Length: 54 Size: 54 Bytes Received Time: Wed Jun  1 21:30:10 2016
|--Ethernet:
|  +Destination: CC-34-29-96-2D-26
|  +Source: A8-66-7F-17-C7-BF
|  +Type: IPv4 (0x0800)
|---|--Internet Protocol Version 4:
    |  +Version: 4
    |  +Header Length: 5 bytes
    |  +Differentiated Services Field: 0x00
    |     0000 00.. = Differentiated Services Codepoint
    |     .... ..00 = Explicit Congestion Notification
    |  +Total Length: 40
    |  +Identification: 0x3a83
    |  +Flags: 0x02
    |     0... .... = Reserved bit: Not set
    |     .1.. .... = Don't fragment: Set
    |     ..0. .... = More fragment: Not set
    |     Fragment offset: 0
    |  +Time to live: 64
    |  +Protocol: TCP (6)
    |  +Header checksum: 0xb9f0
    |  +Source: 192.168.1.101
    |  +Destination: 117.34.15.45
    |---|--Transmission Control Protocol:
        |  +Source Port: 52146
        |  +Destination Port: 80
        |  +Sequence number: 0x6241fc17
        |  +Acknowledgment number: 0xec55030a
        |  +Header Length: 20 bytes
        |  +Flags:
        |     .... ..0. .... = Urgent: Not set
        |     .... ...1 .... = Acknowledgment: Set
        |     .... .... 0... = Push: Not set
        |     .... .... .0.. = Reset: Not set
        |     .... .... ..0. = Syn: Not set
        |     .... .... ...0 = Fin: Not set
        |  +Window size value: 8192
        |  +Checksum: 0x2fbc
        |  +Urgent pointer: 0x0000
 0000   cc 34 29 96 2d 26 a8 66 7f 17 c7 bf 08 00 45 00   .4).-&.f......E.
 0010   00 28 3a 83 40 00 40 06 b9 f0 c0 a8 01 65 75 22   .(:.@.@......eu"
 0020   0f 2d cb b2 00 50 62 41 fc 17 ec 55 03 0a 50 10   .-...PbA...U..P.
 0030   20 00 2f bc 00 00
```

* UDP 包分析展示:

```
Number: 120 Length: 72 Size: 72 Bytes Received Time: Wed Jun  1 21:32:44 2016
|--Ethernet:
|  +Destination: CC-34-29-96-2D-26
|  +Source: A8-66-7F-17-C7-BF
|  +Type: IPv4 (0x0800)
|---|--Internet Protocol Version 4:
    |  +Version: 4
    |  +Header Length: 5 bytes
    |  +Differentiated Services Field: 0x00
    |     0000 00.. = Differentiated Services Codepoint
    |     .... ..00 = Explicit Congestion Notification
    |  +Total Length: 58
    |  +Identification: 0x12d3
    |  +Flags: 0x00
    |     0... .... = Reserved bit: Not set
    |     .0.. .... = Don't fragment: Not set
    |     ..0. .... = More fragment: Not set
    |     Fragment offset: 0
    |  +Time to live: 64
    |  +Protocol: UDP (11)
    |  +Header checksum: 0x5941
    |  +Source: 192.168.1.101
    |  +Destination: 10.170.65.232
    |---|--User Datagram Protocol:
        |  +Source Port: 51413
        |  +Destination Port: 27913
        |  +Length: 38
        |  +Checksum: 0x24e7
 0000   cc 34 29 96 2d 26 a8 66 7f 17 c7 bf 08 00 45 00   .4).-&.f......E.
 0010   00 3a 12 d3 00 00 40 11 59 41 c0 a8 01 65 0a aa   .:....@.YA...e..
 0020   41 e8 c8 d5 6d 09 00 26 24 e7 41 02 63 bf 92 69   A...m..&$.A.c..i
 0030   c1 e7 00 00 00 00 00 04 00 00 9d 1d 00 00 00 08   ................
 0040   00 00 00 00 00 00 00 00
```

* ICMP 和 ARP 的包我没抓取到, 可能是我的环境中没有这两种包, 但是分析这两种协议的代码是有的.

## 开发心得

* 了解了数据在内存中存储的大端小端问题, 本程序中使用网络字节序和主机字节序转换函数来解决的.
* 一开始数据分析不详细, 只是简单的分析了物理地址, IP 地址和端口, 然后花了一整天的时间进行了支持的六种类型协议进行了详细的分析, 现在我对数据包头部的每一个比特都很熟悉.
* 此次开发使用了 C 语言中位字段的数据结构, 这个数据结构用来操作比特很方便, 此次开发让我更熟悉了 C 语言的运用.

## 感谢

通过学习 [Programming with Libpcap - Sniffing the network from our own application](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf) by Luis MartinGarcia. Hakin9 Magazine. Issue 2/2008 我知道了如何使用 libpcap 进行抓包, 在此非常感谢作者!

## License

The MIT License (MIT)

Copyright (c) 2016 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

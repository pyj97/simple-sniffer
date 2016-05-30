# simple-sniffer

[![](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![](https://img.shields.io/badge/License-MIT-blue.svg)]()
[![](https://img.shields.io/badge/C-11-yellow..svg)]()

simple-sniffer 是一个简单的嗅探器, 由 C 语言使用 libpcap 库实现, 具有抓取过滤功能, 可以对抓取的数据包进行还算详细的分析. 该工具在 Mac OS X 上实现, 没有图形化界面.

## 编译运行
### 环境
* GCC
* libpcap
### 编译
`gcc simple_sniffer.c -lpcap -o simple_sniffer.out`
### 运行
`./simple_sniffer.out`

## 感谢

通过学习 [Programming with Libpcap - Sniffing the network from our own application](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf) by Luis MartinGarcia. Hakin9 Magazine. Issue 2/2008 我知道了如何使用 libpcap 进行抓包, 在此非常感谢作者!


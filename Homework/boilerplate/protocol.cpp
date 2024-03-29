#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <cassert>
#include <cstdio>


/*
    在头文件 rip.h 中定义了如下的结构体：
    #define RIP_MAX_ENTRY 25
    typedef struct {
        // all fields are big endian
        // we don't store 'family', as it is always 2(response) and 0(request)
        // we don't store 'tag', as it is always 0
        uint32_t addr;
        uint32_t mask;
        uint32_t nexthop;
        uint32_t metric;
    } RipEntry;

    typedef struct {
        uint32_t numEntries;
        // all fields below are big endian
        uint8_t command; // 1 for request, 2 for response, otherwsie invalid
        // we don't store 'version', as it is always 2
        // we don't store 'zero', as it is always 0
        RipEntry entries[RIP_MAX_ENTRY];
    } RipPacket;

    你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
    由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
    需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint32_t tot_len = ((uint32_t)packet[2] << 8) | packet[3];
    if (tot_len > len) {
        return false;
    }
    if ((tot_len - 32) % 20) { // invalid length
        return false;
    }
    output->numEntries = (tot_len - 32) / 20;
    packet += 28;
    if (packet[0] != 1 && packet[0] != 2) { // invalid command
        return false;
    }
    output->command = packet[0];
    if (packet[1] != 2) { // invalid version
        return false;
    }
    if (packet[2] || packet[3]) { // invalid zero field
        return false;
    }
    packet += 4;
    for (int i = 0; i < output->numEntries; ++i) {
        if (packet[0] || output->command == 1 && packet[1] != 0 || output->command == 2 && packet[1] != 2) { // invalid family
            return false;
        } 
        if (packet[2] || packet[3]) { // invalid tag
            return false;
        }
        packet += 4;
        output->entries[i].addr = *(uint32_t*)packet;
        // output->entries[i].addr = (uint32_t)(packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
        packet += 4;
        uint32_t tmpMask = (uint32_t)(packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
        uint32_t y = ~tmpMask;
        uint32_t z = y + 1;
        if (y & z) { // invalid netmask
            return false;
        }
        output->entries[i].mask = *(uint32_t*)packet;
        // output->entries[i].mask = (uint32_t)(packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
        packet += 4;
        output->entries[i].nexthop = *(uint32_t*)packet;
        // output->entries[i].nexthop = (uint32_t)(packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
        packet += 4;
        // if (*(uint32_t*)packet == 0 || *(uint32_t*)packet > 16) { // invalid metric
        //     return false;
        // }
        if (packet[0] || packet[1] || packet[2] || packet[3] == 0 || packet[3] > 0x10) { // invalid metric
            return false;
        }
        output->entries[i].metric = *(uint32_t*)packet;
        // output->entries[i].metric = (uint32_t)(packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
        packet += 4;
    }
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    uint8_t* origin = buffer;
    *(buffer++) = rip->command;
    *(buffer++) = 0x2;

    *(buffer++) = 0x0;
    *(buffer++) = 0x0;
    for (int i = 0; i < rip->numEntries; ++i) {
        *(buffer++) = 0x0;
        *(buffer++) = rip->command == 0x2 ? 0x2 : 0x0;

        *(buffer++) = 0x0;
        *(buffer++) = 0x0;

        *(uint32_t*)buffer = rip->entries[i].addr;
        buffer += 4;
        *(uint32_t*)buffer = rip->entries[i].mask;
        buffer += 4;
        *(uint32_t*)buffer = rip->entries[i].nexthop;
        buffer += 4;
        *(uint32_t*)buffer = rip->entries[i].metric;
        buffer += 4;
    }
    return buffer - origin;
}
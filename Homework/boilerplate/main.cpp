#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
using std::map, std::pair, std::swap;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern void rip_update(RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];

extern map<uint32_t, RoutingTableEntry> table[33];

// 你可以按需进行修改，注意端序
// 192.168.3.2, 192.168.4.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0};
const in_addr_t multi_addr = 0x090000e0;

void printRoutingTable() {
    for (int i = 0; i <= 32; ++i) {
        for (auto p : table[i]) {
            uint32_t addr = p.second.addr;
            uint32_t len = p.second.len;
            uint32_t nexthop = p.second.nexthop;
            uint32_t metric = p.second.metric;
            printf("%u.%u.%u.%u/%u -> %u.%u.%u.%u metric=%u\n", (uint32_t)(addr & 0xff),
            (uint32_t)((addr & 0xff00) >> 8), (uint32_t)((addr & 0xff0000) >> 16),
            (uint32_t)((addr & 0xff000000 >> 24)), (uint32_t)(nexthop & 0xff),
            (uint32_t)((nexthop & 0xff00) >> 8), (uint32_t)((nexthop & 0xff0000) >> 16),
            (uint32_t)((nexthop & 0xff000000 >> 24)), metric); 
        }
    }
}

void constructHeader(uint32_t srcAddr, uint32_t dstAddr, uint32_t ipLen) {
    output[0] = 0x45;
    output[1] = 0x0;
    // length
    output[2] = ipLen >> 8;
    output[3] = ipLen & 255;
    // id
    output[4] = 0x0;
    output[5] = 0x0;
    // flags
    output[6] = 0x0;
    output[7] = 0x0;
    // TTL
    output[8] = 0x1;
    // protocol
    output[9] = 0x11;
    // source endian?
    *(uint32_t*)(output + 12) = srcAddr;
    // dest endian?
    *(uint32_t*)(output + 16) = dstAddr;
    // checksum
    output[10] = 0x0;
    output[11] = 0x0;
    unsigned sum_low = 0;
    unsigned sum_hi = 0;
    for (int i = 0; i < 20; i += 2) {
        sum_hi += *(output + i);
        sum_low += *(output + i + 1);
    }
    unsigned sum = sum_low + (sum_hi << 8);
    sum = (sum >> 16) + (sum & 0xffff);
    sum = (~sum) & 0xffff;
    output[10] = sum >> 8;
    output[11] = sum & 255;

    output[20] = 0x02;
    output[21] = 0x08;
    output[22] = 0x02;
    output[23] = 0x08;
    ipLen -= 20;
    output[24] = ipLen >> 8;
    output[25] = ipLen & 255;
    // checksum = 0
    output[26] = 0x0;
    output[27] = 0x0;
}

uint32_t getMask(int len) {
    uint32_t mask = 0xffffffff << (32 - len);
    uint8_t* ptr = &mask;
    swap(*ptr, *(ptr + 3));
    swap(*(ptr + 1), *(ptr + 2));
    return mask;
}

uint32_t getLen(uint32_t mask) {
    uint8_t* ptr = &mask;
    swap(*ptr, *(ptr + 3));
    swap(*(ptr + 1), *(ptr + 2));
    for (uint32_t i = 0; i < 32; ++i) {
        if (mask << i == 0) {
            return i;
        }
    }
    return 32;
}

RipPacket constructRipPacket(uint32_t ignore) {
    RipPacket resp;
    resp.command = 2;
    resp.numEntries = 0;
    for (int i = 32; i >= 0; --i) {
        uint32_t mask = getMask(i);
        for (auto p : table[i]) {
            auto info = p.second;
            if (ignore & mask == info.addr & mask) {
                continue;
            }
            resp.entries[resp.numEntries].addr = info.addr;
            resp.entries[resp.numEntries].nexthop = info.nexthop;
            resp.entries[resp.numEntries].mask = getMask(info.len);
            resp.entries[resp.numEntries].metric = info.metric;
            ++resp.numEntries;
        }
    }
    return resp;
}

int main(int argc, char *argv[]) {
    // 0a.
    int res = HAL_Init(1, addrs);
    if (res < 0) {
        return res;
    }

    // 0b. Add direct routes
    for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        RoutingTableEntry entry = {
            .addr = addrs[i] & 0x00FFFFFF, // big endian
            .len = 24,        // small endian
            .if_index = i,    // small endian
            .nexthop = 0      // big endian, means direct
        };
        update(true, entry);
    }

    uint64_t last_time = 0;
    while (1) {
        uint64_t time = HAL_GetTicks();
        // when testing, you can change 30s to 5s
        if (time > last_time + 5 * 1000) {
            // TODO: send complete routing table to every interface
            // ref. RFC2453 Section 3.8
            // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
            for (int i = 0; i < N_IFACE_ON_BOARD; ++i) {
                auto packet = constructRipPacket(addrs[i]);
                uint32_t len = assemble(&packet, output + 28);
                constructHeader(addrs[i], multi_addr, len + 28);
                macaddr_t dst_mac;
                HAL_ArpGetMacAddress(i, multi_addr, dst_mac);
                HAL_SendIPPacket(i, output, len + 28, dst_mac);
            }

            printRoutingTable();
            last_time = time;
            printf("5s Timer\n");
        }

        int mask = (1 << N_IFACE_ON_BOARD) - 1;
        macaddr_t src_mac;
        macaddr_t dst_mac;
        int if_index;
        res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);
        if (res == HAL_ERR_EOF) {
            break;
        } else if (res < 0) {
            return res;
        } else if (res == 0) {
            // Timeout
            continue;
        } else if (res > sizeof(packet)) {
            // packet is truncated, ignore it
            continue;
        }

        // 1. validate
        if (!validateIPChecksum(packet, res)) {
            printf("Invalid IP Checksum\n");
            continue;
        }
        in_addr_t src_addr, dst_addr;
        // TODO: extract src_addr and dst_addr from packet (big endian)
        src_addr = *(uint32_t*)(packet + 12);
        dst_addr = *(uint32_t*)(packet + 16);

        // 2. check whether dst is me
        bool dst_is_me = false;
        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
            if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
                dst_is_me = true;
                break;
            }
        }
        // TODO: handle rip multicast address(224.0.0.9)
        if (memcmp(&dst_addr, &multi_addr, sizeof(in_addr_t)) == 0) {
            dst_is_me = true;
        }

        if (dst_is_me) {
            // 3a.1
            RipPacket rip;
            // check and validate
            if (disassemble(packet, res, &rip)) {
                if (rip.command == 1) {
                    // 3a.3 request, ref. RFC2453 3.9.1
                    // only need to respond to whole table requests in the lab

                    // assembleRIP
                    RipPacket resp = constructRipPacket(src_addr);
                    uint32_t rip_len = assemble(&resp, &output[20 + 8]);
                    // TODO: fill IP headers
                    constructHeader(addrs[if_index], src_addr, rip_len + 28);

                    // send it back
                    HAL_SendIPPacket(if_index, output, rip_len + 28, src_mac);
                    } else {
                    // 3a.2 response, ref. RFC2453 3.9.2
                    // TODO: update routing table
                    // new metric = ?
                    // update metric, if_index, nexthop
                    // HINT: handle nexthop = 0 case
                    // HINT: what is missing from RoutingTableEntry?
                    // you might want to use `query` and `update` but beware of the difference between exact match and longest prefix match
                    // optional: triggered updates? ref. RFC2453 3.10.1
                    for (int i = 0; i < rip.numEntries; i++) {
                        RoutingTableEntry entry = {
                            .addr = rip.entries[i].addr,
                            .len = getLen(rip.entries[i].mask),
                            .if_index = if_index,
                            .nexthop = src_addr,
                            .metric = rip.entries[i].metric
                        };
                        if (rip.entries[i].metric < 16) {
                            rip_update(entry);
                        }
                    }
                }
            }
        } else {
            // 3b.1 dst is not me
            // forward
            // beware of endianness
            uint32_t nexthop, dest_if;
            if (query(dst_addr, &nexthop, &dest_if)) {
                // found
                macaddr_t dest_mac;
                // direct routing
                if (nexthop == 0) {
                    nexthop = dst_addr;
                }
                if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
                    // found
                    memcpy(output, packet, res);
                    // update ttl and checksum
                    forward(output, res);
                    // TODO(optional): check ttl=0 case
                    if (output[8] == 0) {
                        continue;
                    }
                    HAL_SendIPPacket(dest_if, output, res, dest_mac);
                } else {
                    // not found
                    // you can drop it
                    printf("ARP not found for nexthop %x\n", nexthop);
                }
            } else {
                // not found
                // TODO(optional): send ICMP Host Unreachable
                printf("IP not found for src %x dst %x\n", src_addr, dst_addr);
            }
        }
    }
}

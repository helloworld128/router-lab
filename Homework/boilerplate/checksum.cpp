#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <cassert>
using namespace std;

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
    int header_len = (packet[0] & 15) * 4;
    // cout << header_len << '\n';
    unsigned sum_low = 0;
    unsigned sum_hi = 0;
    for (int i = 0; i < header_len; i += 2) {
        sum_hi += *(packet + i);
        sum_low += *(packet + i + 1);
    }
    unsigned sum = sum_low + (sum_hi << 8);
    sum = (sum >> 16) + (sum & 0xffff);
    return sum == 0xffff;
}
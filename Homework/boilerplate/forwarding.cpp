#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
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
    sum += (sum >> 16);
    if (sum != 0xffff) {
        return false;
    }
    // TTL -= 1
    --packet[8];
    // reset checksum
    packet[10] = 0;
    packet[11] = 0;
    sum_low = sum_hi = 0;
    for (int i = 0; i < header_len; i += 2) {
        sum_hi += *(packet + i);
        sum_low += *(packet + i + 1);
    }
    sum = sum_low + (sum_hi << 8);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    sum = (~sum) & 0xffff;
    packet[10] = sum >> 8;
    packet[11] = sum & 0xff;
    return true;
}
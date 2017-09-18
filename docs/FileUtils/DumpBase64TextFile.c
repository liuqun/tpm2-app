/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "DumpBase64File.h"

void DumpBase64TextFile(FILE *fpOut, unsigned int len, const void *dataIn) {
    const char base[64] = { //base64编码映射表
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
    };
    const unsigned char *data = (const unsigned char *)dataIn;
    unsigned int a, b, c, d;
    unsigned int i;
    for (i=3; i<=len; i+=3) {
        a = data[i-3] >> 2;
        b = ((0x03 & data[i-3])<<4) | (data[i-2]>>4);
        c = ((0x0F & data[i-2])<<2) | (data[i-1]>>6);
        d =  0x3F & data[i-1];
        fprintf(fpOut, "%c%c%c%c", base[a], base[b], base[c], base[d]); // TODO: 分别调用 ferror(fpOut) clearerr(fpOut) 检查IO输出是否出错
    }

    i -= 3;
    if (i == len) {
        return;
    }

    // 可能剩余2字节或剩余1字节未处理, 对应 i 的取值可能等于 len-2 或 len-1
    a = data[i] >> 2;
    fprintf(fpOut, "%c", base[a]);
    b = (0x03 & data[i]) << 4;
    if (i == len -1) {
        fprintf(fpOut, "%c==", base[b]);
        return;
    }
    b |= data[i+1] >> 4;
    c = (0x0F & data[i+1]) << 2;
    fprintf(fpOut, "%c%c=", base[b], base[c]);
}

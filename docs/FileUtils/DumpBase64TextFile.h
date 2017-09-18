/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#ifndef DUMP_BASE64_TEXT_FILE_H_
#define DUMP_BASE64_TEXT_FILE_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 按Base64纯文本文件格式输出数据
 */
void DumpBase64TextFile(FILE *fpOut, unsigned int dataInLength, const void *dataIn);

#ifdef __cplusplus
};
#endif

#endif // DUMP_BASE64_TEXT_FILE_H_

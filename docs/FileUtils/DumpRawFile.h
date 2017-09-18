/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#ifndef _DUMP_RAW_FILE_H
#define _DUMP_RAW_FILE_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 按Raw(原始)格式输出二进制文件
 *
 * @param fpOut
 * @param length
 * @param dataIn
 * @throws std::ios::failure when file output failed. 可能原因包括: 1.文件不可写(权限不足); 2.磁盘已满; 3.其他
 */
void DumpRawFile(FILE *fpOut, unsigned int length, const void *dataIn);

#ifdef __cplusplus
};
#endif

#endif // _DUMP_RAW_FILE_H

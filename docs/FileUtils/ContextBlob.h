/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#ifndef _CONTEXT_BLOB_H
#define _CONTEXT_BLOB_H
#ifndef __cplusplus
#error // 本头文件只能从C++引用
#endif

#include <cstdio>
using std::FILE;

class ContextBlob {
public:
    ContextBlob();
    ~ContextBlob();
    void loadFromRawData(unsigned int len, const void *raw);
    void loadFromRawFile(FILE *fpIn);
    void loadFromBase64Text(FILE *fpIn);
    void loadFromHexTextFile(FILE *fpIn, const char *separator=":");

    const void *data();
    unsigned int size();

    void dumpRaw(FILE *fpOut);
    void dumpBase64Text(FILE *fpOut);
    void dumpHexText(FILE *fpOut, const char *separator=":");

    /// 清空私有存储区(恢复初始化状态)
    void reset();
private:
    struct InvisibleData *m_pBlackBox; ///< 私有存储区存储(黑盒数据块)
};

#endif // _CONTEXT_BLOB_H

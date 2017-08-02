/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdexcept>
#include <vector>
using std::vector;
using namespace std;
#include "DumpRawFile.h"
#include "ContextBlob.h"

struct InvisibleData // 私有存储区存储(黑盒)
{
    vector<uint8_t> buf;
};

ContextBlob::ContextBlob()
{
    m_pBlackBox = new struct InvisibleData;
    m_pBlackBox->buf.clear();
}

ContextBlob::~ContextBlob()
{
    delete m_pBlackBox;
}

void ContextBlob::reset()
{
    m_pBlackBox->buf.clear();
}

void ContextBlob::loadFromRawData(unsigned int len, const void *raw)
{
    const uint8_t *p = (const uint8_t *) raw;
    m_pBlackBox->buf.clear();
    m_pBlackBox->buf.assign(p, p+len); // 存储共 len 个字节原始数据
}

void ContextBlob::loadFromRawFile(FILE *fpIn)
{
    const int BufSize = 1600;
    uint8_t buf[BufSize];

    m_pBlackBox->buf.clear();
    while (!feof(fpIn))
    {
        clearerr(fpIn);
        size_t n = fread(buf, sizeof(uint8_t), BufSize, fpIn);
        for (unsigned int i=0; i<n; i++)
        {
            m_pBlackBox->buf.push_back(buf[i]); // 每次只追加1个字节到末尾
        }
        if (n < BufSize)
        {
            break;
        }
        else if (ferror(fpIn))
        {
            break; // TODO: maybe we should throw an expection
        }
    }
}

#include <fstream>
#include <stdexcept>
void ContextBlob::dumpRaw(FILE *fpOut)
{
    unsigned int size = m_pBlackBox->buf.size();
    const uint8_t *data = m_pBlackBox->buf.data();
    try
    {
        DumpRawFile(fpOut, size, data);
    }
    catch (std::ofstream::failure& failure)
    {
        fprintf(stderr, "IO error: %s\n", failure.what());
    }
    catch (std::exception& other)
    {
    }
}

void ContextBlob::dumpBase64Text(FILE *fpOut)
{
    unsigned int size = m_pBlackBox->buf.size();
    const uint8_t *data = m_pBlackBox->buf.data();
    DumpBase64TextFile(fpOut, size, data);
}


void ContextBlob::loadFromBase64Text(FILE *fpIn)
{
    // TODO
}

void ContextBlob::dumpHexText(FILE *fpOut, const char *separator)
{
    const unsigned int TotalLength = m_pBlackBox->buf.size();
    const uint8_t *data = m_pBlackBox->buf.data();
    for (unsigned int i=0; i<TotalLength; i++)
    {
        fprintf(fpOut, "%02X", data[i]);
        fprintf(fpOut, "%s", separator);
    }

}

void ContextBlob::loadFromHexTextFile(FILE *fpIn, const char *separator)
{
    // TODO
}

const void *ContextBlob::data()
{
    return m_pBlackBox->buf.data();
}

unsigned int ContextBlob::size()
{
    return m_pBlackBox->buf.size();
}

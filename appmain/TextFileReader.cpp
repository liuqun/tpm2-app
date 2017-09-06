/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <string>
using std::string;
#include <ios>
using std::ios;
#include "TextFileReader.h"

// GetNextLineFromTextFile(fp, s, '\n') 从文件fp读取下一行内容存储到字符串s中, 指定'\n'作为换行标记符
const string& GetNextLineFromTextFile(FILE *fpTextFileIn, string& sLineOut, char cLineDelimiter)
{
    int ch;
    string line;

    if (feof(fpTextFileIn))
    {
        throw ios::failure("Already at end of file! No more lines to read!");
    }
    while ((ch = fgetc(fpTextFileIn)) != EOF)
    {
        if (ch == cLineDelimiter)
        {
            break; // NOTE: 这里不额外存储行末的换行符
        }
        if (isprint(ch) || isblank(ch)) // FIXME: 任何非ASCII编码的字符都被当作无效字符直接忽略. (建议事先将汉字转换为Base64格式存储)
        {
            line += (char)ch;
        }
    }
    sLineOut = line;
    return(sLineOut);
}

/**
 * @file SM3.h
 * @brief SM3(256位) 哈希算法 C 语言头文件
 *
 * @note 关于 SM3 哈希算法的详细描述和实现代码请查阅《GM/T 0004-2012 SM3密码杂凑算法》。可登录(中国)国家商用密码管理办公室网站进行查询
 * @see http://www.oscca.gov.cn
 *
 * 库函数调用方法请参考相应目录下的示例程序:
 * @example example.c 是一个 C 语言示例程序
 * @example example.cpp 是一个 C++ 语言示例程序
 */

#ifndef _SM3_H_
#define _SM3_H_

#if (defined(__GNUC__) || (defined(_MSC_VER) && (_MSC_VER >= 1600)))
#include <stdint.h>
/*
 * GCC 始终支持 <stdint.h>
 * Mircrosoft Visual Studio 2010 以上版本(_MSC_VER >= 1600)才支持 C99 标准 <stdint.h>
 */
#else
/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typdef the following:
 * name meaning
 * uint32_t unsigned 32 bit integer
 * uint8_t unsigned 8 bit integer (i.e., unsigned char)
 */
#include <windef.h>
typedef BYTE uint8_t;
typedef DWORD uint32_t;
#endif

/**
 * 定义 SM3 函数的一组成功/错误返回值
 */
enum
{
	SM3Success = 0, ///< Success
	SM3Null, ///< Null pointer parameter
	SM3InputTooLong, ///< input data too long
	SM3StateError, ///< This error happens when another SM3Input() is called unexpectedly after SM3Result()
};

#define SM3HashDigestSize 32 ///< SM3 哈希摘要结果长度(32 字节 = 256 位)
/**
 * This structure will hold context information for the SM3
 * hashing operation.
 * 这是 SM3 哈希算法上下文结构体
 *
 * @see SM3CreateNewContext() 创建 SM3 上下文
 * @see SM3DeleteContext() 销毁 SM3 上下文
 */
typedef struct _sm3_ctx_t SM3Context;

#ifdef __cplusplus
extern "C" {
#endif//
/*
 * Function Prototypes
 * API 接口函数原型声明如下:
 */

/**
 * 对 SM3 上下文结构体进行复位清零
 *
 * @return SM3Success=0 表示成功, 其他非 0 值表示错误: SM3Null
 */
int SM3Reset(
		SM3Context *context ///< 上下文指针
		);

/**
 * 向 SM3 上下文结构体输入数据
 *
 * @return SM3Success=0 表示成功, 其他非 0 值表示错误: SM3Null / SM3InputTooLong / SM3StateError
 */
int SM3Input(
		SM3Context *context, ///< 上下文指针
		const uint8_t data[], ///< 数据
		unsigned int length ///< 数据长度
		);

/**
 * 从 SM3 上下文取出哈希摘要结果
 *
 * @return SM3Success=0 表示成功, 其他非 0 值表示错误: SM3Null / SM3StateError
 */
int SM3Result(
		SM3Context *context, ///< 上下文指针
		uint8_t Message_Digest[SM3HashDigestSize] ///< 输出 SM3HashDigestSize=32 字节哈希摘要
		);

/**
 * 创建 SM3 上下文对象
 *
 * @return 指针, 指向新创建的上下文对象
 */
SM3Context *SM3CreateNewContext();

/**
 * 删除 SM3 上下文对象
 */
void SM3DeleteContext(SM3Context *context ///< 上下文指针
		);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_SM3_H

/**
* @file SHA1.h
* @brief SHA1 哈希算法 C 语言头文件
*
* @details
* Description:
* This is the header file for code which implements the Secure
* Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
* April 17, 1995.
*
* Many of the variable names in this code, especially the
* single character names, were used because those were the names
* used in the publication.
*
* @note 关于 SHA1 哈希算法的详细描述和实现代码请查阅 RFC3174
* @see https://tools.ietf.org/html/rfc3174
*
* 库函数调用方法请参考相应目录下的示例程序:
* @example example.c 是一个 C 语言示例程序
* @example example.cpp 是一个 C++ 语言示例程序
*/

#ifndef _SHA1_H_
#define _SHA1_H_

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
*
*/
#include <windef.h>
typedef BYTE uint8_t;
typedef DWORD uint32_t;
#endif

#ifndef _SHA_enum_
#define _SHA_enum_
/**
* 定义 SHA1 函数的一组成功/错误返回值
*/
enum
{
	shaSuccess = 0, ///< Success
	shaNull, ///< Null pointer parameter
	shaInputTooLong, ///< input data too long
	shaStateError, ///< This error happens when another SHA1Input() is called unexpectedly after SHA1Result()
};
#endif
#define SHA1HashSize 20 ///< SHA1 哈希摘要结果长度(20 字节)
/**
* This structure will hold context information for the SHA-1
* hashing operation
*/
typedef struct _SHA1Context SHA1Context;

/*
* Function Prototypes
*/
#ifdef __cplusplus
extern "C" {
#endif//

/**
 * 对 SHA1 上下文结构体进行复位清零
 *
 * @return shaSuccess=0 表示成功, 其他非 0 值表示错误: shaNull
 */
int SHA1Reset(
		SHA1Context *context ///< 上下文指针
		);

/**
 * 向 SHA1 上下文结构体输入数据
 *
 * @return shaSuccess=0 表示成功, 其他非 0 值表示错误: shaNull / shaInputTooLong / shaStateError
 */
int SHA1Input(
		SHA1Context *context, ///< 上下文指针
		const uint8_t data[], ///< 数据
		unsigned int length ///< 数据长度
		);

/**
 * 从 SHA1 上下文取出哈希摘要结果
 *
 * @return shaSuccess=0 表示成功, 其他非 0 值表示错误: shaNull / shaStateError
 */
int SHA1Result(
		SHA1Context *context, ///< 上下文指针
		uint8_t Message_Digest[SHA1HashSize] ///< 输出 SHA1HashSize=20 字节哈希摘要
		);

/**
 * 创建 SHA1 上下文对象
 *
 * @return 指针, 指向新创建的上下文对象
 */
SHA1Context *SHA1CreateNewContext();

/**
 * 删除 SHA1 上下文对象
 */
void SHA1DeleteContext(SHA1Context *context ///< 上下文指针
		);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif

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
* @example example.cpp
* 库函数调用方法请参考相应目录下的示例文件: example.cpp
*/

#ifndef _SHA1_H_
#define _SHA1_H_
#include <stdint.h>
/*
* If you do not have the ISO standard stdint.h header file, then you
* must typdef the following:
* name meaning
* uint32_t unsigned 32 bit integer
* uint8_t unsigned 8 bit integer (i.e., unsigned char)
* int_least16_t integer of >= 16 bits
*
*/
#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
	shaSuccess = 0,
	shaNull, /* Null pointer parameter */
	shaInputTooLong, /* input data too long */
	shaStateError /* called Input after Result */
};
#endif
#define SHA1HashSize 20
/*
* This structure will hold context information for the SHA-1
* hashing operation
*/
typedef struct SHA1Context
{
	uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest */
	uint32_t Length_Low; /* Message length in bits */
	uint32_t Length_High; /* Message length in bits */
	/* Index into message block array */
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[64]; /* 512-bit message blocks */
	int Computed; /* Is the digest computed? */
	int Corrupted; /* Is the message digest corrupted? */
} SHA1Context;


/*
* Function Prototypes
*/
#ifdef __cplusplus
extern "C" {
#endif//
int SHA1Reset( SHA1Context *);
int SHA1Input( SHA1Context *,
	const uint8_t *,
	unsigned int);
int SHA1Result( SHA1Context *,
	uint8_t Message_Digest[SHA1HashSize]);

#ifdef __cplusplus
}
#endif//__cplusplus


#endif

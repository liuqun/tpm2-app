/* encoding: utf-8 */
/// @file SM3.cpp
/// @details 国密 SM3 哈希算法的 C 底层实现
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

/**
 * Portable issues: ISO C98 <stdint.h>
 */
#if (defined(_MSC_VER) && (_MSC_VER < 1600))
#warning "On Win32/Win64 platform, we recommend Microsoft Visual Studio 2010 or higher version."
#warning "Otherwise the ISO C98 <stdint.h> will not be available to you."
#endif

#include <stdint.h>
#include <cstdlib>
#include <cstring> // using standard C functions: memset() / memcpy()

/**
 * Portable issues: htonl() / ntohl()
 */
#if !defined(htonl) || !defined(ntohl)
static uint32_t htonl(uint32_t hostEndian); // Standard "host endian to net endian (big-endian)" byte order converter
static uint32_t ntohl(uint32_t bigEndian); // Standard "net endian to host endian" byte order converter
#endif

#include "SM3.h"

/** SM3 哈希摘要的尺寸(单位:字节) */
#define SM3_DIGEST_LENGTH	SM3HashDigestSize

/** 单个数据分组的尺寸(单位:字节) */
#define SM3_BLOCK_SIZE		64

/**
 * 内部上下文结构体
 */
struct _sm3_ctx_t {
	uint32_t Intermediate_Hash[SM3_DIGEST_LENGTH / sizeof(uint32_t)]; ///< Message Digest (Always stored in localhost's endian format)
	uint64_t nBits; ///< Total input bits received
	/** Index into message block array */
	int Message_Block_Index; // 内部实现细节:
	// 此处通过定义int型的Message_Block_Index强制将Message_Block[64]进行主机字对齐(对齐8字节或4字节),
	// 子函数访问64字节数据块时按整字(8字节或4字节)访问可以加快读写速度
	uint8_t Message_Block[SM3_BLOCK_SIZE]; ///< 512-bit message blocks, @see SM3_BLOCK_SIZE
	int Computed; ///< Is the digest computed?
};

// ===========================================================================
// SM3 上下文的创建和释放(C 语言 API 接口)
// ===========================================================================

SM3Context *SM3CreateNewContext()
{
	SM3Context *context;

	context = (SM3Context *) malloc(sizeof(SM3Context));
	SM3Reset(context); // 默认自动执行一次复位清零
	return context;
}

void SM3DeleteContext(SM3Context *context)
{
	free(context);
}

// ===========================================================================
// 以下内容为 SM3 哈希算法的 C 语言底层实现
// ===========================================================================

/*
 * SM3 哈希算法的一个 C 语言实现
 *
 * Description:
 *
 * Portability Issues:
 * SM3 (like SHA-1) algorithm is defined in terms of 32-bit "words". This code uses <stdint.h> to define 32 and 8 bit unsigned integer types. If your C compiler does not support 32 bit unsigned integers, this code is not appropriate.
 */

/* Local Function Prototyptes */
#if !defined(htonl) || !defined(ntohl)
static uint32_t htonl(uint32_t hostEndian); // Standard "host endian to net endian(big-endian)" byte order converter
static uint32_t ntohl(uint32_t bigEndian); // Standard "net endian to host endian" byte order converter
#endif
static void SM3PadMessage(SM3Context *);
static void SM3ProcessMessageBlock(uint32_t Intermediate_Hash[8], const uint8_t Message_Block[64]);

/**
 * SM3 上下文内容清零复位
 *
 * @details:
 * This function will initialize the SM3Context in preparation
 * for computing a new SM3 message digest.
 *
 * @param context SM3 哈希上下文指针
 *
 * @return
 * The following error code:
 * - SM3Null on pointer error (NULL context pointer detected)
 * - SM3Success when everything is ok
 */
int SM3Reset(SM3Context *context) {
	if (!context) {
		return SM3Null;
	}
	context->nBits = 0;
	context->Message_Block_Index = 0;
	context->Intermediate_Hash[0] = ntohl(0x6F168073);
	context->Intermediate_Hash[1] = ntohl(0xB9B21449);
	context->Intermediate_Hash[2] = ntohl(0xD7422417);
	context->Intermediate_Hash[3] = ntohl(0x00068ADA);
	context->Intermediate_Hash[4] = ntohl(0xBC306FA9);
	context->Intermediate_Hash[5] = ntohl(0xAA383116);
	context->Intermediate_Hash[6] = ntohl(0x4DEE8DE3);
	context->Intermediate_Hash[7] = ntohl(0x4E0EFBB0);
	context->Computed = 0;
	return SM3Success;
}

/*
 * 完成最后一个64字节数据分组的哈希计算并取回最终 SM3 哈希摘要结果
 *
 * Description:
 * This function will return the 256-bit message digest into the
 * Message_Digest array provided by the caller.
 *
 * Parameters:
 * 参见 C 语言头文件中的声明
 *
 * @return
 * The following error code:
 * - SM3Success on success
 * - SM3Null when one of the input parameters is a NULL pointer
 */
int SM3Result(SM3Context *context, uint8_t Message_Digest[]) {
	uint32_t bigEndian[SM3_DIGEST_LENGTH / sizeof(uint32_t)]; // 存储转换回网络字节序的哈希运算结果
	int i;
	if (!context || !Message_Digest) {
		return SM3Null;
	}
	if (!context->Computed) {
		SM3PadMessage(context);
		for (i = 0; i < 64; ++i) {
			/* message may be sensitive, clear it out */
			context->Message_Block[i] = 0;
		}
		context->nBits = 0; /* clear total input data bit counter */
		context->Computed = 1;
	}
	for (i = 0; i < (SM3_DIGEST_LENGTH / sizeof(uint32_t)); i++) {
		bigEndian[i] = htonl(context->Intermediate_Hash[i]);
	}
	memcpy(Message_Digest, (void *)bigEndian, SM3_DIGEST_LENGTH);
	return SM3Success;
}

/*
 * 输入任意长度数据
 *
 * Description:
 * 将任意长度的输入数据拆分为若干个 64 字节的数据分组依次进行 SM3 压缩
 *
 * Return code:
 * - SM3Success on success or when length == 0
 * - SM3Null when one of the input parameters is a NULL pointer
 * - SM3StateError if this function is called unexpectedly after another SM3Result()
 */
int SM3Input(SM3Context *context, ///< 上下文指针
		const uint8_t message_array[], ///< 数据
		unsigned int length ///< 数据长度
		) {
	if (!length) {
		return SM3Success;
	}
	if (!context || !message_array) {
		return SM3Null;
	}
	if (context->Computed) {
		return (SM3StateError);
	}
	while (length--) {
		context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);
		context->nBits += 8; /* clear length */
		if (context->Message_Block_Index == SM3_BLOCK_SIZE) {
			SM3ProcessMessageBlock(context->Intermediate_Hash, context->Message_Block);
			context->Message_Block_Index = 0;
		}
		message_array++;
	}
	return SM3Success;
}

/*
 * SM3PadMessage
 *
 * Description:
 * TODO: (ADD IMPLEMENTATION DETAIL DESCRIPTIONS HERE)
 *
 * Parameters:
 * TODO: (ADD IMPLEMENTATION DETAIL DESCRIPTIONS HERE)
 */
void SM3PadMessage(SM3Context *context) {
	/*
	 * Check to see if the current message block is too small to hold
	 * the initial padding bits and length. If so, we will pad the
	 * block, process it, and then continue padding into a second
	 * block.
	 */
	if (context->Message_Block_Index >= (SM3_BLOCK_SIZE - sizeof(uint64_t))) {
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < SM3_BLOCK_SIZE) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
		SM3ProcessMessageBlock(context->Intermediate_Hash, context->Message_Block);
		context->Message_Block_Index = 0;
		while (context->Message_Block_Index < (SM3_BLOCK_SIZE - sizeof(uint64_t))) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	} else {
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < (SM3_BLOCK_SIZE - sizeof(uint64_t))) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	/*
	 * Store the message length as the last 8 octets
	 */
	context->Message_Block[SM3_BLOCK_SIZE - 8] = (uint8_t) (context->nBits >> 56);
	context->Message_Block[SM3_BLOCK_SIZE - 7] = (uint8_t) (context->nBits >> 48);
	context->Message_Block[SM3_BLOCK_SIZE - 6] = (uint8_t) (context->nBits >> 40);
	context->Message_Block[SM3_BLOCK_SIZE - 5] = (uint8_t) (context->nBits >> 32);
	context->Message_Block[SM3_BLOCK_SIZE - 4] = (uint8_t) (context->nBits >> 24);
	context->Message_Block[SM3_BLOCK_SIZE - 3] = (uint8_t) (context->nBits >> 16);
	context->Message_Block[SM3_BLOCK_SIZE - 2] = (uint8_t) (context->nBits >> 8);
	context->Message_Block[SM3_BLOCK_SIZE - 1] = (uint8_t) (context->nBits);
	SM3ProcessMessageBlock(context->Intermediate_Hash, context->Message_Block);
	context->Message_Block_Index = 0;
}

/**
 * 宏定义
 *
 * 模拟寄存器循环左移指令
 */
#define SM3CircularShift(bits,word) \
	(((word) << (bits)) | ((word) >> (32-(bits))))

/**
 * P0 组合运算符定义
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
inline uint32_t P0(uint32_t x) {
	return (x ^ SM3CircularShift(9, x) ^ SM3CircularShift(17, x));
}

/**
 * P1 组合运算符定义
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
inline uint32_t P1(uint32_t x) {
	return (x ^ SM3CircularShift(15, x) ^ SM3CircularShift(23, x));
}

/**
 * 3变量异或运算符定义
 */
inline uint32_t XOR_3_VARIABLES(uint32_t x, uint32_t y, uint32_t z) {
	return (x ^ y ^ z);
}

/**
 * FF0: 3变量异或运算符定义
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) {
	return (x ^ y ^ z);
}

/**
 * FF1: 3变量组合逻辑运算符定义
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
	return ((x & y) | (y & z) | (z & x));
}

/**
 * GG0: 3变量异或运算符定义
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) {
	return (x ^ y ^ z);
}

/**
 * GG1: 3变量组合逻辑运算符定义
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
	return ((x & y) | ((~x) & z));
}

/*
 * SM3ProcessMessageBlock
 *
 * @details
 * This function will process the next 512 bits of the message
 * stored in the Message_Block array.
 *
 * Parameters:
 * TODO: (ADD IMPLEMENTATION DETAIL DESCRIPTIONS HERE)
 *
 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
 * @see https://github.com/guanzhi/GmSSL/blob/master/crypto/sm3/sm3.c
 */
void SM3ProcessMessageBlock(uint32_t Intermediate_Hash[8], const uint8_t Message_Block[64]) {
	/**
	 * Constants defined in SM3 (Always stroed in localhost's endian format)
	 * @see 《GM/T 0004-2012 SM3密码杂凑算法》
	 */
	const uint32_t T[] = {
			ntohl(0x1945CC79), // 0x79CC4519 for little endian X86 CPU
			ntohl(0x8A9D877A), // 0x7A879D8A
			};
	int t; /* Loop counter */
	uint32_t SS0, SS1,SS2; /* Word buffers (Always stroed in localhost's endian format)*/
	uint32_t TT1,TT2; /* Temporary word value (Always stroed in localhost's endian format)*/
	uint32_t W[68]; /* Word sequence (Always stroed in localhost's endian format)*/
	uint32_t W1[64]; /* Word sequence (Always stroed in localhost's endian format)*/
	uint32_t A, B, C, D, E, F, G, H; /* Word buffers (Always stroed in localhost's endian format)*/

	/*
	 * Initialize the first 16 words in the array W
	 */
	uint32_t *p; // Pointer to a big endian uint32_t's memory address. Note: 此处要求 context->Message_Block[64] 必须是4字节对正的内存块 否则无法快速访问
	for (t = 0, p = (uint32_t *) (Message_Block); t < 16; t++, p++) {
		W[t] = ntohl(*p);
	}
	for (t = 16; t < sizeof(W)/sizeof(W[0]); t++) {
		uint32_t x = W[t - 16] ^ W[t - 9] ^ SM3CircularShift(15, W[t - 3]);
		W[t] = P1(x) ^ SM3CircularShift(7, W[t - 13]) ^ W[t - 6];
	}
	for (t = 0;  t < sizeof(W1)/sizeof(W1[0]); t++) {
		W1[t] = W[t] ^ W[t + 4];
	}
	A = Intermediate_Hash[0];
	B = Intermediate_Hash[1];
	C = Intermediate_Hash[2];
	D = Intermediate_Hash[3];
	E = Intermediate_Hash[4];
	F = Intermediate_Hash[5];
	G = Intermediate_Hash[6];
	H = Intermediate_Hash[7];
	for (t = 0; t < 16; t++) {
		SS0 = SM3CircularShift(12, A) + E + SM3CircularShift(t, T[0]);
		SS1 = SM3CircularShift(7, SS0);
		SS2 = SS1 ^ SM3CircularShift(12, A);
		TT1 = FF0(A, B, C) + D + SS2 + W1[t];
		TT2 = GG0(E, F, G) + H + SS1 + W[t];
		D = C;
		C = SM3CircularShift(9, B);
		B = A;
		A = TT1;
		H = G;
		G = SM3CircularShift(19, F);
		F = E;
		E = P0(TT2);
	}
	for (t = 16; t < 64; t++) {
		SS0 = SM3CircularShift(12, A) + E + SM3CircularShift(t, T[1]);
		SS1 = SM3CircularShift(7, SS0);
		SS2 = SS1 ^ SM3CircularShift(12, A);
		TT1 = FF1(A, B, C) + D + SS2 + W1[t];
		TT2 = GG1(E, F, G) + H + SS1 + W[t];
		D = C;
		C = SM3CircularShift(9, B);
		B = A;
		A = TT1;
		H = G;
		G = SM3CircularShift(19, F);
		F = E;
		E = P0(TT2);
	}
	Intermediate_Hash[0] ^= A;
	Intermediate_Hash[1] ^= B;
	Intermediate_Hash[2] ^= C;
	Intermediate_Hash[3] ^= D;
	Intermediate_Hash[4] ^= E;
	Intermediate_Hash[5] ^= F;
	Intermediate_Hash[6] ^= G;
	Intermediate_Hash[7] ^= H;
}

// ===========================================================================
// 网络字节序-本机字节序转换
// ===========================================================================

#if defined(HAVE_ARPA_INET_H) || defined(HAVE_WINSOCK2_H)
# if defined(_WIN32)
#  include <winsock2.h> // Windows winsock2.h provides htonl()
# else
#  include <arpa/inet.h> // Unix htonl()
# endif
#else

/**
 * @brief 本机字节序转为网络字节序
 * @param 输入任意本机字节序格式的 32 位无符号整数
 * @return 符合网络字节序(大尾端)格式的 32 位无符号整数
 */
inline
uint32_t htonl(uint32_t x) {
	uint32_t bigEndian;
	uint8_t *v;

	v = (uint8_t *) &bigEndian;
	v[0] = (uint8_t) (x >> 24);
	v[1] = (uint8_t) ((x >> 16) & 0xFF);
	v[2] = (uint8_t) ((x >> 8) & 0xFF);
	v[3] = (uint8_t) (x & 0xFF);
	return (bigEndian);
}

/**
 * @brief 网络字节序转为本机字节序
 * @param bigEndian 输入任意网络字节序(大尾端)格式的 32 位无符号整数
 * @return 表示本机字节序 32 位无符号整数
 */
inline
uint32_t ntohl(uint32_t bigEndian) {
	uint8_t *v;

	v = (uint8_t *) &bigEndian;
	return (
		(((uint32_t) v[0]) << 24) |
		(((uint32_t) v[1]) << 16) |
		(((uint32_t) v[2]) << 8) |
		v[3]
		);
}
#endif

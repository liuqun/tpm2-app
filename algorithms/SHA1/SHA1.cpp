#include <stdint.h>
#include <cassert>
#include <cstdlib>
#include <cstring> // using memset()

#include "SHA1.hpp"

/**
 * 内部结构体
 *
 * @note _SHA1Context 和 SHA1Context完全相同, 前缀带下划线的只在本文件内部使用
 */
struct _SHA1Context {
	uint32_t Intermediate_Hash[SHA1HashSize / 4]; ///< Message Digest (Always stored in localhost's endian format)
	uint32_t Length_Low; ///< Message length in bits (Always stored in localhost's endian format)
	uint32_t Length_High; ///< Message length in bits (Always stored in localhost's endian format)
	/** Index into message block array */
	int Message_Block_Index; // 内部实现细节:
	// 此处通过定义int型的Message_Block_Index强制将Message_Block[64]进行主机字对齐(对齐8字节或4字节),
	// 子函数访问64字节数据块时按整字(8字节或4字节)访问可以加快读写速度
	uint8_t Message_Block[64]; ///< 512-bit message blocks
	int Computed; ///< Is the digest computed?
	int Corrupted; ///< Is the message digest corrupted?
};

SHA1::SHA1() {
	this->context = new SHA1Context;
	assert(this->context);
	(void) SHA1Reset(this->context);
}

SHA1::~SHA1() {
	(void) SHA1Reset(this->context); // 退出之前再执行 Reset() 和 memset() 清除内部残留数据
	memset(this->context->Message_Block, 0x00, sizeof(this->context->Message_Block));
	delete this->context;
}

void SHA1::inputData(const uint8_t data[], ///< 输入数据
		unsigned int length ///< 输入数据长度
		) {
	int err;
	err = SHA1Input(this->context, data, length);
	if (err) {
		// TODO: 处理错误
	}
}

uint64_t SHA1::getTotalDataBits() {
	uint64_t total;

	total = this->context->Length_High;
	total <<= 32;
	total += this->context->Length_Low;
	return total;
}

void SHA1::inputEnd() {
	/* 结束数据输入: 当前的算法实现中此处无额外处理 */
}

void SHA1::getHashResult(uint8_t digest[SHA1HashSize]) {
	SHA1Context snapshot; // 保存上下文状态当前的一份 snapshot

#if defined(__GNUC__)
	snapshot = *(this->context); // 对结构体进行整体复制(需要 C++ 编译器支持)
#endif
#if !defined(__GNUC__)
	memcpy(snapshot.Intermediate_Hash, this->context->Intermediate_Hash, sizeof(snapshot.Intermediate_Hash));
	snapshot.Length_Low = this->context->Length_Low;
	snapshot.Length_High = this->context->Length_High;
	snapshot.Message_Block_Index = this->context->Message_Block_Index;
	memcpy(snapshot.Message_Block, this->context->Message_Block, this->context->Message_Block_Index);
	snapshot.Computed = this->context->Computed;
	snapshot.Corrupted = this->context->Corrupted;
#endif

	/* Note: 此处只对快照备份数据进行 padding 操作并生成摘要, 不会修改原始数据 */
	int err;
	err = SHA1Result(&snapshot, digest);
	(void) SHA1Reset(&snapshot); // 通过 Reset() 和 memset() 清除 snapshot 内部残留数据
	memset(snapshot.Message_Block, 0x00, sizeof(snapshot.Message_Block));
	if (err) {
		// TODO: 处理错误
	}
}

#if __cplusplus >= 201103L
void SHA1::getHashResult(std::array<uint8_t, SHA1HashSize>& digest) {
	getHashResult(digest.data());
}
#endif

void SHA1::reset() {
	(void) SHA1Reset(this->context);
}

// ===========================================================================
// SHA1 上下文的创建和释放(C 语言 API 接口)
// ===========================================================================

SHA1Context *SHA1CreateNewContext()
{
	SHA1Context *context;

	context = (SHA1Context *) malloc(sizeof(SHA1Context));
	SHA1Reset(context); // 默认自动执行一次复位清零
	return context;
}

void SHA1DeleteContext(SHA1Context *context)
{
	free(context);
}

// ===========================================================================
// 以下内容为 SHA1 哈希算法的 C 语言底层实现
// ===========================================================================

/*
* SHA1 哈希算法的一个 C 语言实现
*
* Description:
* This file implements the Secure Hashing Algorithm 1 as
* defined in FIPS PUB 180-1 published April 17, 1995.
*
* The SHA-1, produces a 160-bit message digest for a given
* data stream. It should take about 2**n steps to find a
* message with the same digest as a given message and
* 2**(n/2) to find any two messages with the same digest,
* when n is the digest size in bits. Therefore, this
* algorithm can serve as a means of providing a
* "fingerprint" for a message.
*
* Portability Issues:
* SHA-1 is defined in terms of 32-bit "words". This code
* uses <stdint.h> (included via "sha1.h" to define 32 and 8
* bit unsigned integer types. If your C compiler does not
* support 32 bit unsigned integers, this code is not
* appropriate.
*
* Caveats:
* SHA-1 is designed to work with messages less than 2^64 bits
* long. Although SHA-1 allows a message digest to be generated
* for messages of any number of bits less than 2^64, this
* implementation only works with messages with a length that is
* a multiple of the size of an 8-bit character.
*/

/* Local Function Prototyptes */
#if !defined(htonl) || !defined(ntohl)
static uint32_t htonl(uint32_t hostEndian); // Standard "host endian to net endian(big-endian)" byte order converter
static uint32_t ntohl(uint32_t bigEndian); // Standard "net endian to host endian" byte order converter
#endif
static void SHA1PadMessage(SHA1Context *);
static void SHA1ProcessMessageBlock(SHA1Context *);

/*
 * SHA1Reset
 *
 * Description:
 * This function will initialize the SHA1Context in preparation
 * for computing a new SHA1 message digest.
 *
 * Parameters:
 * context: [in/out]
 * The context to reset.
 *
 * Returns:
 * sha Error Code.
 *
 */
int SHA1Reset(SHA1Context *context) {
	if (!context) {
		return shaNull;
	}
	context->Length_Low = 0;
	context->Length_High = 0;
	context->Message_Block_Index = 0;
	context->Intermediate_Hash[0] = ntohl(0x01234567);
	context->Intermediate_Hash[1] = ntohl(0x89ABCDEF);
	context->Intermediate_Hash[2] = ntohl(0xFEDCBA98);
	context->Intermediate_Hash[3] = ntohl(0x76543210);
	context->Intermediate_Hash[4] = ntohl(0xF0E1D2C3);
	context->Computed = 0;
	context->Corrupted = 0;
	return shaSuccess;
}

/*
 * SHA1Result
 *
 * Description:
 * This function will return the 160-bit message digest into the
 * Message_Digest array provided by the caller.
 * NOTE: The first octet of hash is stored in the 0th element,
 * the last octet of hash in the 19th element.
 *
 * Parameters:
 * context: [in/out]
 * The context to use to calculate the SHA-1 hash.
 * Message_Digest: [out]
 * Where the digest is returned.
 *
 * Returns:
 * sha Error Code.
 *
 */
int SHA1Result(SHA1Context *context, uint8_t Message_Digest[SHA1HashSize]) {
	uint32_t bigEndian[5]; // 存储转换回网络字节序的哈希运算结果
	int i;
	if (!context || !Message_Digest) {
		return shaNull;
	}
	if (context->Corrupted) {
		return context->Corrupted;
	}
	if (!context->Computed) {
		SHA1PadMessage(context);
		for (i = 0; i < 64; ++i) {
			/* message may be sensitive, clear it out */
			context->Message_Block[i] = 0;
		}
		context->Length_Low = 0; /* and clear length */
		context->Length_High = 0;
		context->Computed = 1;
	}
	for (i = 0; i < 5; i++) {
		bigEndian[i] = htonl(context->Intermediate_Hash[i]);
	}
	memcpy(Message_Digest, (void *)bigEndian, SHA1HashSize);
	return shaSuccess;
}

/*
 * SHA1Input
 *
 * Description:
 * This function accepts an array of octets as the next portion
 * of the message.
 *
 * Parameters:
 * context: [in/out]
 * The SHA context to update
 * message_array: [in]
 * An array of characters representing the next portion of
 * the message.
 * length: [in]
 * The length of the message in message_array
 *
 * Returns:
 * sha Error Code.
 *
 */
int SHA1Input(SHA1Context *context, ///< 上下文指针
		const uint8_t message_array[], ///< 数据
		unsigned int length ///< 数据长度
		) {
	if (!length) {
		return shaSuccess;
	}
	if (!context || !message_array) {
		return shaNull;
	}
	if (context->Computed) {
		context->Corrupted = shaStateError;
		return shaStateError;
	}
	if (context->Corrupted) {
		return context->Corrupted;
	}
	while (length-- && !context->Corrupted) {
		context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);
		context->Length_Low += 8;
		if (context->Length_Low == 0) {
			context->Length_High++;
			if (context->Length_High == 0) {
				/* Message is too long */
				context->Corrupted = 1;
			}
		}
		if (context->Message_Block_Index == 64) {
			SHA1ProcessMessageBlock(context);
		}
		message_array++;
	}
	return shaSuccess;
}

/*
 * SHA1PadMessage
 *
 * Description:
 * According to the standard, the message must be padded to an even
 * 512 bits. The first padding bit must be a ’1’. The last 64
 * bits represent the length of the original message. All bits in
 * between should be 0. This function will pad the message
 * according to those rules by filling the Message_Block array
 * accordingly. It will also call the ProcessMessageBlock function
 * provided appropriately. When it returns, it can be assumed that
 * the message digest has been computed.
 *
 * Parameters:
 * context: [in/out]
 * The context to pad
 * ProcessMessageBlock: [in]
 * The appropriate SHA*ProcessMessageBlock function
 * Returns:
 * Nothing.
 *
 */
void SHA1PadMessage(SHA1Context *context) {
	/*
	 * Check to see if the current message block is too small to hold
	 * the initial padding bits and length. If so, we will pad the
	 * block, process it, and then continue padding into a second
	 * block.
	 */
	if (context->Message_Block_Index > 55) {
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 64) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
		SHA1ProcessMessageBlock(context);
		while (context->Message_Block_Index < 56) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	} else {
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 56) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	/*
	 * Store the message length as the last 8 octets
	 */
	context->Message_Block[56] = context->Length_High >> 24;
	context->Message_Block[57] = context->Length_High >> 16;
	context->Message_Block[58] = context->Length_High >> 8;
	context->Message_Block[59] = context->Length_High;
	context->Message_Block[60] = context->Length_Low >> 24;
	context->Message_Block[61] = context->Length_Low >> 16;
	context->Message_Block[62] = context->Length_Low >> 8;
	context->Message_Block[63] = context->Length_Low;
	SHA1ProcessMessageBlock(context);
}

/**
 * 宏定义
 * 模拟寄存器循环左移指令
 */
#define SHA1CircularShift(bits,word) \
	(((word) << (bits)) | ((word) >> (32-(bits))))

/*
 * SHA1ProcessMessageBlock
 *
 * Description:
 * This function will process the next 512 bits of the message
 * stored in the Message_Block array.
 *
 * Parameters:
 * None.
 *
 * Returns:
 * Nothing.
 *
 * Comments:
 * Many of the variable names in this code, especially the
 * single character names, were used because those were the
 * names used in the publication.
 *
 */
void SHA1ProcessMessageBlock(SHA1Context *context) {
	/** Constants defined in SHA-1 (Always stroed in localhost's endian format)*/
	const uint32_t K[] = {
			ntohl(0x9979825A), // =0x5A827999 for little endian CPU(e.g. x86)
			ntohl(0xA1EBD96E), // =0x6ED9EBA1 for little endian CPU
			ntohl(0xDCBC1B8F), // =0x8F1BBCDC for little endian CPU
			ntohl(0xD6C162CA), // =0xCA62C1D6 for little endian CPU
			};
	int t; /* Loop counter */
	uint32_t temp; /* Temporary word value (Always stroed in localhost's endian format)*/
	uint32_t W[80]; /* Word sequence (Always stroed in localhost's endian format)*/
	uint32_t A, B, C, D, E; /* Word buffers (Always stroed in localhost's endian format)*/
	/*
	 * Initialize the first 16 words in the array W
	 */
	uint32_t *p; // Pointer to a big endian uint32_t's memory address. Note: 此处要求 context->Message_Block[64] 必须是4字节对正的内存块 否则无法快速访问
	for (t = 0, p = (uint32_t *) (context->Message_Block); t < 16; t++, p++) {
		W[t] = ntohl(*p);
	}
	for (t = 16; t < 80; t++) {
		W[t] = SHA1CircularShift(1, (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]));
	}
	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];
	for (t = 0; t < 20; t++) {
		temp = SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}
	for (t = 20; t < 40; t++) {
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}
	for (t = 40; t < 60; t++) {
		temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}
	for (t = 60; t < 80; t++) {
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}
	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;
	context->Message_Block_Index = 0;
}

/**
 * @note 上述 SHA1 哈希算法的实现代码与 RFC3174 中的样例代码基本一致
 * @see https://tools.ietf.org/html/rfc3174
 */

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

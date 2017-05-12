/**
* @file SHA1.hpp
* @brief SHA1 哈希算法 C++ 语言头文件
*
* @note 关于 SHA1 哈希算法的详细描述请查阅 RFC3174
* @see https://tools.ietf.org/html/rfc3174
*
* 库函数调用方法请参考相应目录下的示例程序:
* @example example.cpp 是一个 C++ 语言示例程序
*/

#ifndef _SHA1_HPP_
#define _SHA1_HPP_

#ifndef __cplusplus
#error "This header is only for C++"
#endif

#include "SHA1.h"
#include <stdint.h>
#if __cplusplus >= 201103L
#include <array> /// @note 使用 std::array<uint8_t, 20> 需要 C++ 编译器支持 -std=c++11 选项并且 __cplusplus >= 201103L
#endif // __cplusplus >= 201103L

/**
 * @class SHA1
 * @brief 面向对象的 SHA1 哈希摘要计算器 API
 * @note 具体使用方法请参考以下示例程序:
 * @example example.cpp 是一个 C++ 示例程序, 参考该示例程序可以了解本 API 使用的方法
 */
class SHA1 {
private:
	SHA1Context *context;

public:
	/** 构造函数 */
	SHA1();

	/** 析构函数 */
	~SHA1();

	/** 输入数据 */
	void inputData(const uint8_t data[], ///< 输入数据
			unsigned int length ///< 输入数据长度
			);

	/**
	 * 查询累计输入数据的比特数
	 *
	 * @return 累计输入数据总比特数. (注: 8比特=1字节)
	 */
	uint64_t getTotalDataBits();

	/**
	 * 结束输入
	 *
	 * @details This method function is designed as to send an input end signal
	 * to confirm that all the data has been inputted. But implementations may
	 * just ignore this signal.
	 */
	void inputEnd();

	/** 取出哈希摘要结果 */
	void getHashResult(uint8_t digest[SHA1HashSize] ///< 输出 SHA1 摘要. 调用者需预先分配足够容纳 SHA1HashSize=20 字节的空间
			);
	#if __cplusplus >= 201103L
	void getHashResult(std::array<uint8_t, SHA1HashSize>& digest///< 输出 SHA1 摘要
			);
	#endif

	/** 清除当前运算结果和所有中间数据 */
	void reset();
};

#endif//_SHA1_HPP_

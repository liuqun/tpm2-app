/*
 * example.cpp
 *
 * Description:
 * 使用 C++ API 接口进行 SHA1 运算的示例程序
 *
 * Portability Issues:
 * 调用 std::array<uint8_t, 20> 需要 C++ 编译器支持 -std=c++11 选项
 * 并且 __cplusplus >= 201103L
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "SHA1.hpp"

const char *testarray[3] = {
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"0123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567",
};

const char *strCorrectSHA1Result[3] = {
	"A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
	"84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
	"DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52",
};

int main()
{
	SHA1 calc; // SHA1 Hash calculator object

	/*
	 * Perform some SHA-1 tests
	 */
	for (int j = 0; j < 3; j++)
	{
		std::array<uint8_t, SHA1HashSize> Message_Digest;

		calc.reset();

		calc.inputData((unsigned char *) testarray[j],
				strlen(testarray[j]));
		calc.inputEnd();
		calc.getHashResult(Message_Digest);

		printf("[Test-%d]\n", j + 1);
		printf("Origin message testarray[%d]: \"%s\"\n", j, testarray[j]);
		printf("SHA1 digest:\n");
		for (unsigned i = 0; i < Message_Digest.size(); ++i)
		{
			printf("%02X ", Message_Digest[i]);
		}
		printf("\n");

		printf("Should match:\n");
		printf("%s\n", strCorrectSHA1Result[j]);
		printf("\n");
		printf("\n");
	}

	return 0;
}


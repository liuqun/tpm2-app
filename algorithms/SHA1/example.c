/*
 * example.c
 *
 * Description:
 * This file will exercise the SHA-1 code performing the three
 * tests documented in FIPS PUB 180-1 plus one which calls
 * SHA1Input with an exact multiple of 512 bits, plus a few
 * error test checks.
 *
 * Portability Issues:
 * None.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "SHA1.h"

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
	SHA1Context *pContext;
	pContext = SHA1CreateNewContext();

	/*
	 * Perform some SHA-1 tests
	 */
	for (int j = 0; j < 3; j++)
	{
		uint8_t Message_Digest[20];

		SHA1Reset(pContext);

		SHA1Input(pContext, (unsigned char *) testarray[j],
				strlen(testarray[j]));

		SHA1Result(pContext, Message_Digest);

		printf("[Test-%d]\n", j + 1);
		printf("Origin message testarray[%d]: \"%s\"\n", j, testarray[j]);
		printf("SHA1 digest:\n");
		for (int i = 0; i < 20; ++i)
		{
			printf("%02X ", Message_Digest[i]);
		}
		printf("\n");

		printf("Should match:\n");
		printf("%s\n", strCorrectSHA1Result[j]);
		printf("\n");
		printf("\n");
	}

	SHA1DeleteContext(pContext);
	return 0;
}

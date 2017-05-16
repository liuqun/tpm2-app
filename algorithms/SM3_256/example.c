/*
 * example.c
 *
 * Description:
 *
 * Portability Issues:
 * <stdint.h> is only supported by GCC and _MSC_VER>=1600 (Microsoft Visual Studio 2010 or later)
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "SM3.h"

const char *testarray[3] = {
	"abc",
	"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
};

const char *strCorrectSM3Result[3] = {
	"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
};

int main()
{
	SM3Context *pContext;
	pContext = SM3CreateNewContext();

	/*
	 * Perform some SM3 tests
	 */
	for (int j = 0; j <= 1; j++)
	{
		uint8_t Message_Digest[SM3HashDigestSize];

		SM3Reset(pContext);

		SM3Input(pContext, (unsigned char *) testarray[j],
				strlen(testarray[j]));

		SM3Result(pContext, Message_Digest);

		printf("[Test-%d]\n", j + 1);
		printf("Origin message testarray[%d]: \"%s\"\n", j, testarray[j]);
		printf("SM3 digest:\n");
		for (int i = 0; i < SM3HashDigestSize; ++i)
		{
			printf("%02X", Message_Digest[i]);
		}
		printf("\n");

		printf("Should match:\n");
		printf("%s\n", strCorrectSM3Result[j]);
		printf("\n");
		printf("\n");
	}

	SM3DeleteContext(pContext);
	return 0;
}

/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.
#ifndef TEST_CASE_H_
#define TEST_CASE_H_

#ifdef __cplusplus

namespace TestCase {

void HashingShortMessageWithin1024Bytes(const char *hostname="127.0.0.1", unsigned int port=2323);
void HashingLongMessageMoreThan1024Bytes(const char *hostname="127.0.0.1", unsigned int port=2323);
void SigningAndSignatureVerification(const char *hostname="127.0.0.1", unsigned int port=2323);

namespace HMAC {
void RFC2202TestCasesForHMACSHA1(const char *hostname="127.0.0.1", unsigned int port=2323);
void MyTestCaseForHMACSHA1UsingTPMProtectedHMACKey(const char *hostname="127.0.0.1", unsigned int port=2323);
}// end of namespace HMAC

}

#endif//__cplusplus

#endif//TEST_CASE_H_

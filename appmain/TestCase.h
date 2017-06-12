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

}

#endif//__cplusplus

#endif//TEST_CASE_H_

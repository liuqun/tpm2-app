/// @file undocumented_types.h
///
/// @warning This file is written for doxygen tools only! Please don't include
/// this header file in your C/C++ code!
///
/// @brief Detailed informations for several TPM2B_* structure definitions
///
/// @details In <sapi/tpmb.h>, the upstream maintainers provided the following
/// micros to build their TPM2B_*
/// structures:
/// ```
/// #define TPM2B_TYPE(name, bytes)  \
///     typedef union {              \
///     struct  {                    \
///         UINT16  size;            \
///         BYTE    buffer[(bytes)]; \
///     } t;                         \
///     TPM2B   b;                   \
///     } TPM2B_##name
///
/// #define TPM2B_TYPE1(name, bytes, bufferName) \
///     typedef union {                          \
///     struct  {                                \
///         UINT16  size;                        \
///         BYTE    bufferName[(bytes)];         \
///     } t;                                     \
///     TPM2B   b;                               \
///     } TPM2B_##name
///
/// #define TPM2B_TYPE2(name, type, bufferName ) \
///     typedef union {                          \
///     struct  {                                \
///         UINT16  size;                        \
///         type bufferName;                     \
///     } t;                                     \
///     TPM2B   b;                               \
///     } TPM2B_##name
/// ```
/// Unfortunately, doxygen (and most C/C++ IDE's) could not understand these
/// code tricks. I decided to fix those broken structure references by hand,
/// before anyone could give a better solution.
///
/// @see TPM2B_TYPE
/// @see TPM2B_TYPE1
/// @see TPM2B_TYPE2

/*
 * TPM2B_* structure detailed definitions (coded by hand).
 */

/**
 * TPM 2.0 digest structure (with a UINT16 size indicator)
 *
 * ```
 * // Sample code showing the usage of TPM2B_DIGEST structure and its members
 * #include <string.h>
 * #include <sapi/tpm20.h>
 *
 * void foobar() {
 *     TPM2B_DIGEST sha1digest;
 *
 *     sha1digest.t.size = SHA1_DIGEST_SIZE;
 *     memset(sha1digest.t.buffer, 0x00, SHA1_DIGEST_SIZE); // clear data
 * }
 * ```
 * @details
 * This structure is designed as a scalable-sized buffer.
 *
 * @throws IndexOutOfBoundsException: Size indicator should NEVER be set larger
 * than the longest digest length produced by each implemented hash algorithm.
 * The max buffer size may be  64, 48, 32 or even only 20 bytes, which depends
 * on the actual size of TPMU_HA inside the libsapi's binary distribution.
 *
 * @see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ,
 * Chapter 10.4.2
 * Table 73: Definition of TPM2B_DIGEST Structure
 */
typedef union {
    struct {
        UINT16 size;
        BYTE buffer[sizeof(TPMU_HA)];
    } t;
    TPM2B b;
} TPM2B_DIGEST;

/**
 * TPM 2.0 key creation private data storage structure
 * (with a UINT16 size indicator)
 *
 * ```
 * // C++ pseudo-code showing the usage of TPM2B_PRIVATE
 *
 * TPM2B_PRIVATE outPrivate;
 *
 * // Call Tss2_Sys_Create()
 * Tss2_Sys_Create(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inSensitive,
 *     &inPublic,
 *     &outsideInfo,
 *     &creationPCR,
 *     &outPrivate, // Here TPM2B_PRIVATE is used as output parameter
 *     &outPublic,
 *     &creationData,
 *     &creationHash,
 *     &creationTicket,
 *     &rspAuthsArray
 *     );
 *
 * TPM2B_PRIVATE& inPrivate = outPrivate; // C++ coding syntax
 *
 * // Call Tss2_Sys_Load()
 * Tss2_Sys_Load(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inPrivate, // Here TPM2B_PRIVATE is used as input parameter
 *     &inPublic,
 *     &keyHandle,
 *     &keyName,
 *     &rspAuthsArray
 *     );
 * ```
 * @details
 * This structure is designed as a scalable-sized buffer.
 *
 * @see _PRIVATE
 *
 * @see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ,
 * Chapter 12.3.7
 * Table 191: Definition of TPM2B_PRIVATE Structure
 */
typedef union {
    struct {
        UINT16 size;
        BYTE buffer[sizeof(_PRIVATE)];
    } t;
    TPM2B b;
} TPM2B_PRIVATE;


/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Written on May 30, 2024
 * Contact: develop@qrcs.ca
 */

#ifndef RHX_UTILS_H
#define RHX_UTILS_H

#include "common.h"
#include <stdio.h>
#include <time.h>
#if defined(SYSTEM_OS_WINDOWS)
#	include <Windows.h>
#   if defined(SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "advapi32.lib")
#   endif
#else
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <errno.h>
#	include <fcntl.h>
#	include <limits.h>
#	include <stdlib.h>
#	include <stdio.h>
#	include <sys/types.h>
#	include <unistd.h>
#	if !defined(O_NOCTTY)
#		define O_NOCTTY 0
#	endif
#endif
#if defined(SYSTEM_OS_WINDOWS)
#	include <direct.h>
#	include <io.h>
#else
#	include <unistd.h>
#	include <stdlib.h>
#endif
#if defined(__OpenBSD__) || defined(__CloudABI__) || defined(__wasi__)
#	define HAVE_SAFE_ARC4RANDOM
#endif

/*!
* \def HKDS_STRINGUTILS_TOKEN_NOT_FOUND
* \brief The search token was not found
*/
#define UTILS_TOKEN_NOT_FOUND -1

/*!
* \def UTILS_STRING_MAX_LEN
* \brief The string maximum length
*/
#define UTILS_STRING_MAX_LEN 4096

/*!
* \def UTILS_CPUIDEX_SERIAL_SIZE
* \brief The CPU serial number length
*/
#define UTILS_CPUIDEX_SERIAL_SIZE 12

/*!
* \def UTILS_CPUIDEX_VENDOR_SIZE
* \brief The CPU vendor name length
*/
#if defined(SYSTEM_OS_APPLE) && defined(SYSTEM_COMPILER_GCC)
#	define UTILS_CPUIDEX_VENDOR_SIZE 32
#else
#	define UTILS_CPUIDEX_VENDOR_SIZE 12
#endif

/*!
* \enum utils_cpu_maker
* \brief The detectable CPU architectures
*/
typedef enum utils_cpu_maker
{
    hkds_cpuid_unknown = 0,                  /*!< The CPU type is unknown  */
    hkds_cpuid_amd = 1,                      /*!< The CPU type is AMD  */
    hkds_cpuid_intel = 2,                    /*!< The CPU type is Intel */
    hkds_cpuid_via = 3,                      /*!< The CPU type is VIA */
    hkds_cpuid_hygion = 4,                   /*!< The CPU type is Hygion */
} utils_cpu_maker;

/*!
* \struct utils_cpu_features
* \brief Contains the CPU feature availability
*/
RHX_EXPORT_API typedef struct utils_cpu_features
{
	bool adx;	                            	/*!< The ADX flag  */
    bool aesni;	                            	/*!< The AESNI flag  */
    bool pcmul;                             	/*!< The PCLMULQDQ flag */

    bool armv7;                                 /*!< ARMv7 cpu flag */
    bool neon;                                  /*!< Neon instructions flag */
    bool sha256;                                /*!< SHA2-256 flag */
    bool sha512;                                /*!< SHA2-512 flag */
    bool sha3;                                  /*!< SHA3 flag */

    bool avx;                               	/*!< The AVX flag */
    bool avx2;                              	/*!< The AVX2 flag */
    bool avx512f;                           	/*!< The AVX512F flag */
    bool hyperthread;                       	/*!< The hyper-thread flag */
    bool rdrand;                            	/*!< The RDRAND flag */
    bool rdtcsp;                            	/*!< The RDTCSP flag */

    uint32_t cacheline;                     	/*!< The number of cache lines */
    uint32_t cores;                         	/*!< The number of cores */
    uint32_t cpus;                          	/*!< The number of CPUs */
    uint32_t freqbase;                      	/*!< The frequency base */
    uint32_t freqmax;                       	/*!< The frequency maximum */
    uint32_t freqref;                       	/*!< The frequency reference */
    uint32_t l1cache;                       	/*!< The L1 cache size */
    uint32_t l1cacheline;                   	/*!< The L1 cache line size */
    uint32_t l2associative;                 	/*!< The L2 associative size */
    uint32_t l2cache;                       	/*!< The L2 cache size */
    char serial[UTILS_CPUIDEX_SERIAL_SIZE];   	/*!< The CPU serial number */
    char vendor[UTILS_CPUIDEX_VENDOR_SIZE];   	/*!< The CPU vendor name */
    utils_cpu_maker cputype;             	/*!< The CPU manufacturer */
} utils_cpu_features;

/*!
* \def HKDS_CSP_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
#define UTILS_SEED_MAX 1024000

/* file functions */

/**
* \brief Test to see if a file exists
*
* \param path: [const] The fully qualified path to the file
* \return Returns true if the file exists
*/
RHX_EXPORT_API bool utils_file_exists(const char* path);

/**
* \brief Reads a line of text from a formatted file.
*
* \warning line buffer must be freed after last call
*
* \param line: the line of text to read
* \param length: the buffer size
* \param fp: the file stream handle
* \return Returns the number of characters read
*/
RHX_EXPORT_API int64_t utils_file_getline(char** line, size_t* length, FILE* fp);

/**
* \brief Open a file and return the file pointer
*
* \param path: The filer path
* \param mode: The read, write, or read/write mode
* \param err: A pointer to an error variable
* \return Returns the FILE handle or NULL on failure
*/
RHX_EXPORT_API FILE*  utils_open_file(const char* path, const char* mode, errno_t* err);

/* pseudo-random generation */

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
RHX_EXPORT_API bool utils_seed_generate(uint8_t* output, size_t length);

/* cpuid */

/**
* \brief Get a list of supported CPU features
*
* \param features: A utils_cpu_features structure
* \return Returns true for success, false if CPU is not recognized
*/
RHX_EXPORT_API bool utils_cpu_features_set(utils_cpu_features* const features);

/* console functions */

/**
* \brief Convert a hexadecimal character string to a character byte array
*
* \param hexstr: [const] The string to convert
* \param output: The character output array
* \param length: The number of characters to convert
*/
RHX_EXPORT_API void utils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Print an array of characters to the console
*
* \param input: [const] The character array to print
*/
RHX_EXPORT_API void utils_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: [const] The character array to print
*/
RHX_EXPORT_API void utils_print_line(const char* input);

/* timer functions */

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
RHX_EXPORT_API uint64_t utils_stopwatch_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The time difference in milliseconds
*/
RHX_EXPORT_API uint64_t utils_stopwatch_elapsed(uint64_t start);

/* string functions */

/**
* \brief Find a substrings position within a string
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns the character position within the string, or HKDS_STRINGUTILS_TOKEN_NOT_FOUND if the string is not found
*/
RHX_EXPORT_API int64_t utils_find_string(const char* source, const char* token);

/**
* \brief Test if the string contains a substring
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns true if the substring is found
*/
RHX_EXPORT_API bool utils_string_contains(const char* source, const char* token);

/**
* \brief Get the character length of a string
*
* \param source: [const] The source string pointer
* \return Returns the size of the string
*/
RHX_EXPORT_API size_t utils_string_size(const char* source);

/**
* \brief Convert a string to all lower-case characters
*
* \param source: The string to convert to lower-case
*/
RHX_EXPORT_API void utils_string_to_lowercase(char* source);

/* memory functions */

/**
* \brief Erase a block of memory
*
* \param output: A pointer to the memory block to erase
* \param length: The number of bytes to erase
*/
RHX_EXPORT_API void utils_memory_clear(void* output, size_t length);


/**
* \brief Allocate a block of memory
*
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
RHX_EXPORT_API void* utils_memory_malloc(size_t length);

/**
* \brief Free a memory block created with alloc
*
* \param block: A pointer to the memory block to release
*/
RHX_EXPORT_API void utils_memory_alloc_free(void* block);

/**
* \brief Compare two byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
* \param length: The number of bytes to compare
*
* \return Returns if the arrays are equivalent
*/
RHX_EXPORT_API bool utils_memory_are_equal(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Compare two 16 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
RHX_EXPORT_API bool utils_memory_are_equal_128(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 32 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
RHX_EXPORT_API bool utils_memory_are_equal_256(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 64 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
RHX_EXPORT_API bool utils_memory_are_equal_512(const uint8_t* a, const uint8_t* b);

/**
* \brief Copy a block of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to copy
*/
RHX_EXPORT_API void utils_memory_copy(void* output, const void* input, size_t length);

/**
* \brief Bitwise XOR two blocks of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to XOR
*/
RHX_EXPORT_API void utils_memory_xor(uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief Bitwise XOR a block of memory with a byte value
*
* \param output: A pointer to the destination array
* \param value: A byte value
* \param length: The number of bytes to XOR
*/
RHX_EXPORT_API void utils_memory_xorv(uint8_t* output, const uint8_t value, size_t length);

/* integer functions */

/**
* \brief Convert a 16-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 16-bit integer
*/
RHX_EXPORT_API void utils_integer_be16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit big endian integer
*/
RHX_EXPORT_API uint32_t utils_integer_be8to32(const uint8_t* input);

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 32-bit integer
*/
RHX_EXPORT_API void utils_integer_be32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit big endian integer
*/
RHX_EXPORT_API uint64_t utils_integer_be8to64(const uint8_t* input);

/**
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 64-bit integer
*/
RHX_EXPORT_API void utils_integer_be64to8(uint8_t* output, uint64_t value);

/**
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: The destination integer 8-bit array
* \param otplen: The length of the output counter array
*/
RHX_EXPORT_API void utils_integer_be8increment(uint8_t* output, size_t otplen);

/**
* \brief Increment an 8-bit integer array as a segmented little-endian integer
*
* \param output: The source integer 8-bit array
* \param otplen: The length of the output counter array
*/
RHX_EXPORT_API void utils_integer_le8increment(uint8_t* output, size_t otplen);

#if defined(SYSTEM_HAS_AVX)
/**
* \brief Increment the low 64-bit integer of a little endian array by one
*
* \param counter: The counter vector
*/
RHX_EXPORT_API void utils_integer_leincrement_x128(__m128i* counter);
#endif

#if defined(SYSTEM_HAS_AVX512)
/**
* \brief Offset increment the low 64-bit integer of a set of 64-bit pairs of a little endian integers (ex. lo + 1,2,3,4)
*
* \param counter: The counter vector
*/
RHX_EXPORT_API void utils_integer_leincrement_x512(__m512i* counter);
#endif

/**
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 32-bit integer
*/
RHX_EXPORT_API void utils_integer_le32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit little endian integer
*/
RHX_EXPORT_API uint64_t utils_integer_le8to64(const uint8_t* input);

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 64-bit integer
*/
RHX_EXPORT_API void utils_integer_le64to8(uint8_t* output, uint64_t value);

/**
* \brief Return the smaller of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the smaller integer
*/
RHX_EXPORT_API size_t utils_integer_min(size_t a, size_t b);

/**
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
RHX_EXPORT_API uint64_t utils_integer_rotl64(uint64_t value, size_t shift);

#if defined(SYSTEM_HAS_AVX)
/**
* \brief Reverse a 128-bit array
*
* \param input: [const] The first 128-bit integer array
* \param output: The second 128-bit integer
*/
RHX_EXPORT_API void utils_integer_reverse_bytes_x128(const __m128i* input, __m128i* output);
#endif

#if defined(SYSTEM_HAS_AVX512)
/**
* \brief Reverse a 512-bit array
*
* \param input: [const] The first 512-bit integer array
* \param output: The second 512-bit integer
*/
RHX_EXPORT_API void utils_integer_reverse_bytes_x512(const __m512i* input, __m512i* output);

#endif
/**
* \brief Constant time comparison of two arrays of unsigned 8-bit integers
*
* \param a: [const] The first 8-bit integer array
* \param b: [const] The second 8-bit integer array
* \param length: The number of bytes to check
* \return Returns zero if the arrays are equivalent
*/
RHX_EXPORT_API int32_t utils_integer_verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
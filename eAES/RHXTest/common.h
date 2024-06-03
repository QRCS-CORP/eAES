
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
 * Updated on May 30, 2024
 * Contact: develop@qrcs.ca
 */

#ifndef RHX_COMMON_H
#define RHX_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>

/**
* \file common.h
* \brief This file contains common definitions
* \endcode
*/

/**
* \file common.h
* \brief global definitions and includes.
*/

/*!
\def SYSTEM_COMPILER_XXX
* \brief The identified compiler
*/
#if defined(_MSC_VER)
#	define SYSTEM_COMPILER_MSC
#elif defined(__MINGW32__)
#	define SYSTEM_COMPILER_MINGW
#	define SYSTEM_COMPILER_GCC
#elif defined(__CC_ARM)
#	define SYSTEM_COMPILER_ARM
#elif defined(__BORLANDC__)
#	define SYSTEM_COMPILER_BORLAND
#elif defined(__GNUC__)
#	define SYSTEM_COMPILER_GCC
#elif defined(__clang__)
#	define SYSTEM_COMPILER_CLANG
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	define SYSTEM_COMPILER_IBM
#elif defined(__INTEL_COMPILER) || defined(__ICL)
#	define SYSTEM_COMPILER_INTEL
#elif defined(__MWERKS__)
#	define SYSTEM_COMPILER_MWERKS
#elif defined(__OPEN64__)
#	define SYSTEM_COMPILER_OPEN64
#elif defined(__SUNPRO_C)
#	define SYSTEM_COMPILER_SUNPRO
#elif defined(__TURBOC__)
#	define SYSTEM_COMPILER_TURBO
#endif

/*!
\def SYSTEM_OS_XXX
* \brief The identified operating system
*/
#if defined(_WIN64) || defined(_WIN32) || defined(__WIN64__) || defined(__WIN32__)
#	if !defined(SYSTEM_OS_WINDOWS)
#		define SYSTEM_OS_WINDOWS
#	endif
#	if defined(_WIN64)
#		define SYSTEM_ISWIN64
#	elif defined(_WIN32)
#		define SYSTEM_ISWIN32
#	endif
#elif defined(__ANDROID__)
#	define SYSTEM_OS_ANDROID
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define SYSTEM_OS_APPLE
#	define SYSTEM_OS_BSD
#	if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
#		define SYSTEM_ISIPHONESIM
#	elif TARGET_OS_IPHONE
#		define SYSTEM_ISIPHONE
#	else
#		define SYSTEM_ISOSX
#	endif
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__) || defined(SYSTEM_ISOSX)
#	define SYSTEM_OS_BSD
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__ )
#	define SYSTEM_OS_LINUX
    typedef int errno_t;
#elif defined(__unix) || defined(__unix__)
#	define SYSTEM_OS_UNIX
#	if defined(__hpux) || defined(hpux)
#		define SYSTEM_OS_HPUX
#	endif
#	if defined(__sun__) || defined(__sun) || defined(sun)
#		define SYSTEM_OS_SUNUX
#	endif
#endif

#if defined(__posix) || defined(__posix__) || defined(__USE_POSIX) || defined(_POSIX_VERSION) || defined(SYSTEM_OS_APPLE)
    /*!
    \def SYSTEM_OS_POSIX
    * \brief The operating system is posix compliant
    */
#	define SYSTEM_OS_POSIX
#endif

#if defined(SYSTEM_OS_WINDOWS) && defined(SYSTEM_COMPILER_MSC)
    /*!
    \def SYSTEM_WINDOWS_VSTUDIO_BUILD
    * \brief The build is MSVC windows
    */
#   define SYSTEM_WINDOWS_VSTUDIO_BUILD
#endif

#if defined(_OPENMP)
#	define SYSTEM_OPENMP
#endif

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
    /*!
	\def SYSTEM_DEBUG_MODE
	* \brief The build is in bedug mode
	*/
#	define SYSTEM_DEBUG_MODE
#endif

/*!
\def SYSTEM_ARCH_XXX
* \brief The CPU architecture
*/
#if defined(SYSTEM_COMPILER_MSC)
#	if defined(_M_X64) || defined(_M_AMD64)
#		define SYSTEM_ARCH_IX86_64
#		define SYSTEM_ARCH_IX86
#		if defined(_M_AMD64)
#			define SYSTEM_ARCH_AMD64
#		endif
#	elif defined(_M_IX86) || defined(_X86_)
#		define SYSTEM_ARCH_IX86_32
#		define SYSTEM_ARCH_IX86
#	elif defined(_M_ARM)
#		define SYSTEM_ARCH_ARM
#		if defined(_M_ARM_ARMV7VE)
#			define SYSTEM_ARCH_ARMV7VE
#		elif defined(_M_ARM_FP)
#			define SYSTEM_ARCH_ARMFP
#		elif defined(_M_ARM64)
#			define SYSTEM_ARCH_ARM64
#		endif
#	elif defined(_M_IA64)
#		define SYSTEM_ARCH_IA64
#	endif
#elif defined(SYSTEM_COMPILER_GCC)
#	if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
#		define SYSTEM_ARCH_IX86_64
#		define SYSTEM_ARCH_IX86
#		if defined(_M_AMD64)
#			define SYSTEM_ARCH_AMD64
#		endif
#	elif defined(i386) || defined(__i386) || defined(__i386__)
#		define SYSTEM_ARCH_IX86_32
#		define SYSTEM_ARCH_IX86
#	elif defined(__arm__)
#		define SYSTEM_ARCH_ARM
#		if defined(__aarch64__)
#			define SYSTEM_ARCH_ARM64
#		endif
#	elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
#		define SYSTEM_ARCH_IA64
#	elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#		define SYSTEM_ARCH_PPC
#	elif defined(__sparc) || defined(__sparc__)
#		define SYSTEM_ARCH_SPARC
#		if defined(__sparc64__)
#			define SYSTEM_ARCH_SPARC64
#		endif
#	endif
#endif

#if defined(SYSTEM_COMPILER_MSC)
#	if defined(SYSTEM_ARCH_ARM)
#		include <arm_neon.h>
#	else
#		include <intrin.h>	/* Microsoft C/C++ compatible compiler */
#	endif
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#	include <x86intrin.h>	/* GCC-compatible compiler, targeting x86/x86-64 */
#elif defined(__GNUC__) && defined(__ARM_NEON__)
#	include <arm_neon.h>	/* GCC-compatible compiler, targeting ARM with NEON */
#elif defined(__GNUC__) && defined(__IWMMXT__)
#	include <mmintrin.h>	/* GCC-compatible compiler, targeting ARM with WMMX */
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
#	include <altivec.h>		/* XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX */
#elif defined(__GNUC__) && defined(__SPE__)
#	include <spe.h>			/* GCC-compatible compiler, targeting PowerPC with SPE */
#endif

/*!
\def SYSTEM_SOCKETS_XXX
* \brief The network sockets architecture
*/
#if defined(_WIN64) || defined(_WIN32) || defined(__CYGWIN__)
#	define SYSTEM_SOCKETS_WINDOWS
#else
#	define SYSTEM_SOCKETS_BERKELY
#endif

/*!
\def __attribute__
* \brief Assign an attribute
*/
#if !defined(__clang__) && !defined(__GNUC__)
#	ifdef __attribute__
#		undef __attribute__
#	endif
#	define __attribute__(a)
#endif

/*!
\def RHX_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define RHX_DLL_API
#endif
/*!
\def RHX_EXPORT_API
* \brief The api export prefix
*/
#if defined(RHX_DLL_API)
#	if defined(SYSTEM_COMPILER_MSC)
#		if defined(RHX_DLL_IMPORT)
#			define RHX_EXPORT_API __declspec(dllimport)
#		else
#			define RHX_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(SYSTEM_COMPILER_GCC)
#		if defined(RHX_DLL_IMPORT)
#		define RHX_EXPORT_API __attribute__((dllimport))
#		else
#		define RHX_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define RHX_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define RHX_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define RHX_EXPORT_API extern __declspec(dllexport)
#		else
#			define RHX_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define RHX_EXPORT_API
#endif

/*!
\def SYSTEM_CACHE_ALIGNED
* \brief The cache alignment
*/
#if defined(__GNUC__)
#	define SYSTEM_CACHE_ALIGNED __attribute__((aligned(64)))
#elif defined(_MSC_VER)
#	define SYSTEM_CACHE_ALIGNED __declspec(align(64))
#endif

#if defined(SYSTEM_ARCH_IX86_64) || defined(SYSTEM_ARCH_ARM64) || defined(SYSTEM_ARCH_IA64) || defined(SYSTEM_ARCH_AMD64) || defined(SYSTEM_ARCH_ARM64) || defined(SYSTEM_ARCH_SPARC64)
/*!
\def SYSTEM_IS_X64
* \brief The system is X64
*/
#	define SYSTEM_IS_X64
#else
/*!
\def SYSTEM_IS_X86
* \brief The system is X86
*/
#	define SYSTEM_IS_X86
#endif

/*!
\def SYSTEM_SIZE_MAX
* \brief The maximum system integer size
*/
#if defined(SYSTEM_IS_X64)
#	define SYSTEM_SIZE_MAX UINT64_MAX
#else
#	define SYSTEM_SIZE_MAX UINT32_MAX
#endif

/*!
\def SYSTEM_IS_LITTLE_ENDIAN
* \brief The system is little endian
*/
#define SYSTEM_IS_LITTLE_ENDIAN (((union { uint32_t x; uint8_t c; }){1}).c)

#if (!defined(SYSTEM_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || defined(__MWERKS__) && (!defined(__INTEL__))
		/*!
		\def SYSTEM_IS_BIG_ENDIAN
		* \brief The system is big endian
		*/
#		define SYSTEM_IS_BIG_ENDIAN
#	else
		/*!
		\def SYSTEM_IS_LITTLE_ENDIAN
		* \brief The system is little endian
		*/
#		define SYSTEM_IS_LITTLE_ENDIAN
#	endif
#endif

/*!
\def SYSTEM_ALIGN
* \brief Align an integer
*/
#if !defined(SYSTEM_ALIGN)
#	if defined(__GNUC__) || defined(__clang__)
#		define SYSTEM_ALIGN(x)  __attribute__((aligned(x)))
#	elif defined(_MSC_VER)
#		define SYSTEM_ALIGN(x)  __declspec(align(x))
#	else
#		define SYSTEM_ALIGN(x)
#	endif
#endif

/*!
\def uint128_t
* \brief 128-bit uint32_t integer support
*/
#if defined(__SIZEOF_INT128__) && defined(SYSTEM_IS_X64) && !defined(__xlc__) && ! defined(uint128_t)
#	define SYSTEM_NATIVE_UINT128
	/* Prefer TI mode over __int128 as GCC rejects the latter in pedantic mode */
#	if defined(__GNUC__) /* was __GNUG__? */
		typedef uint32_t uint128_t __attribute__((mode(TI)));
#	else
		typedef __int128 uint128_t;
#	endif
#endif

/*!
\def SYSTEM_FAST_64X64_MUL
* \brief Fast 64-bit integer multiplication
*/
#if defined(SYSTEM_NATIVE_UINT128)
#	define SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
      const uint128_t r = (uint128_t)(X) * Y;	\
      *High = (r >> 64) & 0xFFFFFFFFFFFFFFFFULL;			\
      *Low = (r) & 0xFFFFFFFFFFFFFFFFULL;					\
	} while(0)

#elif defined(SYSTEM_COMPILER_MSC) && defined(SYSTEM_IS_X64)
#	include <intrin.h>
#	pragma intrinsic(_umul128)
#	define SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
		*Low = _umul128(X, Y, High);						\
	} while(0)

#elif defined(SYSTEM_COMPILER_GCC)
#	if defined(SYSTEM_ARCH_IX86)
#		define SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("mulq %3" : "=d" (*High), "=X" (*Low) : "X" (X), "rm" (Y) : "cc");	\
		} while(0)
#	elif defined(SYSTEM_ARCH_ALPHA)
#		define SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("umulh %1,%2,%0" : "=r" (*High) : "r" (X), "r" (Y));				\
		*Low = X * Y;															\
		} while(0)
#	elif defined(SYSTEM_ARCH_IA64)
#		define SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("xmpy.hu %0=%1,%2" : "=f" (*High) : "f" (X), "f" (Y));				\
		*Low = X * Y;															\
		} while(0)
#	elif defined(SYSTEM_ARCH_PPC)
#		define SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("mulhdu %0,%1,%2" : "=r" (*High) : "r" (X), "r" (Y) : "cc");		\
		*Low = X * Y;															\
		} while(0)
#	endif
#endif

/*!
\def SYSTEM_MAX_PATH
* \brief The maximum path length
*/
#define SYSTEM_MAX_PATH 260

/*!
\def SYSTEM_OPTIMIZE_IGNORE
* \brief Compiler hint to stop optimizing code
*/
#if defined(SYSTEM_COMPILER_MSC)
#	define SYSTEM_OPTIMIZE_IGNORE __pragma(optimize("", off))
#elif defined(SYSTEM_COMPILER_GCC) || defined(SYSTEM_COMPILER_MINGW)
#if defined(__clang__)
#	define SYSTEM_OPTIMIZE_IGNORE __attribute__((optnone))
#else
#	define SYSTEM_OPTIMIZE_IGNORE __attribute__((optimize("O0")))
#endif
#elif defined(SYSTEM_COMPILER_CLANG)
#	define SYSTEM_OPTIMIZE_IGNORE __attribute__((optnone))
#elif defined(SYSTEM_COMPILER_INTEL)
#	define SYSTEM_OPTIMIZE_IGNORE pragma optimize("", off)
#else
#	define SYSTEM_OPTIMIZE_IGNORE
#endif

/*!
\def SYSTEM_OPTIMIZE_IGNORE
* \brief Compiler hint to continue optimizing code
*/
#if defined(SYSTEM_COMPILER_MSC)
#	define SYSTEM_OPTIMIZE_RESUME __pragma(optimize("", on))
#elif defined(SYSTEM_COMPILER_GCC) || defined(SYSTEM_COMPILER_MINGW)
#if defined(__clang__)
#	define SYSTEM_OPTIMIZE_RESUME
#else
#	define SYSTEM_OPTIMIZE_RESUME _Pragma("GCC diagnostic pop")
#endif
#elif defined(CEX_COMPILER_INTEL)
#	define SYSTEM_OPTIMIZE_RESUME pragma optimize("", on)
#else
#	define SYSTEM_OPTIMIZE_RESUME
#endif

/*!
\def SYSTEM_OPTIMIZE_IGNORE
* \brief Compiler hint to ignore a condition in code
*/
#if defined(SYSTEM_COMPILER_MSC)
#	define SYSTEM_CONDITION_IGNORE(x) __pragma(warning(disable : x))
#elif defined(SYSTEM_COMPILER_GCC) || defined(SYSTEM_COMPILER_MINGW)
#	define SYSTEM_CONDITION_IGNORE(x) _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wunused-parameter\"")
#elif defined(CEX_COMPILER_INTEL)
#	define SYSTEM_CONDITION_IGNORE(x)
#else
#	define SYSTEM_CONDITION_IGNORE(x)
#endif

/* intrinsics support level */

#if (_MSC_VER >= 1600)
	/*!
	\def SYSTEM_WMMINTRIN_H
	* \brief The CPU supports SIMD instructions
	*/
#	define SYSTEM_WMMINTRIN_H 1
#endif
#if (_MSC_VER >= 1700) && (defined(_M_X64))
	/*!
	\def SYSTEM_HAVE_AVX2INTRIN_H
	* \brief The CPU supports AVX2
	*/
#	define SYSTEM_HAVE_AVX2INTRIN_H 1
#endif

/*
* AVX512 Capabilities Check
* https://software.intel.com/en-us/intel-cplusplus-compiler-16.0-user-and-reference-guide
* https://software.intel.com/en-us/articles/compiling-for-the-intel-xeon-phi-processor-and-the-intel-avx-512-isa
* https://colfaxresearch.com/knl-avx512/
*
* #include <immintrin.h>
* supported is 1: ex. __AVX512CD__ 1
* F		__AVX512F__					Foundation
* CD	__AVX512CD__				Conflict Detection Instructions(CDI)
* ER	__AVX512ER__				Exponential and Reciprocal Instructions(ERI)
* PF	__AVX512PF__				Pre-fetch Instructions(PFI)
* DQ	__AVX512DQ__				Double-word and Quadword Instructions(DQ)
* BW	__AVX512BW__				Byte and Word Instructions(BW)
* VL	__AVX512VL__				Vector Length Extensions(VL)
* IFMA	__AVX512IFMA__				Integer Fused Multiply Add(IFMA)
* VBMI	__AVX512VBMI__				Vector Byte Manipulation Instructions(VBMI)
* VNNIW	__AVX5124VNNIW__			Vector instructions for deep learning enhanced word variable precision
* FMAPS	__AVX5124FMAPS__			Vector instructions for deep learning floating - point single precision
* VPOPCNT	__AVX512VPOPCNTDQ__		?
*
* Note: AVX512 is currently untested, this flag enables support on a compliant system
*/

/* Enable this define to support AVX512 on a compatible system */
/*#define CEX_AVX512_SUPPORTED*/

#if defined(__AVX512F__) && (__AVX512F__ == 1)
		/*!
		\def __AVX512__
		* \brief The system supports AVX512 instructions
		*/
#	include <immintrin.h>
#	if (!defined(__AVX512__))
#		define __AVX512__
#	endif
#endif

#if defined(__SSE2__)
	/*!
	\def SYSTEM_HAS_SSE2
	* \brief The system supports SSE2 instructions
	*/
#	define SYSTEM_HAS_SSE2
#endif

#if defined(__SSE3__)
	/*!
	\def SYSTEM_HAS_SSE3
	* \brief The system supports SSE3 instructions
	*/
#	define SYSTEM_HAS_SSE3
#endif

#if defined(__SSSE3__)
	/*!
	\def SYSTEM_HAS_SSSE3
	* \brief The system supports SSSE3 instructions
	*/
#	define SYSTEM_HAS_SSSE3
#endif

#if defined(__SSE4_1__)
	/*!
	\def SYSTEM_HAS_SSE41
	* \brief The system supports SSE41 instructions
	*/
#	define SYSTEM_HAS_SSE41
#endif

#if defined(__SSE4_2__)
	/*!
	\def SYSTEM_HAS_SSE42
	* \brief The system supports SSE42 instructions
	*/
#	define SYSTEM_HAS_SSE42
#endif

#if defined(__AVX__)
	/*!
	\def SYSTEM_HAS_AVX
	* \brief The system supports AVX instructions
	*/
#	define SYSTEM_HAS_AVX
#endif

#if defined(__AVX2__)
	/*!
	\def SYSTEM_HAS_AVX2
	* \brief The system supports AVX2 instructions
	*/
#	define SYSTEM_HAS_AVX2
#endif

#if defined(__AVX512__)
	/*!
	\def SYSTEM_HAS_AVX512
	* \brief The system supports AVX512 instructions
	*/
#	define SYSTEM_HAS_AVX512
#endif
#if defined(__XOP__)
#	define SYSTEM_HAS_XOP
#endif

#if defined(SYSTEM_HAS_AVX) || defined(SYSTEM_HAS_AVX2) || defined(SYSTEM_HAS_AVX512)
	/*!
	\def SYSTEM_AVX_INTRINSICS
	* \brief The system supports AVX instructions
	*/
#	define SYSTEM_AVX_INTRINSICS
#endif

/*!
*\def SYSTEM_ASM_ENABLED
* \brief Enables global ASM processing
*/
//#define SYSTEM_ASM_ENABLED

/*!
*\def SYSTEM_GCC_ASM_ENABLED
* \brief Enables GCC ASM processing
*/
#if defined(SYSTEM_AVX_INTRINSICS) && defined(SYSTEM_COMPILER_GCC) && defined(SYSTEM_ASM_ENABLED)
/* #	define SYSTEM_GCC_ASM_ENABLED */
#endif

/*!
\def SYSTEM_SIMD_ALIGN
* \brief Align an array by SIMD instruction width
*/
#if defined(SYSTEM_HAS_AVX512)
#	define SYSTEM_SIMD_ALIGN SYSTEM_ALIGN(64)
#	define SYSTEM_SIMD_ALIGNMENT 64
#elif defined(SYSTEM_HAS_AVX2)
#	define SYSTEM_SIMD_ALIGN SYSTEM_ALIGN(32)
#	define SYSTEM_SIMD_ALIGNMENT 32
#elif defined(SYSTEM_HAS_AVX)
#	define SYSTEM_SIMD_ALIGN SYSTEM_ALIGN(16)
#	define SYSTEM_SIMD_ALIGNMENT 16
#else
#	define SYSTEM_SIMD_ALIGN
#	define SYSTEM_SIMD_ALIGNMENT 8
#endif

#if defined(SYSTEM_AVX_INTRINSICS)
/*!
* \def SYSTEM_RDRAND_COMPATIBLE
* \brief The system has an RDRAND compatible CPU
*/
#	define SYSTEM_RDRAND_COMPATIBLE
#endif

/*!
\def SYSTEM_STATUS_SUCCESS
* Function return value indicates successful operation
*/
#define SYSTEM_STATUS_SUCCESS 0

/*!
\def SYSTEM_STATUS_FAILURE
* Function return value indicates failed operation
*/
#define SYSTEM_STATUS_FAILURE -1


/* User Modifiable Values
* Modifiable values that determine which parameter sets and options get compiled.
* These values can be tuned by the user to enable/disable features for a specific environment, or hardware configuration.
* This list also includes the asymmetric cipher and signature scheme parameter set options.
*/

/*!
\def SYSTEM_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the SYSTEM_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/
#if !defined(SYSTEM_AESNI_ENABLED)
#	if defined(SYSTEM_AVX_INTRINSICS)
#		define SYSTEM_AESNI_ENABLED
#	endif
#endif

#endif

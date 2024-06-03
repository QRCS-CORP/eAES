#include "utils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* bogus winbase.h error */
SYSTEM_CONDITION_IGNORE(5105)

#if defined(SYSTEM_OS_WINDOWS)
#	include <Windows.h>
#	if defined(SYSTEM_ARCH_IX86)
#		include <intrin.h>
#		pragma intrinsic(__cpuid)
#	elif defined(SYSTEM_ARCH_ARM)
#		include <processthreadsapi.h>
#	endif
#elif defined(SYSTEM_OS_POSIX)
#	if defined(SYSTEM_OS_BSD)
#   	include <sys/param.h>
#   	include <sys/sysctl.h>
#		include <sys/types.h>
#		include <unistd.h>
#	else
#		include <cpuid.h>
#   	include <limits.h>
#		include <x86intrin.h>
#   	include <unistd.h>
#		include <xsaveintrin.h>
#	endif
#	if defined(_AIX)
#		include <sys/systemcfg.h>
#	endif
#endif


bool utils_file_exists(const char* path)
{
	int32_t err;

#if defined(SYSTEM_OS_WINDOWS)
	err = _access(path, 0);
#else
	err = access(path, F_OK);
#endif

	return (err == 0);
}

int64_t utils_file_getline(char** line, size_t* length, FILE* fp)
{
	char* tmpl;

	/* check if either line, length or fp are NULL pointers */
	if (line == NULL || length == NULL || fp == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	else
	{
		/* use a chunk array of 128 bytes as parameter for fgets */
		char chunk[128] = { 0 };

		/* allocate a block of memory for *line if it is NULL or smaller than the chunk array */
		if (*line == NULL || *length < sizeof(chunk))
		{
			*length = sizeof(chunk);

			if ((*line = malloc(*length)) == NULL)
			{
				errno = ENOMEM;
				return -1;
			}
		}

		(*line)[0] = '\0';

		while (fgets(chunk, sizeof(chunk), fp) != NULL)
		{
			/* resize the line buffer if necessary */
			size_t lenused = strlen(*line);
			size_t chunkused = strlen(chunk);

			if (*length - lenused < chunkused)
			{
				// Check for overflow
				if (*length > SIZE_MAX / 2)
				{
					errno = EOVERFLOW;
					return -1;
				}
				else
				{
					*length *= 2;
				}

				tmpl = realloc(*line, *length);

				if (tmpl != NULL)
				{
					*line = tmpl;
				}
				else
				{
					errno = ENOMEM;
					return -1;
				}
			}

			/* copy the chunk to the end of the line buffer */
			utils_memory_copy(*line + lenused, chunk, chunkused);
			lenused += chunkused;
			(*line)[lenused] = '\0';

			/* check if *line contains '\n', if yes, return the *line length */
			if ((*line)[lenused - 1] == '\n')
			{
				return lenused;
			}
		}

		return -1;
	}
}

FILE*  utils_open_file(const char* path, const char* mode, errno_t* err)
{
    FILE* fp;

    fp = NULL;
    #if defined(SYSTEM_OS_WINDOWS)
	*err = fopen_s(&fp, path, mode);
#else
    fp = fopen(path, mode);
    *err = (fp == NULL) ? -1 : 0;
#endif

return fp;
}

void utils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	assert(hexstr != NULL);
	assert(output != NULL);
	assert(length != 0);

	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (hexstr != NULL && output != NULL && length != 0)
	{
		utils_memory_clear(output, length);

		for (size_t  pos = 0; pos < (length * 2); pos += 2)
		{
			idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
			idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
			output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
		}
	}
}

void utils_print_line(const char* input)
{
	assert(input != NULL);

	if (input != NULL)
	{
		utils_print_safe(input);
	}

	utils_print_safe("\n");
}

void utils_print_safe(const char* input)
{
	assert(input != NULL);

	if (input != NULL && utils_string_size(input) > 0)
	{
#if defined(SYSTEM_OS_WINDOWS)
		printf_s("%s", input);
#else
		printf("%s", input);
#endif
	}
}


bool utils_seed_generate(uint8_t* output, size_t length)
{
	assert(output != 0);
	assert(length <= UTILS_SEED_MAX);

	bool res;

	res = true;

#if defined(SYSTEM_OS_WINDOWS)

	HCRYPTPROV hprov;

	if (CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) == true)
	{
		if (CryptGenRandom(hprov, (DWORD)length, output) == false)
		{
			res = false;
		}
	}
	else
	{
		res = false;
	}

	if (hprov != 0)
	{
		CryptReleaseContext(hprov, 0);
	}

#elif defined(HAVE_SAFE_ARC4RANDOM)

	arc4random_buf(output, length);

#else

	int32_t fd = open("/dev/urandom", O_RDONLY);

	if (fd <= 0)
	{
		res = false;
	}
	else
	{
		int32_t r = read(fd, output, length);

		if (r != length)
		{
			res = false;
		}

		close(fd);
	}

#endif

	return res;
}

static uint32_t utils_cpu_count()
{
	uint32_t res;

#if defined(SYSTEM_OS_WINDOWS)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	res = (uint32_t)sysinfo.dwNumberOfProcessors;
#else
	res = (uint32_t)sysconf(_SC_NPROCESSORS_CONF);
#endif

	if (res < 1)
	{
		res = 1;
	}

	return res;
}

#if defined(SYSTEM_ARCH_ARM)
#	if !defined(HWCAP_ARMv7)
#		define HWCAP_ARMv7 (1 << 29)
#	endif
#	if !defined(HWCAP_ASIMD)
#		define HWCAP_ASIMD (1 << 1)
#	endif
#	if !defined(HWCAP_NEON)
#		define HWCAP_NEON (1 << 12)
#	endif
#	if !defined(HWCAP_CRC32)
#		define HWCAP_CRC32 (1 << 7)
#	endif
#	if !defined(HWCAP2_CRC32)
#		define HWCAP2_CRC32 (1 << 4)
#	endif
#	if !defined(HWCAP_PMULL)
#		define HWCAP_PMULL (1 << 4)
#	endif
#	if !defined(HWCAP2_PMULL)
#		define HWCAP2_PMULL (1 << 1)
#	endif
#	if !defined(HWCAP_AES)
#		define HWCAP_AES (1 << 3)
#	endif
#	if !defined(HWCAP2_AES)
#		define HWCAP2_AES (1 << 0)
#	endif
#	if !defined(HWCAP_SHA1)
#		define HWCAP_SHA1 (1 << 5)
#	endif
#	if !defined(HWCAP_SHA2)
#		define HWCAP_SHA2 (1 << 6)
#	endif
#	if !defined(HWCAP2_SHA1)
#		define HWCAP2_SHA1 (1 << 2)
#	endif
#	if !defined(HWCAP2_SHA2)
#		define HWCAP2_SHA2 (1 << 3)
#	endif
#	if !defined(HWCAP_SM3)
#		define HWCAP_SM3 (1 << 18)
#	endif
#	if !defined(HWCAP_SM4)
#		define HWCAP_SM4 (1 << 19)
#	endif

static bool utils_is_armv7()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_ARMv7) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_ARMv7) != 0 ||
		(getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__arm__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	res = true;
#endif

	return res;
}

static bool utils_has_neon()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_ASIMD) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv8())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_pmull()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_PMULL) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_PMULL) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_PMULL) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_PMULL) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	/* M1 processor */
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_aes()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_AES) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_AES) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_sha256()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA2) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA2) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA2) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA2) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_sha512()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA512) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA512) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA512) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA512) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
}
#endif

	return res;
}

static bool utils_has_sha3()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA3) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA3) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA3) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA3) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#endif

	return res;
}

static void utils_arm_features(utils_cpu_features* features)
{
	features->aesni = utils_has_aes();
	features->armv7 = utils_is_armv7();
	features->neon = utils_has_neon();
	features->pcmul = utils_has_pmull();
	features->sha256 = utils_has_sha256();
	features->sha512 = utils_has_sha512();
	features->sha3 = utils_has_sha3();
}

#endif

#if defined(SYSTEM_ARCH_IX86) && !defined(SYSTEM_OS_BSD)

#	define CPUID_EBX_AVX2 0x00000020UL
#	define CPUID_EBX_AVX512F 0x00010000UL
#	define CPUID_EBX_ADX 0x00080000UL
#	define CPUID_ECX_PCLMUL 0x00000002UL
#	define CPUID_ECX_AESNI 0x02000000UL
#	define CPUID_ECX_XSAVE 0x04000000UL
#	define CPUID_ECX_OSXSAVE 0x08000000UL
#	define CPUID_ECX_AVX 0x10000000UL
#	define CPUID_ECX_RDRAND 0x40000000UL
#	define CPUID_EDX_RDTCSP 0x0000001BUL
#	define CPUID_EBX_SHA2 0x20000000UL
#	define XCR0_SSE 0x00000002UL
#	define XCR0_AVX 0x00000004UL
#	define XCR0_OPMASK 0x00000020UL
#	define XCR0_ZMM_HI256 0x00000040UL
#	define XCR0_HI16_ZMM 0x00000080UL

static void utils_cpu_info(uint32_t info[4], const uint32_t infotype)
{
#if defined(SYSTEM_COMPILER_MSC)
	__cpuid((int*)info, infotype);
#elif defined(SYSTEM_COMPILER_GCC)
	__get_cpuid(infotype, &info[0], &info[1], &info[2], &info[3]);
#endif
}

static uint32_t utils_read_bits(uint32_t value, int index, int length)
{
	int mask = ((1L << length) - 1) << index;

	return (value & mask) >> index;
}

static void utils_vendor_name(utils_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	utils_cpu_info(info, 0x00000000UL);
	utils_memory_clear(features->vendor, UTILS_CPUIDEX_VENDOR_SIZE);
	utils_memory_copy(&features->vendor[0], &info[1], sizeof(uint32_t));
	utils_memory_copy(&features->vendor[4], &info[3], sizeof(uint32_t));
	utils_memory_copy(&features->vendor[8], &info[2], sizeof(uint32_t));
}

static void utils_bus_info(utils_cpu_features* features)
{
	uint32_t info[4] = { 0 };
	utils_cpu_info(info, 0x00000000UL);

	if (info[0] >= 0x00000016UL)
	{
		utils_memory_clear(info, sizeof(info));
		utils_cpu_info(info, 0x00000016UL);
		features->freqbase = info[0];
		features->freqmax = info[1];
		features->freqref = info[2];
	}
}

static void utils_cpu_cache(utils_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	utils_cpu_info(info, 0x80000006UL);

	features->l1cache = utils_read_bits(info[2], 0, 8);
	features->l1cacheline = utils_read_bits(info[2], 0, 11);
	features->l2associative = utils_read_bits(info[2], 12, 4);
	features->l2cache = utils_read_bits(info[2], 16, 16);
}

static void utils_cpu_topology(utils_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	/* total cpu cores */
	features->cores = utils_cpu_count();

	/* hyperthreading and actual cpus */
	utils_cpu_info(info, 0x00000001UL);
	features->hyperthread = utils_read_bits(info[3], 28, 1) != 0;
	features->cpus = (features->hyperthread == true && features->cores > 1) ? (features->cores / 2) : features->cores;

	/* cache line size */
	utils_cpu_info(info, 0x00000001UL);

	/* cpu features */
	features->pcmul = ((info[2] & CPUID_ECX_PCLMUL) != 0x00000000UL);
	features->aesni = ((info[2] & CPUID_ECX_AESNI) != 0x00000000UL);
	features->rdrand = ((info[2] & CPUID_ECX_RDRAND) != 0x00000000UL);
	features->rdtcsp = ((info[3] & CPUID_EDX_RDTCSP) != 0x00000000UL);

#if defined(SYSTEM_HAS_AVX)
	bool havx;

	havx = (info[2] & CPUID_ECX_AVX) != 0x00000000UL;

	if (havx == true)
	{
		uint32_t xcr0;

		xcr0 = 0;

		if ((info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
			(CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
		{
			xcr0 = (uint32_t)_xgetbv(0);
		}

		if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX))
		{
			features->avx = true;
		}
	}
#endif

	if (features->cputype == hkds_cpuid_intel)
	{
		features->cacheline = utils_read_bits(info[1], 16, 8) * 8;
	}
	else if (features->cputype == hkds_cpuid_amd)
	{
		utils_cpu_info(info, 0x80000005UL);
		features->cacheline = utils_read_bits(info[2], 24, 8);
	}

	if (features->avx == true)
	{
#if defined(SYSTEM_HAS_AVX2)
		bool havx2;

		utils_memory_clear(info, sizeof(info));
		utils_cpu_info(info, 0x00000007UL);

#	if defined(SYSTEM_COMPILER_GCC)
		__builtin_cpu_init();
		havx2 = __builtin_cpu_supports("avx2") != 0;
#	else
		havx2 = ((info[1] & CPUID_EBX_AVX2) != 0x00000000UL);
#	endif

		features->adx = ((info[1] & CPUID_EBX_ADX) != 0x00000000UL);
		features->avx2 = havx2 && ((uint32_t)_xgetbv(0) & 0x000000E6UL) != 0x00000000UL;
		features->sha256 = ((info[1] & CPUID_EBX_SHA2) != 0x00000000UL);
#endif

#if defined(SYSTEM_HAS_AVX512)
		bool havx512;
#	if defined(SYSTEM_COMPILER_GCC)
		havx512 = __builtin_cpu_supports("avx512f") != 0;
#	else
		havx512 = ((info[1] & CPUID_EBX_AVX512F) != 0x00000000UL);
#	endif
		if (havx512 == true)
		{
			uint32_t xcr2 = (uint32_t)_xgetbv(0);

			if ((xcr2 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
				(XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
			{
				features->avx512f = true;
			}
		}
#endif
	}
}

static void utils_cpu_type(utils_cpu_features* features)
{
	char tmpn[UTILS_CPUIDEX_VENDOR_SIZE + 1] = { 0 };

	utils_vendor_name(features);
	utils_memory_copy(tmpn, features->vendor, UTILS_CPUIDEX_VENDOR_SIZE);
	utils_string_to_lowercase(tmpn);

	if (utils_string_contains(tmpn, "intel") == true)
	{
		features->cputype = hkds_cpuid_intel;
	}
	else if (utils_string_contains(tmpn, "amd") == true)
	{
		features->cputype = hkds_cpuid_amd;
	}
	else if (utils_string_contains(tmpn, "centaur") == true)
	{
		features->cputype = hkds_cpuid_via;
	}
	else if (utils_string_contains(tmpn, "via") == true)
	{
		features->cputype = hkds_cpuid_via;
	}
	else if (utils_string_contains(tmpn, "hygon") == true)
	{
		features->cputype = hkds_cpuid_hygion;
	}
	else
	{
		features->cputype = hkds_cpuid_unknown;
	}
}

static void utils_serial_number(utils_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	utils_cpu_info(info, 0x00000003UL);
	utils_memory_clear(features->serial, UTILS_CPUIDEX_SERIAL_SIZE);
	utils_memory_copy(&features->serial[0], &info[1], sizeof(uint32_t));
	utils_memory_copy(&features->serial[4], &info[3], sizeof(uint32_t));
	utils_memory_copy(&features->serial[8], &info[2], sizeof(uint32_t));
}

#endif

#if defined(SYSTEM_OS_BSD)

static void utils_bsd_topology(utils_cpu_features* features)
{
	size_t plen;
	uint64_t pval;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.physicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cpus = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.logicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cores = pval;
		features->hyperthread = (pval > features->cpus);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency", &pval, &plen, NULL, 0) == 0)
	{
		features->freqbase = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_max", &pval, &plen, NULL, 0) == 0)
	{
		features->freqmax = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_min", &pval, &plen, NULL, 0) == 0)
	{
		features->freqref = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l1dcachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l1cache = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l2cachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l2cache = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.adx", &pval, &plen, NULL, 0) == 0)
	{
		features->adx = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.aes", &pval, &plen, NULL, 0) == 0)
	{
		features->aesni = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx1_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx = (pval == 1);
	}


	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx2_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx2 = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx512f", &pval, &plen, NULL, 0) == 0)
	{
		features->avx512f = (pval == 1);
	}

	features->pcmul = features->avx;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	features->rdtcsp = features->avx;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	char vend[1024] = { 0 };
	plen = sizeof(vend);

	if (sysctlbyname("machdep.cpu.brand_string", vend, &plen, NULL, 0) >= 0)
	{
		utils_memory_copy(features->vendor, vend, UTILS_CPUIDEX_VENDOR_SIZE - 1);
		utils_string_to_lowercase(vend);

		if (utils_string_contains(vend, "intel") == true)
		{
			features->cputype = hkds_cpuid_intel;
		}
		else if (utils_string_contains(vend, "amd") == true)
		{
			features->cputype = hkds_cpuid_amd;
		}
		else
		{
			features->cputype = hkds_cpuid_unknown;
		}
	}
}

#elif defined(SYSTEM_OS_POSIX)

static void utils_posix_topology(utils_cpu_features* features)
{
#	if defined(SYSTEM_ARCH_IX86) && defined(SYSTEM_COMPILER_GCC)

	utils_cpu_type(features);

	if (features->cputype == hkds_cpuid_intel || features->cputype == hkds_cpuid_amd)
	{
		utils_bus_info(features);
		utils_cpu_cache(features);
		utils_cpu_topology(features);
		utils_serial_number(features);
	}

#	else

	int32_t res;

	res = sysconf(_SC_NPROCESSORS_CONF);

	if (res > 0)
	{
		features->cpus = (uint32_t)res;
	}

	res = sysconf(_SC_NPROCESSORS_ONLN);

	if (res > 0)
	{
		features->cores = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_SIZE);

	if (res > 0)
	{
		features->l1cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_LINESIZE);

	if (res > 0)
	{
		features->l1cacheline = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_SIZE);

	if (res > 0)
	{
		features->l2cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_ASSOC);

	if (res > 0)
	{
		features->l2associative = (uint32_t)res;
	}


	res = sysconf(_SC_LEVEL2_CACHE_LINESIZE);

	if (res > 0)
	{
		features->cacheline = (uint32_t)res;
	}
#	endif
}

#elif defined(SYSTEM_OS_WINDOWS)

static void utils_windows_topology(utils_cpu_features* features)
{
#	if defined(SYSTEM_ARCH_IX86)
	utils_cpu_type(features);

	if (features->cputype == hkds_cpuid_intel || features->cputype == hkds_cpuid_amd)
	{
		utils_bus_info(features);
		utils_cpu_cache(features);
		utils_cpu_topology(features);
		utils_serial_number(features);
	}
#	else

	features->cpus = utils_cpu_count();
	features->cores = features->cpus;

#	endif
}

#endif

bool utils_cpu_features_set(utils_cpu_features* features)
{
    bool res;

    features->adx = false;
    features->aesni = false;
    features->pcmul = false;
	/* ARM features */
	features->armv7 = false;
	features->neon = false;
	features->sha256 = false;
	features->sha512 = false;
	features->sha3 = false;
	/* Intel features */
    features->avx = false;
    features->avx2 = false;
    features->avx512f = false;
    features->hyperthread = false;
    features->rdrand = false;
    features->rdtcsp = false;
	/* cpu topology */
    features->cacheline = 0;
    features->cores = 0;
    features->cpus = 1;
    features->freqbase = 0;
    features->freqmax = 0;
    features->freqref = 0;
    features->l1cache = 0;
    features->l1cacheline = 0;
    features->l2associative = 4;
    features->l2cache = 0;
    utils_memory_clear(features->serial, UTILS_CPUIDEX_SERIAL_SIZE);

#if defined(SYSTEM_OS_POSIX)
#	if defined(SYSTEM_OS_BSD)
	utils_bsd_topology(features);
    res = true;
#else
	utils_posix_topology(features);
	res = true;
#endif
#elif defined(SYSTEM_OS_WINDOWS)
	utils_windows_topology(features);
	res = true;
#else
	res = false;
#endif

#if defined(SYSTEM_ARCH_ARM)
	utils_arm_features(features);
#endif

    return res;
}

uint64_t utils_stopwatch_start()
{
	uint64_t start;

	start = (uint64_t)clock();

	return start;
}

uint64_t utils_stopwatch_elapsed(uint64_t start)
{
	uint64_t diff;
	uint64_t msec;

	msec = clock();
	diff = msec - start;
	msec = (diff * 1000) / CLOCKS_PER_SEC;

	return msec;
}


int64_t utils_find_string(const char* source, const char* token)
{
	assert(source != NULL);
	assert(token != NULL);

	int64_t pos;

	pos = UTILS_TOKEN_NOT_FOUND;

	if (source != NULL && token != NULL)
	{
		size_t slen;
		size_t tlen;

		slen = utils_string_size(source);
		tlen = utils_string_size(token);

		for (size_t i = 0; i < slen; ++i)
		{
			if (source[i] == token[0])
			{
				if (utils_memory_are_equal(source + i, token, tlen) == true)
				{
					pos = i;
					break;
				}
			}
		}
	}

	return pos;
}

bool utils_string_contains(const char* source, const char* token)
{
	assert(source != NULL);
	assert(token != NULL);

	bool res;

	res = false;

	if (source != NULL && token != NULL)
	{
		res = (utils_find_string(source, token) >= 0);
	}

	return res;
}

size_t utils_string_size(const char* source)
{
	assert(source != NULL);

	size_t res;

	res = 0;

	if (source != NULL)
	{
#if defined(SYSTEM_OS_WINDOWS)
		res = strnlen_s(source, UTILS_STRING_MAX_LEN);
#else
		res = strlen(source);
#endif
	}

	return res;
}

void utils_string_to_lowercase(char* source)
{
	assert(source != NULL);

	if (source != NULL)
	{
#if defined(SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = utils_string_size(source) + 1;
		_strlwr_s(source, slen);
#else
		for(size_t i = 0; i < strlen(source); ++i)
		{
			source[i] = tolower(source[i]);
		}
#endif
	}
}


#if defined(SYSTEM_HAS_AVX)
static void utils_clear128(void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#endif

#if defined(SYSTEM_HAS_AVX2)
static void utils_clear256(void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
}
#endif

#if defined(SYSTEM_HAS_AVX512)
static void utils_clear512(void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_setzero_si512());
}
#endif

void utils_memory_clear(void* output, size_t length)
{
	assert(output != NULL);
	assert(length != 0);

	size_t pctr;

	if (output != NULL && length != 0)
	{
		pctr = 0;

#if defined(SYSTEM_AVX_INTRINSICS)
#	if defined(SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#	if defined(SYSTEM_HAS_AVX512)
				utils_clear512(((uint8_t*)output + pctr));
#	elif defined(SYSTEM_HAS_AVX2)
				utils_clear256(((uint8_t*)output + pctr));
#	elif defined(SYSTEM_HAS_AVX)
				utils_clear128(((uint8_t*)output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			utils_clear256(((uint8_t*)output + pctr));
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			utils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#elif defined(SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			utils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = 0x00;
			}
		}
	}
}

#if defined(SYSTEM_HAS_AVX)
static bool utils_equal128(const uint8_t* a, const uint8_t* b)
{
	__m128i wa;
	__m128i wb;
	__m128i wc;
	uint64_t ra[sizeof(__m128i) / sizeof(uint64_t)] = { 0 };

	wa = _mm_loadu_si128((const __m128i*)a);
	wb = _mm_loadu_si128((const __m128i*)b);
	wc = _mm_cmpeq_epi64(wa, wb);
	_mm_storeu_si128((__m128i*)ra, wc);

	return ((~ra[0] + ~ra[1]) == 0);
}
#endif

#if defined(SYSTEM_HAS_AVX2)
static bool utils_equal256(const uint8_t* a, const uint8_t* b)
{
	__m256i wa;
	__m256i wb;
	__m256i wc;
	uint64_t ra[sizeof(__m256i) / sizeof(uint64_t)] = { 0 };

	wa = _mm256_loadu_si256((const __m256i*)a);
	wb = _mm256_loadu_si256((const __m256i*)b);
	wc = _mm256_cmpeq_epi64(wa, wb);
	_mm256_storeu_si256((__m256i*)ra, wc);

	return ((~ra[0] + ~ra[1] + ~ra[2] + ~ra[3]) == 0);
}
#endif

#if defined(SYSTEM_HAS_AVX512)
static bool utils_equal512(const uint8_t* a, const uint8_t* b)
{
	__m512i wa;
	__m512i wb;
	__m512i wc;
	__mmask8 mr;

	wa = _mm512_loadu_si512((const __m512i*)a);
	wb = _mm512_loadu_si512((const __m512i*)b);
	mr = _mm512_cmpeq_epi64_mask(wa, wb); // NOTE: test this.

	return ((const char)mr == 0);
}
#endif

void* utils_memory_malloc(size_t length)
{
	assert(length != 0);

	void* ret;

	ret = NULL;

	if (length != 0)
	{
		ret = malloc(length);
	}

	return ret;
}

void utils_memory_alloc_free(void* block)
{
	assert(block != NULL);

	if (block != NULL)
	{
		free(block);
	}
}

bool utils_memory_are_equal(const uint8_t* a, const uint8_t* b, size_t length)
{
	assert(a != NULL);
	assert(b != NULL);
	assert(length > 0);

	size_t pctr;
	int32_t mctr;

	mctr = 0;
	pctr = 0;

	if (a != NULL && b != NULL && length != 0)
	{
#if defined(SYSTEM_AVX_INTRINSICS)
#	if defined(SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(SYSTEM_HAS_AVX512)
				mctr |= ((int32_t)utils_equal512(a + pctr, b + pctr) - 1);
#elif defined(SYSTEM_HAS_AVX2)
				mctr |= ((int32_t)utils_equal256(a + pctr, b + pctr) - 1);
#elif defined(SYSTEM_HAS_AVX)
				mctr |= ((int32_t)utils_equal128(a + pctr, b + pctr) - 1);
#endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				mctr |= (a[i] ^ b[i]);
			}
		}
	}

	return (mctr == 0);
}

bool utils_memory_are_equal_128(const uint8_t* a, const uint8_t* b)
{
#if defined(SYSTEM_HAS_AVX)

	return utils_equal128(a, b);

#else

	int32_t mctr;

	for (size_t i = 0; i < 16; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

bool utils_memory_are_equal_256(const uint8_t* a, const uint8_t* b)
{
#if defined(SYSTEM_HAS_AVX2)

	return utils_equal256(a, b);

#elif defined(SYSTEM_HAS_AVX)

	return (utils_equal128(a, b) && 
		utils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)));

#else

	int32_t mctr;

	for (size_t i = 0; i < 32; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

bool utils_memory_are_equal_512(const uint8_t* a, const uint8_t* b)
{
#if defined(SYSTEM_HAS_AVX512)

	return utils_equal512(a, b);

#elif defined(SYSTEM_HAS_AVX2)

	return utils_equal256(a, b) && 
		utils_equal256(a + sizeof(__m256i), b + sizeof(__m256i));

#elif defined(SYSTEM_HAS_AVX)

	return (utils_equal128(a, b) && 
		utils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)) &&
		utils_equal128(a + (2 * sizeof(__m128i)), b + (2 * sizeof(__m128i))) &&
		utils_equal128(a + (3 * sizeof(__m128i)), b + (3 * sizeof(__m128i))));

#else

	int32_t mctr;

	for (size_t i = 0; i < 64; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

#if defined(SYSTEM_HAS_AVX)
static void utils_copy128(const void* input, void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
}
#endif

#if defined(SYSTEM_HAS_AVX2)
static void utils_copy256(const void* input, void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
}
#endif

#if defined(SYSTEM_HAS_AVX512)
static void utils_copy512(const void* input, void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_loadu_si512((const __m512i*)input));
}
#endif

void utils_memory_copy(void* output, const void* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);

	size_t pctr;

	if (output != NULL && input != NULL && length != 0)
	{
		pctr = 0;

#if defined(SYSTEM_AVX_INTRINSICS)
#	if defined(SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(SYSTEM_HAS_AVX512)
				utils_copy512((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(SYSTEM_HAS_AVX2)
				utils_copy256((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(SYSTEM_HAS_AVX)
				utils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			utils_copy256((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			utils_copy128((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#elif defined(SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			utils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = ((const uint8_t*)input)[i];
			}
		}
	}
}

#if defined(SYSTEM_HAS_AVX)
static void utils_xor128(const uint8_t* input, uint8_t* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(SYSTEM_HAS_AVX2)
static void utils_xor256(const uint8_t* input, uint8_t* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(SYSTEM_HAS_AVX512)
static void utils_xor512(const uint8_t* input, uint8_t* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((__m512i*)output)));
}
#endif

void utils_memory_xor(uint8_t* output, const uint8_t* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);
	assert(length != 0);

	size_t pctr;

	pctr = 0;

#if defined(SYSTEM_AVX_INTRINSICS)
#	if defined(SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64;
#	elif defined(SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32;
#	else
	const size_t SMDBLK = 16;
#	endif

	if (output != NULL && input != NULL && length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(SYSTEM_HAS_AVX512)
			utils_xor512((input + pctr), output + pctr);
#elif defined(SYSTEM_HAS_AVX2)
			utils_xor256((input + pctr), output + pctr);
#elif defined(SYSTEM_HAS_AVX)
			utils_xor128((input + pctr), output + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

#if defined(SYSTEM_HAS_AVX512)
	if (length - pctr >= 32)
	{
		utils_xor256((input + pctr), output + pctr);
		pctr += 32;
	}
	else if (length - pctr >= 16)
	{
		utils_xor128((input + pctr), output + pctr);
		pctr += 16;
	}
#elif defined(SYSTEM_HAS_AVX2)
	if (length - pctr >= 16)
	{
		utils_xor128((input + pctr), output + pctr);
		pctr += 16;
	}
#endif

	if (pctr != length)
	{
		for (size_t i = pctr; i < length; ++i)
		{
			output[i] ^= input[i];
		}
	}
}

#if defined(SYSTEM_HAS_AVX512)
static void utils_xorv512(const uint8_t value, uint8_t* output)
{
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
}
#elif defined(SYSTEM_HAS_AVX2)
static void utils_xorv256(const uint8_t value, uint8_t* output)
{
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((const __m256i*)output)));
}
#elif defined(SYSTEM_HAS_AVX)
static void utils_xorv128(const uint8_t value, uint8_t* output)
{
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) & v), _mm_loadu_si128((const __m128i*)output)));
}
#endif

void utils_memory_xorv(uint8_t* output, const uint8_t value, size_t length)
{
	assert(output != NULL);
	assert(length != 0);

	size_t pctr;

	pctr = 0;

#if defined(SYSTEM_AVX_INTRINSICS)
#	if defined(SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64;
#	elif defined(SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32;
#	else
	const size_t SMDBLK = 16;
#	endif

	if (output != NULL && length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(SYSTEM_HAS_AVX512)
			utils_xorv512(value, (output + pctr));
#elif defined(SYSTEM_HAS_AVX2)
			utils_xorv256(value, (output + pctr));
#elif defined(SYSTEM_HAS_AVX)
			utils_xorv128(value, (output + pctr));
#endif
			pctr += SMDBLK;
		}
	}
#endif

	if (pctr != length)
	{
		for (size_t i = pctr; i < length; ++i)
		{
			output[i] ^= value;
		}
	}
}

void utils_integer_be16to8(uint8_t* output, uint16_t value)
{
	output[1] = (uint8_t)value & 0xFFU;
	output[0] = (uint8_t)(value >> 8) & 0xFFU;
}

uint32_t utils_integer_be8to32(const uint8_t* input)
{
	return (uint32_t)(input[3]) |
		(((uint32_t)(input[2])) << 8) |
		(((uint32_t)(input[1])) << 16) |
		(((uint32_t)(input[0])) << 24);
}

void utils_integer_be32to8(uint8_t* output, uint32_t value)
{
	output[3] = (uint8_t)value & 0xFFU;
	output[2] = (uint8_t)(value >> 8) & 0xFFU;
	output[1] = (uint8_t)(value >> 16) & 0xFFU;
	output[0] = (uint8_t)(value >> 24) & 0xFFU;
}

uint64_t utils_integer_be8to64(const uint8_t* input)
{
	return (uint64_t)(input[7]) |
		(((uint64_t)(input[6])) << 8) |
		(((uint64_t)(input[5])) << 16) |
		(((uint64_t)(input[4])) << 24) |
		(((uint64_t)(input[3])) << 32) |
		(((uint64_t)(input[2])) << 40) |
		(((uint64_t)(input[1])) << 48) |
		(((uint64_t)(input[0])) << 56);
}

void utils_integer_be64to8(uint8_t* output, uint64_t value)
{
	output[7] = (uint8_t)value & 0xFFU;
	output[6] = (uint8_t)(value >> 8) & 0xFFU;
	output[5] = (uint8_t)(value >> 16) & 0xFFU;
	output[4] = (uint8_t)(value >> 24) & 0xFFU;
	output[3] = (uint8_t)(value >> 32) & 0xFFU;
	output[2] = (uint8_t)(value >> 40) & 0xFFU;
	output[1] = (uint8_t)(value >> 48) & 0xFFU;
	output[0] = (uint8_t)(value >> 56) & 0xFFU;
}

void utils_integer_be8increment(uint8_t* output, size_t otplen)
{
	size_t i = otplen;

	if (otplen > 0)
	{
		do
		{
			--i;
			++output[i];
		} 
		while (i != 0 && output[i] == 0);
	}
}

void utils_integer_le8increment(uint8_t* output, size_t otplen)
{
	size_t i;

	i = 0;

	while (i < otplen)
	{
		++output[i];

		if (output[i] != 0)
		{
			break;
		}

		++i;
	}
}

#if defined(SYSTEM_HAS_AVX)
void utils_integer_leincrement_x128(__m128i* counter)
{
	*counter = _mm_add_epi64(*counter, _mm_set_epi64x(0, 1));
}
#endif

#if defined(SYSTEM_HAS_AVX512)
void utils_integer_leincrement_x512(__m512i* counter)
{
	*counter = _mm512_add_epi64(*counter, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
}
#endif

void utils_integer_le32to8(uint8_t* output, uint32_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
}

uint64_t utils_integer_le8to64(const uint8_t* input)
{
	return ((uint64_t)input[0]) |
		((uint64_t)input[1] << 8) |
		((uint64_t)input[2] << 16) |
		((uint64_t)input[3] << 24) |
		((uint64_t)input[4] << 32) |
		((uint64_t)input[5] << 40) |
		((uint64_t)input[6] << 48) |
		((uint64_t)input[7] << 56);
}

void utils_integer_le64to8(uint8_t* output, uint64_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
	output[4] = (uint8_t)(value >> 32) & 0xFFU;
	output[5] = (uint8_t)(value >> 40) & 0xFFU;
	output[6] = (uint8_t)(value >> 48) & 0xFFU;
	output[7] = (uint8_t)(value >> 56) & 0xFFU;
}

size_t utils_integer_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

uint64_t utils_integer_rotl64(uint64_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint64_t) * 8) - shift));
}

#if defined(SYSTEM_HAS_AVX)
void utils_integer_reverse_bytes_x128(const __m128i* input, __m128i* output)
{
	__m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

	*output = _mm_shuffle_epi8(*input, mask);
}
#endif

#if defined(SYSTEM_HAS_AVX512)
void utils_integer_reverse_bytes_x512(const __m512i* input, __m512i* output)
{
	__m512i mask = _mm512_set_epi8(
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 
		32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);

	*output = _mm512_shuffle_epi8(*input, mask);
}
#endif

int32_t utils_integer_verify(const uint8_t* a, const uint8_t* b, size_t length)
{
	uint8_t d;

	d = 0;

	for (size_t i = 0; i < length; ++i)
	{
		d |= (a[i] ^ b[i]);
	}

	return d;
}
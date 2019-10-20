/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2019 vtdev.com
* This file is part of the CEX Cryptographic library.
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* Test platform for the (RHX/RSX=eAES) symmetric block cipher.
* Contact: develop@vtdev.com */

#include "common.h"
#include "rhx.h"
#include "rhx_kat.h"
#include "sha3_kat.h"
#include <stdio.h>

/* AES-NI Detection */

#if defined(_MSC_VER)

#include <intrin.h>
#pragma intrinsic(__cpuid)

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	__cpuid(info, 1);

	if (info[2] != 0)
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#elif defined(__GNUC__)

#include <cpuid.h>
#pragma GCC target ("ssse3")
#pragma GCC target ("sse4.1")
#pragma GCC target ("aes")
#include <x86intrin.h>

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	if (__get_cpuid(1, &info[0], &info[1], &info[2], &info[3]))
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#else

static int has_aes_ni()
{
	return 0;
}

#endif

/**
* \wait for input
*/
void get_response()
{
	wint_t ret;

	ret = getwchar();
}

/**
* \brief Test the CBC mode AES implementations with vectors from Fips197
*/
void aes_test_cbc()
{
	if (aes128_cbc_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 CBC KAT test. \n \n");
	}

	if (aes256_cbc_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 CBC KAT test. \n \n");
	}

}

/**
* \brief Tests the CTR mode AES implementation with vectors from Fips197
*/
void aes_test_ctr()
{
	if (ctr_mode_stress_test() == true)
	{
		printf_s("Success! Passed the CTR stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the CTR stress test. \n \n");
	}

	if (aes128_ctr_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 CTR KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 CTR KAT test. \n \n");
	}

	if (aes256_ctr_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 CTR KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 CTR KAT test. \n \n");
	}
}

/**
* \brief Test the ECB mode AES implementation with vectors from Fips197
*/
void aes_test_ecb()
{
	if (aes128_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 ECB KAT test. \n \n");
	}

	if (aes256_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 ECB KAT test. \n \n");
	}
}

/**
* \brief Test the RHX256 and RHX512 implementations with KAT vectors from the CEX library
*/
void rhx_test_kat()
{
	if (rhx256_kat_test() == true)
	{
		printf_s("Success! Passed the RHX256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX256 KAT test. \n \n");
	}

	if (rhx512_kat_test() == true)
	{
		printf_s("Success! Passed the RHX512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX512 KAT test. \n \n");
	}
}

/**
* \brief Test the RHX256 and RHX512 implementations with Monte Carlo vectors from the CEX library
*/
void rhx_test_monte_carlo()
{
	if (rhx256_monte_carlo_test() == true)
	{
		printf_s("Success! Passed the RHX256 Monte Carlo test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX256 Monte Carlo test. \n \n");
	}

	if (rhx512_monte_carlo_test() == true)
	{
		printf_s("Success! Passed the RHX512 Monte Carlo test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX512 Monte Carlo test. \n \n");
	}
}

int main()
{
	int valid;

	valid = 1;

	if (has_aes_ni() == 1)
	{
		printf_s("AES-NI is available on this system. \n");
#if !defined(RHX_AESNI_ENABLED)
		printf_s("Add the RHX_AESNI_ENABLED flag to the preprocessor definitions to test AES-NI implementation. \n");
#else
		printf_s("The RHX_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled. \n");
#endif
		printf_s("\n");
	}
	else
	{
		printf_s("AES-NI was not detected on this system. \n");
#if defined(RHX_AESNI_ENABLED)
		printf_s("Remove the RHX_AESNI_ENABLED flag from the preprocessor definitions to test the fallback implementation. \n");
		printf_s("Configuration settings error; AES-NI is enabled but not available on this system, check your compiler preprocessor settings. \n");
		printf_s("\n");
		valid = 0;
#endif
	}

#ifdef RHX_CSHAKE_EXTENSION
	printf_s("The CSHAKE cipher extension definition has been detected. \n");
	printf_s("Remove the RHX_CSHAKE_EXTENSION definition to enable the HKDF cipher extensions. \n");
	printf_s("\n\n");
#else
	printf_s("The HKDF cipher extension is enabled. \n");
	printf_s("Add the RHX_CSHAKE_EXTENSION definition to preprocessor flags to enable the CSHAKE cipher extensions. \n");
	printf_s("\n\n");
#endif

	if (valid == 1)
	{
		printf_s("*** Test the AES implemetations using the NIST SP800-38a Known Answer Tests *** \n");
		printf_s("\n");
		aes_test_cbc();
		aes_test_ctr();
		aes_test_ecb();
		printf_s("\n");

		printf_s("*** Test extended cipher implementations using Monte Carlo and KAT vectors from CEX *** \n");
		rhx_test_kat();
		rhx_test_monte_carlo();
		printf_s("\n");

		printf_s("Completed! Press any key to close..");
		get_response();
	}
	else
	{
		printf_s("The test has been cancelled. Press any key to close..");
		get_response();
	}

    return 0;
}


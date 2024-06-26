/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 vtdev.com
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
#include "utils.h"
#include "aesavs_test.h"
#include "cipher_speed.h"
#include "rhx_test.h"
#include "sha2_test.h"
#include "sha3_test.h"
#include "testutils.h"
#include "selftest.h"

bool test_confirm(char* message)
{
	char ans;
	bool res;

	qsctest_print_line(message);

	res = false;
	ans = qsctest_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}

void print_title()
{
	qsctest_print_line("***************************************************");
	qsctest_print_line("* eAES: the RHX symmetric cipher in C             *");
	qsctest_print_line("*                                                 *");
	qsctest_print_line("* Release:   v1.0.0.1b (A1)                       *");
	qsctest_print_line("* License:   GPLv3                                *");
	qsctest_print_line("* Date:      December 7, 2021                     *");
	qsctest_print_line("* Contact:   develop@vtdev.com                    *");
	qsctest_print_line("***************************************************");
	qsctest_print_line("");
}

int main()
{
	utils_cpu_features hfeat;
	bool valid;
	bool res;

	valid = qsctest_selftest_run();

	if (valid == true)
	{
		print_title();

		qsctest_print_line("Passed internal RHX, SHA2, and SHA3 self-checks \n");

		res = utils_cpu_features_set(&hfeat);

		if (res == false)
		{
			qsctest_print_line("The CPU type was not recognized on this system!");
			qsctest_print_line("Some features may be disabled.");
		}

		if (hfeat.aesni == true)
		{
			qsctest_print_line("AES-NI is available on this system.");
			qsctest_print_line("The SYSTEM_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled.");
		}
		else
		{
			qsctest_print_line("AES-NI was not detected on this system.");
		}

		if (hfeat.avx512f == true)
		{
			qsctest_print_line("The AVX-512 intrinsics functions have been detected on this system.");
		}
		else if (hfeat.avx2 == true)
		{
			qsctest_print_line("The AVX-2 intrinsics functions have been detected on this system.");
		}
		else if (hfeat.avx == true)
		{
			qsctest_print_line("The AVX intrinsics functions have been detected on this system.");
			qsctest_print_line("For best performance, set to the highest supported AVX configuration: AVX512 AES-NI instructions are implemented.");
		}
		else
		{
			qsctest_print_line("The AVX intrinsics functions have not been detected or are not enabled.");
			qsctest_print_line("For best performance, enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		}

#if defined(RHX_IS_X86)
		qsctest_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
		qsctest_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif

#if defined(RHX_SHAKE_EXTENSION)
		qsctest_print_line("The CSHAKE cipher extension definition has been detected.");
		qsctest_print_line("Remove the RHX_CSHAKE_EXTENSION definition from rhx.h to enable the HKDF cipher extensions.");
		qsctest_print_line("\n");
#else
		qsctest_print_line("The HKDF cipher extension is enabled.");
		qsctest_print_line("Add the RHX_CSHAKE_EXTENSION definition to preprocessor flags to enable the CSHAKE cipher extensions.");
		qsctest_print_line("\n");
#endif
	}
	else
	{
		qsctest_print_line("Failure! Internal self-checks have errored, aborting tests!");
		valid = false;
	}

	if (valid == true)
	{
		if (test_confirm("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: ") == true)
		{
			qsctest_print_line("*** Test the AES implementations using the AESAVS KAT, Monte Carlo, and Multi-block Message Tests ***");
			qsctest_aesavs_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the AES implementations using the NIST FIPS-197 AES common modes known answer tests ***");
			qsctest_aes_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test extended cipher implementations using Stress testing, Monte Carlo, and KAT vector tests from CEX++ ***");
			qsctest_rhx_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test HKDF, HMAC, and SHA2 implementations using the official KAT vetors. ***");
			qsctest_sha2_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official KAT vetors. ***");
			qsctest_sha3_run();
			qsctest_print_line("");
		}
		else
		{
			qsctest_print_line("");
		}

		if (test_confirm("Press 'Y' then Enter to run Symmetric Cipher Speed Tests, any other key to cancel: ") ==  true)
		{
			qsctest_aes_speed_run();
			qsctest_rhx_speed_run();
		}

		qsctest_print_line("Completed! Press any key to close..");
		qsctest_get_wait();
	}
	else
	{
		qsctest_print_line("The test has been cancelled. Press any key to close..");
		qsctest_get_wait();
	}

	return 0;
}

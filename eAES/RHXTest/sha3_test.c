#include "sha3_test.h"
#include "utils.h"
#include "testutils.h"
#include "hash.h"

bool qsctest_cshake_256_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp512a[64] = { 0 };
	uint8_t exp512b[64] = { 0 };
	uint8_t hashb[keccak_rate_256] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[64] = { 0 };
	keccak_state state;
	bool status;

	qsctest_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsctest_hex_to_bin("D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1"
		"64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C", exp512a, sizeof(exp512a));
	qsctest_hex_to_bin("07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917"
		"27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB", exp512b, sizeof(exp512b));

	qsctest_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	cshake256_compute(output, sizeof(output), msg32, sizeof(msg32), name, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp512a, sizeof(exp512a)) == false)
	{
		qsctest_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	cshake256_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp512b, sizeof(exp512b)) == false)
	{
		qsctest_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */


	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	cshake_initialize(&state, keccak_rate_256, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	cshake_squeezeblocks(&state, keccak_rate_256, hashb, 1);

	if (utils_memory_are_equal(hashb, exp512b, sizeof(exp512b)) == false)
	{
		qsctest_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

bool qsctest_cshake_512_kat()
{
	uint8_t exp512[64] = { 0 };
	uint8_t cust[15] = { 0 };
	uint8_t hashb[keccak_rate_512] = { 0 };
	uint8_t msg512[64] = { 0 };
	uint8_t output[64] = { 0 };
	keccak_state state;
	bool status;

	qsctest_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsctest_hex_to_bin("EF4BDC1F2B91B44C51048C81F5499DAC46F38C6E9CD81CEA3CB85E3A1913F8C4"
		"54CFE40F05370F7DE24E50FC49BBD188F42D2439F25DC2B3DB7CA2E38DC7E4A6", exp512, sizeof(exp512));

	qsctest_hex_to_bin("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"
		"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", msg512, sizeof(msg512));

	status = true;

	/* test compact api */

	cshake512_compute(output, sizeof(output), msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp512, sizeof(exp512)) == false)
	{
		qsctest_print_safe("Failure! cshake_512_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(output, sizeof(output));
	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));

	cshake_initialize(&state, keccak_rate_512, msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));
	cshake_squeezeblocks(&state, keccak_rate_512, hashb, 1);

	if (utils_memory_are_equal(hashb, exp512, sizeof(exp512)) == false)
	{
		qsctest_print_safe("Failure! cshake_512_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac_256_kat()
{
	uint8_t cust0[1] = { 0 };
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[64] = { 0 };
	uint8_t exp256b[64] = { 0 };
	uint8_t exp256c[64] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[64] = { 0 };
	keccak_state state;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));

	qsctest_hex_to_bin("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
		"F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD", exp256a, sizeof(exp256a));
	qsctest_hex_to_bin("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691"
		"589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69", exp256b, sizeof(exp256b));
	qsctest_hex_to_bin("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D9"
		"70FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965", exp256c, sizeof(exp256c));

	qsctest_hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));

	qsctest_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	kmac256_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust168, sizeof(cust168));

	if (utils_memory_are_equal(output, exp256a, sizeof(exp256a)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust0, 0);

	if (utils_memory_are_equal(output, exp256b, sizeof(exp256b)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (utils_memory_are_equal(output, exp256c, sizeof(exp256c)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	utils_memory_clear(output, sizeof(output));

	kmac_initialize(&state, keccak_rate_256, key256, sizeof(key256), cust168, sizeof(cust168));
	kmac_update(&state, keccak_rate_256, msg1600, sizeof(msg1600));
	kmac_finalize(&state, keccak_rate_256, output, sizeof(output));

	if (utils_memory_are_equal(output, exp256c, sizeof(exp256c)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac_512_kat()
{
	uint8_t cust0[21] = { 0 };
	uint8_t cust1[42] = { 0 };
	uint8_t cust2[45] = { 0 };
	uint8_t exp0[64] = { 0 };
	uint8_t exp1[64] = { 0 };
	uint8_t exp2[64] = { 0 };
	uint8_t key0[21] = { 0 };
	uint8_t key1[60] = { 0 };
	uint8_t msg0[42] = { 0 };
	uint8_t msg1[84] = { 0 };
	uint8_t output[64] = { 0 };
	keccak_state state;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust0, sizeof(cust0));
	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", cust1, sizeof(cust1));
	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920", cust2, sizeof(cust2));

	qsctest_hex_to_bin("C41F31CEE9851BAA915716C16F7670C7C137C1908BD9694DA80C679AA6EB5964"
		"E76AD91F2018DE576524D84E0B0FC586C06B110ED6DB273A921FFC86D1C20CE8", exp0, sizeof(exp0));
	qsctest_hex_to_bin("6535FB96EAB4F831D801E6C3C6E71755F4A56E8E711D376DDC564F5C6DACB8B5"
		"91EEF0503F433872B401FCEF8F05DA42FB950176C10FDB59395273FB9EDA39B8", exp1, sizeof(exp1));
	qsctest_hex_to_bin("7BA4F7EE765960E6DA15D2CB51775DBA3E7B9279E5740469EF9FFD04C5246091"
		"9A99BEE5BFDA27163E2729A8E3B663BD963EF067C7CCABDE6F6EFFF9093E2A2F", exp2, sizeof(exp2));

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", key0, sizeof(key0));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B", key1, sizeof(key1));

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", msg0, sizeof(msg0));
	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D"
		"7920546167676564204170706C69636174696F6E", msg1, sizeof(msg1));
	status = true;

	/* test compact api */

	kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key0, sizeof(key0), cust0, sizeof(cust0));

	if (utils_memory_are_equal(output, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key1, sizeof(key1), cust2, sizeof(cust2));

	if (utils_memory_are_equal(output, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac512_compute(output, sizeof(output), msg1, sizeof(msg1), key0, sizeof(key0), cust1, sizeof(cust1));

	if (utils_memory_are_equal(output, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	utils_memory_clear(output, sizeof(output));

	kmac_initialize(&state, keccak_rate_512, key0, sizeof(key0), cust1, sizeof(cust1));
	kmac_update(&state, keccak_rate_512, msg1, sizeof(msg1));
	kmac_finalize(&state, keccak_rate_512, output, sizeof(output));

	if (utils_memory_are_equal(output, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

void qsctest_sha3_run()
{
	if (qsctest_cshake_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the cSHAKE-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the cSHAKE-256 KAT test. \n");
	}

	if (qsctest_cshake_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the cSHAKE-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the cSHAKE-512 KAT test. \n");
	}

	if (qsctest_kmac_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-256 KAT test. \n");
	}

	if (qsctest_kmac_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-512 KAT test. \n");
	}
}

#include "rhx_kat.h"
#include "intutils.h"
#include "rhx.h"
#include "sha2.h"
#include "sha3.h"
#include "sysrand.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef RHX_AESNI_ENABLED
#	if defined(_MSC_VER)
#		include <intrin.h>
#	elif defined(__GNUC__)
#		include <x86intrin.h>
#	endif
#endif

static bool aes128_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	uint8_t expf[4 * RHX_BLOCK_SIZE] = { 0 };
	uint8_t inpf[4 * RHX_BLOCK_SIZE] = { 0 };
	uint8_t outf[4 * RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* copy iv to local */
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const rhx_keyparams kp = { key, AES128_KEY_SIZE, ivc };

	status = true;

	/* test the simplified api */

	/* copy split message and expected arrays to full input */
	for (i = 0; i < 4; ++i)
	{
		memcpy(inpf + (i * RHX_BLOCK_SIZE), message[i], RHX_BLOCK_SIZE);
		memcpy(expf + (i * RHX_BLOCK_SIZE), expected[i], RHX_BLOCK_SIZE);
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_encrypt_block(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test the cbc decryption function */
	memcpy(kp.nonce, iv, RHX_BLOCK_SIZE);
	rhx_initialize(&state, &kp, false, AES128);

	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_decrypt_block(&state, out, expected[i]);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes256_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const rhx_keyparams kp = { key, AES256_KEY_SIZE, ivc };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_encrypt_block(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test decryption */
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	rhx_initialize(&state, &kp, false, AES256);

	/* test the cbc decryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_decrypt_block(&state, out, expected[i]);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes128_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t nce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct with key and nonce, info not used in AES */
	memcpy(nce, nonce, RHX_BLOCK_SIZE);
	const rhx_keyparams kp = { key, AES128_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, message[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	memcpy(state.nonce, nonce, RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, expected[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes256_ctr_monte_carlo(uint8_t* key, const uint8_t* nonce, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t nce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct with key and nonce, info is optional */
	memcpy(nce, nonce, RHX_BLOCK_SIZE);
	rhx_keyparams kp = { key, AES256_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, message[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	memcpy(state.nonce, nonce, RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, expected[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes128_ecb_monte_carlo(uint8_t* key, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES128_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_encrypt_block(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, AES128);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_decrypt_block(&state, out, expected[i]);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes256_ecb_monte_carlo(uint8_t* key, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES256_KEY_SIZE };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_encrypt_block(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state  */
	rhx_initialize(&state, &kp, false, AES256);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_decrypt_block(&state, out, expected[i]);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static void print_array8(const uint8_t* a, size_t count, size_t line)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		if (i != 0 && i % line == 0)
		{
			printf("\n");
		}

		printf("0x%02X, ", a[i]);
	}
}

static void print_array32(const uint32_t* a, size_t count, size_t line)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		if (i != 0 && i % line == 0)
		{
			printf("\n");
		}

		printf("%d ", a[i]);
	}
}

static bool rhx256_ecb_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
{
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE };

	memcpy(msg, message, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX256);

	/* test the ecb encryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_encrypt_block(&state, enc, msg);
		memcpy(msg, enc, RHX_BLOCK_SIZE);
	}

	if (are_equal8(expected, enc, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, RHX256);

	/* test the ecb decryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_decrypt_block(&state, msg, enc);
		memcpy(enc, msg, RHX_BLOCK_SIZE);
	}

	if (are_equal8(message, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool rhx512_ecb_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
{
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE };

	memcpy(msg, message, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX512);

	/* test the ecb encryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_encrypt_block(&state, enc, msg);
		memcpy(msg, enc, RHX_BLOCK_SIZE);
	}

	if (are_equal8(expected, enc, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, RHX512);

	/* test the ecb decryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_decrypt_block(&state, msg, enc);
		memcpy(enc, msg, RHX_BLOCK_SIZE);
	}

	if (are_equal8(message, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

bool aes128_cbc_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F2.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, RHX_BLOCK_SIZE);
	hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, RHX_BLOCK_SIZE);

	hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], RHX_BLOCK_SIZE);
	hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], RHX_BLOCK_SIZE);
	hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], RHX_BLOCK_SIZE);
	hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

bool aes256_cbc_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX256_KEY_SIZE);
	hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, RHX_BLOCK_SIZE);

	hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], RHX_BLOCK_SIZE);
	hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], RHX_BLOCK_SIZE);
	hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], RHX_BLOCK_SIZE);
	hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

bool aes128_ctr_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, RHX_BLOCK_SIZE);
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, RHX_BLOCK_SIZE);

	hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], RHX_BLOCK_SIZE);
	hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], RHX_BLOCK_SIZE);
	hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], RHX_BLOCK_SIZE);
	hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

bool aes256_ctr_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX256_KEY_SIZE);
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, RHX_BLOCK_SIZE);

	hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], RHX_BLOCK_SIZE);
	hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], RHX_BLOCK_SIZE);
	hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], RHX_BLOCK_SIZE);
	hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

bool aes128_ecb_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F1.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, RHX_BLOCK_SIZE);

	hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], RHX_BLOCK_SIZE);
	hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], RHX_BLOCK_SIZE);
	hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], RHX_BLOCK_SIZE);
	hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

bool aes256_ecb_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX256_KEY_SIZE);

	hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], RHX_BLOCK_SIZE);
	hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], RHX_BLOCK_SIZE);
	hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], RHX_BLOCK_SIZE);
	hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

bool rhx256_ctr_stress_test()
{
	uint8_t dec[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t enc[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 1 };
	uint8_t msg[CTR_OUTPUT_LENGTH] = { 128 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE, nonce, NULL, 0 };

	status = true;

	/* initialize the state */
	rhx_initialize(&state, &kp, true, RHX256);

	/* encrypt the array */
	rhx_ctr_transform(&state, enc, msg, CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(state.nonce, 0x00, RHX_BLOCK_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	rhx_initialize(&state, &kp, true, RHX256);

	/* test decryption by using ciphertest as input */
	rhx_ctr_transform(&state, dec, enc, CTR_OUTPUT_LENGTH);

	if (are_equal8(dec, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

bool rhx512_ctr_stress_test()
{
	uint8_t dec[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t enc[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t key[RHX512_KEY_SIZE] = { 1 };
	uint8_t msg[CTR_OUTPUT_LENGTH] = { 128 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE, nonce, NULL, 0 };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX512);

	/* encrypt the array */
	rhx_ctr_transform(&state, enc, msg, CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(state.nonce, 0x00, RHX_BLOCK_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	rhx_initialize(&state, &kp, true, RHX512);

	/* test decryption by using ciphertest as input */
	rhx_ctr_transform(&state, dec, enc, CTR_OUTPUT_LENGTH);

	if (are_equal8(dec, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

bool rhx256_ecb_kat_test()
{
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* vectors from CEX */
#ifdef RHX_SHAKE_EXTENSION
	hex_to_bin("B93AF9A0635964EE2DD1600A95C56905", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("356FE2F76E8954C8292C4FE4EFD52A2C", exp, RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX256_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX256);

	/* test encryption */
	rhx_ecb_encrypt_block(&state, otp, msg);

	if (are_equal8(otp, exp, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, RHX256);

	/* test decryption */
	rhx_ecb_decrypt_block(&state, dec, otp);

	if (are_equal8(dec, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

bool rhx512_ecb_kat_test()
{
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* vectors from CEX */
#ifdef RHX_SHAKE_EXTENSION
	hex_to_bin("4F9D61042EC51DADAB25F081A3E79AF1", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("C23E5C88453124D46B81D7229C6A409F", exp, RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX512_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX512);

	/* test encryption */
	rhx_ecb_encrypt_block(&state, otp, msg);

	if (are_equal8(otp, exp, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state for encryption */
	rhx_initialize(&state, &kp, false, RHX512);

	/* test decryption */
	rhx_ecb_decrypt_block(&state, dec, otp);

	if (are_equal8(dec, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

bool rhx256_monte_carlo_test()
{
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	bool status;

	/* original vectors */

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX256_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

#ifdef RHX_SHAKE_EXTENSION
	hex_to_bin("6DED2973243BCD846C4D98C1BF636FB3", exp, RHX_BLOCK_SIZE);
#else
	hex_to_bin("C4E3D76961144D5F1BAC6C0DE5078597", exp, RHX_BLOCK_SIZE);
#endif

	status = rhx256_ecb_monte_carlo(key, msg, exp);

	return status;
}

bool rhx512_monte_carlo_test()
{
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	bool status;

	/* original vectors */

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX512_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

#ifdef RHX_SHAKE_EXTENSION
	hex_to_bin("FB8977B80F5B0B7C2E4048DF590EB2F6", exp, RHX_BLOCK_SIZE);
#else
	hex_to_bin("3CC3EB49D4328762000EB0D6DB3924E1", exp, RHX_BLOCK_SIZE);
#endif

	status = rhx512_ecb_monte_carlo(key, msg, exp);

	return status;
}

bool hba_rhx256_kat_test()
{
	uint8_t aad1[20] = { 0 };
	uint8_t aad2[20] = { 0 };
	uint8_t aad3[20] = { 0 };
	uint8_t dec1[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec2[RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t dec3[RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t exp1[RHX_BLOCK_SIZE + HBA256_MAC_LENGTH] = { 0 };
	uint8_t exp2[(RHX_BLOCK_SIZE * 2) + HBA256_MAC_LENGTH] = { 0 };
	uint8_t exp3[(RHX_BLOCK_SIZE * 4) + HBA256_MAC_LENGTH] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 0 };
	uint8_t msg1[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg2[RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t msg3[RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t nce1[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce2[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce3[RHX_BLOCK_SIZE] = { 0 };
	uint8_t n1copy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t n2copy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t n3copy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc1[RHX_BLOCK_SIZE + HBA256_MAC_LENGTH] = { 0 };
	uint8_t enc2[(RHX_BLOCK_SIZE * 2) + HBA256_MAC_LENGTH] = { 0 };
	uint8_t enc3[(RHX_BLOCK_SIZE * 4) + HBA256_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#ifdef HBA_KMAC_AUTH
	hex_to_bin("441EF350998DF4C94E1B213E8788200476C92EA60C002D8ABFB814473410AA44FBBC896656D260280F8FC9421694FCDB", exp1, sizeof(exp1));
	hex_to_bin("B6488F5240861A271F9D0DC60101EE11EBE18A8E7D7226787CBAAD6DA1D139EEB5CAD502C4A3CCBEFED40E47693684ADD4A52E2B86B2DB73CBFCD760D23E9B06", exp2, sizeof(exp2));
	hex_to_bin("87CF79C66478E372F5BD7C0273D25BE8614A7A30FAD3B26C48F9B63EA6C2FDF5E1D154959DA4042AD37955882BD54345D6D5071506148783554EE1D9D0628EC0"
		"BE479E0ED2B91BB8752D25638E9B2C34A61016C6378B1DDB3327E7C7AFE34A63", exp3, sizeof(exp3));
#else
	hex_to_bin("4D84CB3748DB5306B57937A249BDC350393C51167DAFEDFEA08D1D34A89416A0E12030E428E88AC1E614D1F401D7083B", exp1, sizeof(exp1));
	hex_to_bin("0FF25E320AFE0A14953C2C40CB95F185C4F660743655C4952B3A854178EC1D927458CAD7B321A5C14E3FC7B2EA616ED7ED50F1E7EB4D9BF60F12611BC95EAF61", exp2, sizeof(exp2));
	hex_to_bin("295DCEF3149C7E6D7BE16E41595EA160B9562D25D1F46A83E80EADE187B7802A534D3AB9284DD8BEBE13F0AD01BEE7B73CE82914E7FB5A29856A345D95ACD620"
		"01D6180A4A4B966FAB12D223C6A2CE21BE1C496A10B90BADA01D048A38D41DEB", exp3, sizeof(exp3));
#endif
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	memcpy(n1copy, nce1, RHX_BLOCK_SIZE);
	memcpy(n2copy, nce2, RHX_BLOCK_SIZE);
	memcpy(n3copy, nce3, RHX_BLOCK_SIZE);

	/* first KAT vector */

	hba_state state;

	const rhx_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	hba_rhx256_initialize(&state, &kp1, true);
	hba_set_associated(&state, aad1, sizeof(aad1));

	if (hba_rhx256_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp1.nonce, n1copy, RHX_BLOCK_SIZE);

	hba_rhx256_initialize(&state, &kp1, false);
	hba_set_associated(&state, aad1, sizeof(aad1));

	if (hba_rhx256_transform(&state, dec1, enc1, sizeof(enc1) - HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const rhx_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	hba_rhx256_initialize(&state, &kp2, true);
	hba_set_associated(&state, aad2, sizeof(aad2));

	if (hba_rhx256_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp2.nonce, n2copy, RHX_BLOCK_SIZE);

	hba_rhx256_initialize(&state, &kp2, false);
	hba_set_associated(&state, aad2, sizeof(aad2));

	if (hba_rhx256_transform(&state, dec2, enc2, sizeof(enc2) - HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const rhx_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	hba_rhx256_initialize(&state, &kp3, true);
	hba_set_associated(&state, aad3, sizeof(aad3));

	if (hba_rhx256_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp3.nonce, n3copy, RHX_BLOCK_SIZE);

	hba_rhx256_initialize(&state, &kp3, false);
	hba_set_associated(&state, aad3, sizeof(aad3));

	if (hba_rhx256_transform(&state, dec3, enc3, sizeof(enc3) - HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (are_equal8(dec3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	return status;
}

bool hba_rhx512_kat_test()
{
	uint8_t aad1[20] = { 0 };
	uint8_t aad2[20] = { 0 };
	uint8_t aad3[20] = { 0 };
	uint8_t dec1[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec2[RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t dec3[RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t exp1[RHX_BLOCK_SIZE + HBA512_MAC_LENGTH] = { 0 };
	uint8_t exp2[(RHX_BLOCK_SIZE * 2) + HBA512_MAC_LENGTH] = { 0 };
	uint8_t exp3[(RHX_BLOCK_SIZE * 4) + HBA512_MAC_LENGTH] = { 0 };
	uint8_t key[RHX512_KEY_SIZE] = { 0 };
	uint8_t msg1[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg2[RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t msg3[RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t nce1[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce2[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce3[RHX_BLOCK_SIZE] = { 0 };
	uint8_t n1copy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t n2copy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t n3copy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc1[RHX_BLOCK_SIZE + HBA512_MAC_LENGTH] = { 0 };
	uint8_t enc2[(RHX_BLOCK_SIZE * 2) + HBA512_MAC_LENGTH] = { 0 };
	uint8_t enc3[(RHX_BLOCK_SIZE * 4) + HBA512_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#ifdef HBA_KMAC_AUTH
	hex_to_bin("98C4B8D42A5CB9F9CFDFC1EEB990DB50B3B712C5A6795AD0FF55C8796FEA63446549943738806B4C74A94664556B305C18D06B724A9D1B5C1D23863BC0024B23"
		"8EBB9015242C7A608961CEC6B255437B", exp1, sizeof(exp1));
	hex_to_bin("E016F0FD9C83AA0D4B06D91AFBA442BE32DEF9B080296163841DD1BADEB2A8302B79BA21CD0EC11A9A5556596F52353AFA526DE0D92C72D80C4A97B81FF8312B"
		"351D616F53C8FCC9C37F37079B48B8930BD2A607BCB4FCE3E1B046906F2D95D8", exp2, sizeof(exp2));
	hex_to_bin("87E21FE9F9E5BFA877027159EE9BB7C74BE3FDD366F9199DEB4C2D179A291F9C6BF4D2747401B815588E06239E21DAC126599D33B416EE5A0236F00E42063B25"
		"E7B295481FC7BBEAF2C263C0E5A9C638CB2502B1F6583700118BB9E3EE417FBF0865BB4996192A55ED2BB0B843B6E777F24212F22E1F78F5AF3AF6A40D2233C4", exp3, sizeof(exp3));
#else
	hex_to_bin("3A8D794EE017CDC58589F8B6738ADA41D963325F6F192F969D72C898742DE6FF72185593DE64588BA9DDBB0FA74E11B2833F30E4B1EB4B6678E14DF9FD8EF3A0"
		"7E22FC0D33009C1BF8BD49119DA8BFC8", exp1, sizeof(exp1));
	hex_to_bin("0F88C8A8785FE66989DE8E8645F72ECAA6B1C6A19641A704FD4DA44236EED54F0F5D6F8F76FEAB328A23A6F68D6CB46CDA62DFE0B938F491607A432B684AE4F4"
		"5BF2FC0E371E5515CAF58CE18C38C2F7A624D9BF15B72BCACCD826D2BBF68D31", exp2, sizeof(exp2));
	hex_to_bin("22E280BCD9C51E57816EC7FE84413C9C787C4E8F777182FE6C0AD6A52ECE844341A00DD22295DCB8864B5BAF73038DFA016FCDA97E421AC281BF967457B97F88"
		"BA792EE35320C49836193B775DE1EA61B04D8CACF02C922B17ADA9B0F092281B65630B1B36C63B9B9C24E73A317B82BEFD8B9832BE7505D52B62775680A362FF", exp3, sizeof(exp3));
#endif
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	memcpy(n1copy, nce1, RHX_BLOCK_SIZE);
	memcpy(n2copy, nce2, RHX_BLOCK_SIZE);
	memcpy(n3copy, nce3, RHX_BLOCK_SIZE);

	/* first KAT vector */

	hba_state state;

	const rhx_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	hba_rhx512_initialize(&state, &kp1, true);
	hba_set_associated(&state, aad1, sizeof(aad1));

	if (hba_rhx512_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp1.nonce, n1copy, RHX_BLOCK_SIZE);

	hba_rhx512_initialize(&state, &kp1, false);
	hba_set_associated(&state, aad1, sizeof(aad1));

	if (hba_rhx512_transform(&state, dec1, enc1, sizeof(enc1) - HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const rhx_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	hba_rhx512_initialize(&state, &kp2, true);
	hba_set_associated(&state, aad2, sizeof(aad2));

	if (hba_rhx512_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp2.nonce, n2copy, RHX_BLOCK_SIZE);

	hba_rhx512_initialize(&state, &kp2, false);
	hba_set_associated(&state, aad2, sizeof(aad2));

	if (hba_rhx512_transform(&state, dec2, enc2, sizeof(enc2) - HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const rhx_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	hba_rhx512_initialize(&state, &kp3, true);
	hba_set_associated(&state, aad3, sizeof(aad3));

	if (hba_rhx512_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp3.nonce, n3copy, RHX_BLOCK_SIZE);

	hba_rhx512_initialize(&state, &kp3, false);
	hba_set_associated(&state, aad3, sizeof(aad3));

	if (hba_rhx512_transform(&state, dec3, enc3, sizeof(enc3) - HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (are_equal8(dec3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	return status;
}

bool hba_rhx256_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	hba_state state;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy));

	tctr = 0;
	status = true;

	while (tctr < HBA_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			sysrand_getbytes(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + HBA256_MAC_LENGTH);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			clear8(dec, mlen);
			clear8(enc, mlen + HBA256_MAC_LENGTH);
			clear8(msg, mlen);
			memcpy(nonce, ncopy, RHX_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			sysrand_getbytes(msg, mlen);

			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			hba_rhx256_initialize(&state, &kp1, true);
			hba_set_associated(&state, aad, sizeof(aad));

			if (hba_rhx256_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, RHX_BLOCK_SIZE);

			/* decrypt the message */
			hba_rhx256_initialize(&state, &kp1, false);
			hba_set_associated(&state, aad, sizeof(aad));

			if (hba_rhx256_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}


			/* compare decryption output to message */
			if (are_equal8(dec, msg, sizeof(msg)) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}

bool hba_rhx512_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	hba_state state;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy));

	tctr = 0;
	status = true;

	while (tctr < HBA_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			sysrand_getbytes(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + HBA512_MAC_LENGTH);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			clear8(dec, mlen);
			clear8(enc, mlen + HBA512_MAC_LENGTH);
			clear8(msg, mlen);
			memcpy(nonce, ncopy, RHX_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			sysrand_getbytes(msg, mlen);

			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			hba_rhx512_initialize(&state, &kp1, true);
			hba_set_associated(&state, aad, sizeof(aad));

			if (hba_rhx512_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, RHX_BLOCK_SIZE);

			/* decrypt the message */
			hba_rhx512_initialize(&state, &kp1, false);
			hba_set_associated(&state, aad, sizeof(aad));

			if (hba_rhx512_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}


			/* compare decryption output to message */
			if (are_equal8(dec, msg, sizeof(msg)) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}

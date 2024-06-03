#include "selftest.h"
#include "utils.h"
#include "rhx.h"
#include "hash.h"
#include <stdio.h>

#define CTR_OUTPUT_LENGTH 33
#define MONTE_CARLO_CYCLES 10000
#define HBA_TEST_CYCLES 100

/***RHX***/

static void hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	size_t  pos;
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	memset(output, 0, length);

	for (pos = 0; pos < (length * 2); pos += 2)
	{
		idx0 = ((uint8_t)hexstr[pos + 0] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void print_safe(const char* input)
{
	if (input != NULL)
	{
#if defined(_MSC_VER)
		printf_s(input);
#else
		printf("%s", input);
#endif
	}
}

static bool aes128_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[RHX_BLOCK_SIZE] = { 0 };
	uint8_t expf[4 * RHX_BLOCK_SIZE] = { 0 };
	uint8_t inpf[4 * RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* copy iv to local */
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const rhx_keyparams kp = { key, RHX_AES128_KEY_SIZE, ivc };

	status = true;

	/* test the simplified api */

	/* copy split message and expected arrays to full input */
	for (i = 0; i < 4; ++i)
	{
		memcpy((uint8_t*)(inpf + (i * RHX_BLOCK_SIZE)), message[i], RHX_BLOCK_SIZE);
		memcpy((uint8_t*)(expf + (i * RHX_BLOCK_SIZE)), expected[i], RHX_BLOCK_SIZE);
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_encrypt_block(&state, out, message[i]);

		if (utils_memory_are_equal(out, expected[i], RHX_BLOCK_SIZE) == false)
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

		if (utils_memory_are_equal(out, message[i], RHX_BLOCK_SIZE) == false)
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
	const rhx_keyparams kp = { key, RHX_AES256_KEY_SIZE, ivc };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_encrypt_block(&state, out, message[i]);

		if (utils_memory_are_equal(out, expected[i], RHX_BLOCK_SIZE) == false)
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

		if (utils_memory_are_equal(out, message[i], RHX_BLOCK_SIZE) == false)
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
	const rhx_keyparams kp = { key, RHX_AES128_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctrbe_transform(&state, out, message[i], RHX_BLOCK_SIZE);

		if (utils_memory_are_equal(out, expected[i], RHX_BLOCK_SIZE) == false)
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
		rhx_ctrbe_transform(&state, out, expected[i], RHX_BLOCK_SIZE);

		if (utils_memory_are_equal(out, message[i], RHX_BLOCK_SIZE) == false)
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
	rhx_keyparams kp = { key, RHX_AES256_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctrbe_transform(&state, out, message[i], RHX_BLOCK_SIZE);

		if (utils_memory_are_equal(out, expected[i], RHX_BLOCK_SIZE) == false)
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
		rhx_ctrbe_transform(&state, out, expected[i], RHX_BLOCK_SIZE);

		if (utils_memory_are_equal(out, message[i], RHX_BLOCK_SIZE) == false)
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
	rhx_keyparams kp = { key, RHX_AES128_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES128);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_encrypt_block(&state, out, message[i]);

		if (utils_memory_are_equal(out, expected[i], RHX_BLOCK_SIZE) == false)
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

		if (utils_memory_are_equal(out, message[i], RHX_BLOCK_SIZE) == false)
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
	rhx_keyparams kp = { key, RHX_AES256_KEY_SIZE };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, AES256);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_encrypt_block(&state, out, message[i]);

		if (utils_memory_are_equal(out, expected[i], RHX_BLOCK_SIZE) == false)
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

		if (utils_memory_are_equal(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool rhx256_ecb_monte_carlo()
{
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t enc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	uint8_t tmp[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;


	/* initialize the key parameters struct, info is optional */
	utils_seed_generate(key, sizeof(msg));
	utils_seed_generate(key, sizeof(key));
	rhx_keyparams kp = { key, RHX_RHX256_KEY_SIZE };

	memcpy(tmp, msg, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX256);

	/* test the ecb encryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_encrypt_block(&state, enc, tmp);
		memcpy(tmp, enc, RHX_BLOCK_SIZE);
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, RHX256);

	/* test the ecb decryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_decrypt_block(&state, tmp, enc);
		memcpy(enc, tmp, RHX_BLOCK_SIZE);
	}

	if (utils_memory_are_equal(tmp, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool rhx512_ecb_monte_carlo()
{
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t enc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	uint8_t tmp[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;


	/* initialize the key parameters struct, info is optional */
	utils_seed_generate(key, sizeof(msg));
	utils_seed_generate(key, sizeof(key));
	rhx_keyparams kp = { key, RHX_RHX512_KEY_SIZE };

	memcpy(tmp, msg, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX256);

	/* test the ecb encryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_encrypt_block(&state, enc, tmp);
		memcpy(tmp, enc, RHX_BLOCK_SIZE);
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, RHX256);

	/* test the ecb decryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_decrypt_block(&state, tmp, enc);
		memcpy(enc, tmp, RHX_BLOCK_SIZE);
	}

	if (utils_memory_are_equal(tmp, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes128_cbc_fips_test()
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

static bool aes256_cbc_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX_RHX256_KEY_SIZE);
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

static bool aes128_ctr_fips_test()
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

static bool aes256_ctr_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX_RHX256_KEY_SIZE);
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

static bool aes128_ecb_fips_test()
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

static bool aes256_ecb_fips_test()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX_RHX256_KEY_SIZE);

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

static bool rhx256_ecb_kat_test()
{
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* vectors from CEX */
#if defined(RHX_SHAKE_EXTENSION)
	hex_to_bin("B93AF9A0635964EE2DD1600A95C56905", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("356FE2F76E8954C8292C4FE4EFD52A2C", exp, RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX_RHX256_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX_RHX256_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX256);

	/* test encryption */
	rhx_ecb_encrypt_block(&state, otp, msg);

	if (utils_memory_are_equal(otp, exp, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false, RHX256);

	/* test decryption */
	rhx_ecb_decrypt_block(&state, dec, otp);

	if (utils_memory_are_equal(dec, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool rhx512_ecb_kat_test()
{
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* vectors from CEX */
#if defined(RHX_SHAKE_EXTENSION)
	hex_to_bin("4F9D61042EC51DADAB25F081A3E79AF1", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("C23E5C88453124D46B81D7229C6A409F", exp, RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX_RHX512_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX_RHX512_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true, RHX512);

	/* test encryption */
	rhx_ecb_encrypt_block(&state, otp, msg);

	if (utils_memory_are_equal(otp, exp, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state for encryption */
	rhx_initialize(&state, &kp, false, RHX512);

	/* test decryption */
	rhx_ecb_decrypt_block(&state, dec, otp);

	if (utils_memory_are_equal(dec, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

/***SHA2***/

static bool sha2_256_kat()
{
	uint8_t exp0[SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp1[SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp2[SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp3[SHA2_256_HASH_SIZE] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[SHA2_256_HASH_SIZE] = { 0 };
	sha256_state state;
	bool status;

	hex_to_bin("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", exp0, sizeof(exp0));
	hex_to_bin("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", exp1, sizeof(exp1));
	hex_to_bin("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1", exp2, sizeof(exp2));
	hex_to_bin("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1", exp3, sizeof(exp3));

	hex_to_bin("00", msg0, sizeof(msg0));
	hex_to_bin("616263", msg1, sizeof(msg1));
	hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	sha256_compute(otp, msg0, 0);

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha256_compute(otp, msg1, sizeof(msg1));

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha256_compute(otp, msg2, sizeof(msg2));

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha256_compute(otp, msg3, sizeof(msg3));

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(otp, sizeof(otp));

	sha256_initialize(&state);
	sha256_update(&state, msg0, 0);
	sha256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha256_initialize(&state);
	sha256_update(&state, msg1, sizeof(msg1));
	sha256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha256_initialize(&state);
	sha256_update(&state, msg2, sizeof(msg2));
	sha256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha256_initialize(&state);

	/* absorb a the message */
	sha256_update(&state, msg3, sizeof(msg3));

	/* finalize the hash */
	sha256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp3, SHA2_256_HASH_SIZE) != true)
	{
		print_safe("Failure! sha2_256_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

static bool sha2_512_kat()
{
	uint8_t exp0[SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp1[SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp2[SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp3[SHA2_512_HASH_SIZE] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[SHA2_512_HASH_SIZE] = { 0 };
	sha512_state state;
	bool status;

	hex_to_bin("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"
		"47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E", exp0, sizeof(exp0));
	hex_to_bin("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
		"2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F", exp1, sizeof(exp1));
	hex_to_bin("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C335"
		"96FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445", exp2, sizeof(exp2));
	hex_to_bin("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"
		"501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909", exp3, sizeof(exp3));

	hex_to_bin("00", msg0, sizeof(msg0));
	hex_to_bin("616263", msg1, sizeof(msg1));
	hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	sha512_compute(otp, msg0, 0);

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha512_compute(otp, msg1, sizeof(msg1));

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha512_compute(otp, msg2, sizeof(msg2));

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha512_compute(otp, msg3, sizeof(msg3));

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(otp, sizeof(otp));
	sha512_initialize(&state);
	sha512_update(&state, msg0, 0);
	sha512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha512_initialize(&state);
	sha512_update(&state, msg1, sizeof(msg1));
	sha512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha512_initialize(&state);
	sha512_update(&state, msg2, sizeof(msg2));
	sha512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	sha512_initialize(&state);
	sha512_update(&state, msg3, sizeof(msg3));
	sha512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! sha2_512_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

static bool hkdf_256_kat()
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	hex_to_bin("D03C9AB82C884B1DCFD3F4CFFD0E4AD1501915E5D72DF0E6D846D59F6CF78047"
		"39958B5DF06BDE49DB6D", exp0, sizeof(exp0));
	hex_to_bin("24B29E50BD5B2968A8FC1B030B52A07B3B87C45603AAA046D649CD3CAAE06D5C"
		"B029960513275DF28548068821DF861904F0C095D063097A61EF571687217603"
		"E7D7673A7F98AEC538879E81E80864A91BCC", exp1, sizeof(exp1));
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	hkdf256_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (utils_memory_are_equal(otp0, exp0, sizeof(otp0)) != true)
	{
		print_safe("Failure! hkdf_256_kat: output does not match the known answer -HK1 \n");
		status = false;
	}

	hkdf256_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (utils_memory_are_equal(otp1, exp1, sizeof(otp1)) != true)
	{
		print_safe("Failure! hkdf_256_kat: output does not match the known answer -HK2 \n");
		status = false;
	}

	return status;
}

static bool hkdf_512_kat()
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	hex_to_bin("7CE212EEB2A92270C4460A4728944B9B0EE9E060DE13C197853D37A20CE7184F"
		"94390EAEA4C18CEF989D", exp0, sizeof(exp0));
	hex_to_bin("C66BAAA5CFB588D3B99CCC193005CD39C7CBAB0E6682F95E4E7D8B5A92EE3031"
		"6D59BC93F6E2BAC696A05BF448E2C088632691CC9CD3B238042FE564439B9074"
		"5DD4E27DC0E6D779129657F3CF424CA207F3", exp1, sizeof(exp1));
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	hkdf512_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (utils_memory_are_equal(otp0, exp0, sizeof(otp0)) != true)
	{
		print_safe("Failure! hkdf_512_kat: output does not match the known answer -HK1 \n");
		status = false;
	}

	hkdf512_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (utils_memory_are_equal(otp1, exp1, sizeof(otp1)) != true)
	{
		print_safe("Failure! hkdf_512_kat: output does not match the known answer -HK2 \n");
		status = false;
	}

	return status;
}

static bool hmac_256_kat()
{
	uint8_t exp0[HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp1[HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp2[HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp3[HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp4[HMAC_256_MAC_SIZE] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t key4[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t msg4[152] = { 0 };
	uint8_t otp[HMAC_256_MAC_SIZE] = { 0 };
	hmac256_state state;
	bool status;

	hex_to_bin("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7", exp0, sizeof(exp0));
	hex_to_bin("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE", exp1, sizeof(exp1));
	hex_to_bin("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B", exp2, sizeof(exp2));
	hex_to_bin("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54", exp3, sizeof(exp3));
	hex_to_bin("9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2", exp4, sizeof(exp4));

	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key3, sizeof(key3));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key4, sizeof(key4));

	hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));
	hex_to_bin("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
		"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
		"642062792074686520484D414320616C676F726974686D2E", msg4, sizeof(msg4));

	status = true;

	/* test compact api */

	hmac256_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK1 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK2 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK3 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK4 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_compute(otp, msg4, sizeof(msg4), key4, sizeof(key4));

	if (utils_memory_are_equal(otp, exp4, sizeof(exp4)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK5 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(otp, sizeof(otp));
	hmac256_initialize(&state, key0, sizeof(key0));
	hmac256_update(&state, msg0, sizeof(msg0));
	hmac256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK6 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_initialize(&state, key1, sizeof(key1));
	hmac256_update(&state, msg1, sizeof(msg1));
	hmac256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK7 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_initialize(&state, key2, sizeof(key2));
	hmac256_update(&state, msg2, sizeof(msg2));
	hmac256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK8 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_initialize(&state, key3, sizeof(key3));
	hmac256_update(&state, msg3, sizeof(msg3));
	hmac256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK9 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac256_initialize(&state, key4, sizeof(key4));
	hmac256_update(&state, msg4, sizeof(msg4));
	hmac256_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp4, sizeof(exp4)) != true)
	{
		print_safe("Failure! hmac_256_kat: output does not match the known answer -MK10 \n");
		status = false;
	}

	return status;
}

static bool hmac_512_kat()
{
	uint8_t exp0[HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp1[HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp2[HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp3[HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp4[HMAC_512_MAC_SIZE] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t key4[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t msg4[152] = { 0 };
	uint8_t otp[HMAC_512_MAC_SIZE] = { 0 };
	hmac512_state state;
	bool status;

	hex_to_bin("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854", exp0, sizeof(exp0));
	hex_to_bin("FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB", exp1, sizeof(exp1));
	hex_to_bin("B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD", exp2, sizeof(exp2));
	hex_to_bin("80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598", exp3, sizeof(exp3));
	hex_to_bin("E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58", exp4, sizeof(exp4));

	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key3, sizeof(key3));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key4, sizeof(key4));

	hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));
	hex_to_bin("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
		"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
		"642062792074686520484D414320616C676F726974686D2E", msg4, sizeof(msg4));

	status = true;

	/* test compact api */

	hmac512_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK1 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK2 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK3 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK4 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_compute(otp, msg4, sizeof(msg4), key4, sizeof(key4));

	if (utils_memory_are_equal(otp, exp4, sizeof(exp4)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK5 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(otp, sizeof(otp));
	hmac512_initialize(&state, key0, sizeof(key0));
	hmac512_update(&state, msg0, sizeof(msg0));
	hmac512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp0, sizeof(exp0)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK6 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_initialize(&state, key1, sizeof(key1));
	hmac512_update(&state, msg1, sizeof(msg1));
	hmac512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp1, sizeof(exp1)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK7 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_initialize(&state, key2, sizeof(key2));
	hmac512_update(&state, msg2, sizeof(msg2));
	hmac512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp2, sizeof(exp2)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK8 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_initialize(&state, key3, sizeof(key3));
	hmac512_update(&state, msg3, sizeof(msg3));
	hmac512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp3, sizeof(exp3)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK9 \n");
		status = false;
	}

	utils_memory_clear(otp, sizeof(otp));
	hmac512_initialize(&state, key4, sizeof(key4));
	hmac512_update(&state, msg4, sizeof(msg4));
	hmac512_finalize(&state, otp);

	if (utils_memory_are_equal(otp, exp4, sizeof(exp4)) != true)
	{
		print_safe("Failure! hmac_512_kat: output does not match the known answer -MK10 \n");
		status = false;
	}

	return status;
}

/***SHA3***/

static bool cshake_128_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t hashb[KECCAK_128_RATE] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[32] = { 0 };
	keccak_state state;
	bool status;

	hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	hex_to_bin("C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5", exp256a, sizeof(exp256a));
	hex_to_bin("C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B", exp256b, sizeof(exp256b));

	hex_to_bin("00010203", msg32, sizeof(msg32));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	cshake128_compute(output, sizeof(output), msg32, sizeof(msg32), name, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp256a, sizeof(exp256a)) == false)
	{
		print_safe("Failure! cshake_128_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	cshake128_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp256b, sizeof(exp256b)) == false)
	{
		print_safe("Failure! cshake_128_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	cshake_initialize(&state, KECCAK_128_RATE, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	cshake_squeezeblocks(&state, KECCAK_128_RATE, hashb, 1);

	if (utils_memory_are_equal(hashb, exp256b, sizeof(exp256b)) == false)
	{
		print_safe("Failure! cshake_128_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

static bool cshake_256_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp512a[64] = { 0 };
	uint8_t exp512b[64] = { 0 };
	uint8_t hashb[KECCAK_256_RATE] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[64] = { 0 };
	keccak_state state;
	bool status;

	hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	hex_to_bin("D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1"
		"64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C", exp512a, sizeof(exp512a));
	hex_to_bin("07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917"
		"27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB", exp512b, sizeof(exp512b));

	hex_to_bin("00010203", msg32, sizeof(msg32));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
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
		print_safe("Failure! cshake_256_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	cshake256_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp512b, sizeof(exp512b)) == false)
	{
		print_safe("Failure! cshake_256_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */


	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	cshake_initialize(&state, KECCAK_256_RATE, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	cshake_squeezeblocks(&state, KECCAK_256_RATE, hashb, 1);

	if (utils_memory_are_equal(hashb, exp512b, sizeof(exp512b)) == false)
	{
		print_safe("Failure! cshake_256_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

static bool cshake_512_kat()
{
	uint8_t exp512[64] = { 0 };
	uint8_t cust[15] = { 0 };
	uint8_t hashb[KECCAK_512_RATE] = { 0 };
	uint8_t msg512[64] = { 0 };
	uint8_t output[64] = { 0 };
	keccak_state state;
	bool status;

	hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	hex_to_bin("EF4BDC1F2B91B44C51048C81F5499DAC46F38C6E9CD81CEA3CB85E3A1913F8C4"
		"54CFE40F05370F7DE24E50FC49BBD188F42D2439F25DC2B3DB7CA2E38DC7E4A6", exp512, sizeof(exp512));

	hex_to_bin("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"
		"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", msg512, sizeof(msg512));

	status = true;

	/* test compact api */

	cshake512_compute(output, sizeof(output), msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));

	if (utils_memory_are_equal(output, exp512, sizeof(exp512)) == false)
	{
		print_safe("Failure! cshake_512_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(output, sizeof(output));
	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));

	cshake_initialize(&state, KECCAK_512_RATE, msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));
	cshake_squeezeblocks(&state, KECCAK_512_RATE, hashb, 1);

	if (utils_memory_are_equal(hashb, exp512, sizeof(exp512)) == false)
	{
		print_safe("Failure! cshake_512_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	return status;
}

static bool kmac_128_kat()
{
	uint8_t cust0[1] = { 0 };
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t exp256c[32] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[32] = { 0 };
	keccak_state state;
	bool status;

	hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));

	hex_to_bin("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E", exp256a, sizeof(exp256a));
	hex_to_bin("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5", exp256b, sizeof(exp256b));
	hex_to_bin("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230", exp256c, sizeof(exp256c));

	hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));

	hex_to_bin("00010203", msg32, sizeof(msg32));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	kmac128_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust0, 0);

	if (utils_memory_are_equal(output, exp256a, sizeof(exp256a)) == false)
	{
		print_safe("Failure! kmac_128_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac128_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust168, sizeof(cust168));

	if (utils_memory_are_equal(output, exp256b, sizeof(exp256b)) == false)
	{
		print_safe("Failure! kmac_128_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac128_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (utils_memory_are_equal(output, exp256c, sizeof(exp256c)) == false)
	{
		print_safe("Failure! kmac_128_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	utils_memory_clear(output, sizeof(output));

	kmac_initialize(&state, KECCAK_128_RATE, key256, sizeof(key256), cust168, sizeof(cust168));
	kmac_update(&state, KECCAK_128_RATE, msg1600, sizeof(msg1600));
	kmac_finalize(&state, KECCAK_128_RATE, output, sizeof(output));

	if (utils_memory_are_equal(output, exp256c, sizeof(exp256c)) == false)
	{
		print_safe("Failure! kmac_128_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

static bool kmac_256_kat()
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

	hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));

	hex_to_bin("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
		"F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD", exp256a, sizeof(exp256a));
	hex_to_bin("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691"
		"589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69", exp256b, sizeof(exp256b));
	hex_to_bin("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D9"
		"70FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965", exp256c, sizeof(exp256c));

	hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));

	hex_to_bin("00010203", msg32, sizeof(msg32));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
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
		print_safe("Failure! kmac_256_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust0, 0);

	if (utils_memory_are_equal(output, exp256b, sizeof(exp256b)) == false)
	{
		print_safe("Failure! kmac_256_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (utils_memory_are_equal(output, exp256c, sizeof(exp256c)) == false)
	{
		print_safe("Failure! kmac_256_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	utils_memory_clear(output, sizeof(output));

	kmac_initialize(&state, KECCAK_256_RATE, key256, sizeof(key256), cust168, sizeof(cust168));
	kmac_update(&state, KECCAK_256_RATE, msg1600, sizeof(msg1600));
	kmac_finalize(&state, KECCAK_256_RATE, output, sizeof(output));

	if (utils_memory_are_equal(output, exp256c, sizeof(exp256c)) == false)
	{
		print_safe("Failure! kmac_256_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

static bool kmac_512_kat()
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

	hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust0, sizeof(cust0));
	hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", cust1, sizeof(cust1));
	hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920", cust2, sizeof(cust2));

	hex_to_bin("C41F31CEE9851BAA915716C16F7670C7C137C1908BD9694DA80C679AA6EB5964"
		"E76AD91F2018DE576524D84E0B0FC586C06B110ED6DB273A921FFC86D1C20CE8", exp0, sizeof(exp0));
	hex_to_bin("6535FB96EAB4F831D801E6C3C6E71755F4A56E8E711D376DDC564F5C6DACB8B5"
		"91EEF0503F433872B401FCEF8F05DA42FB950176C10FDB59395273FB9EDA39B8", exp1, sizeof(exp1));
	hex_to_bin("7BA4F7EE765960E6DA15D2CB51775DBA3E7B9279E5740469EF9FFD04C5246091"
		"9A99BEE5BFDA27163E2729A8E3B663BD963EF067C7CCABDE6F6EFFF9093E2A2F", exp2, sizeof(exp2));

	hex_to_bin("4D7920546167676564204170706C69636174696F6E", key0, sizeof(key0));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B", key1, sizeof(key1));

	hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", msg0, sizeof(msg0));
	hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D"
		"7920546167676564204170706C69636174696F6E", msg1, sizeof(msg1));
	status = true;

	/* test compact api */

	kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key0, sizeof(key0), cust0, sizeof(cust0));

	if (utils_memory_are_equal(output, exp0, sizeof(exp0)) == false)
	{
		print_safe("Failure! kmac_512_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key1, sizeof(key1), cust2, sizeof(cust2));

	if (utils_memory_are_equal(output, exp1, sizeof(exp1)) == false)
	{
		print_safe("Failure! kmac_512_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	utils_memory_clear(output, sizeof(output));
	kmac512_compute(output, sizeof(output), msg1, sizeof(msg1), key0, sizeof(key0), cust1, sizeof(cust1));

	if (utils_memory_are_equal(output, exp2, sizeof(exp2)) == false)
	{
		print_safe("Failure! kmac_512_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	utils_memory_clear(state.state, KECCAK_STATE_SIZE * sizeof(uint64_t));
	utils_memory_clear(output, sizeof(output));

	kmac_initialize(&state, KECCAK_512_RATE, key0, sizeof(key0), cust1, sizeof(cust1));
	kmac_update(&state, KECCAK_512_RATE, msg1, sizeof(msg1));
	kmac_finalize(&state, KECCAK_512_RATE, output, sizeof(output));

	if (utils_memory_are_equal(output, exp2, sizeof(exp2)) == false)
	{
		print_safe("Failure! kmac_512_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

/***Tests***/

bool qsctest_rhx_test()
{
	bool res;

	res = true;

	if (aes128_cbc_fips_test() == false)
	{
		res = false;
	}
	else if (aes256_cbc_fips_test() == false)
	{
		res = false;
	}
	else if (aes128_ctr_fips_test() == false)
	{
		res = false;
	}
	else if (aes256_ctr_fips_test() == false)
	{
		res = false;
	}
	else if (aes128_ecb_fips_test() == false)
	{
		res = false;
	}
	else if (aes256_ecb_fips_test() == false)
	{
		res = false;
	}
	else if (rhx256_ecb_kat_test() == false)
	{
		res = false;
	}
	else if (rhx512_ecb_kat_test() == false)
	{
		res = false;
	}
	else if (rhx256_ecb_monte_carlo() == false)
	{
		res = false;
	}
	else if (rhx512_ecb_monte_carlo() == false)
	{
		res = false;
	}

	return res;
}

bool qsctest_sha2_test()
{
	bool res;

	res = true;

	if (sha2_256_kat() == false)
	{
		res = false;
	}
	else if (sha2_512_kat() == false)
	{
		res = false;
	}
	else if (hkdf_256_kat() == false)
	{
		res = false;
	}
	else if (hkdf_512_kat() == false)
	{
		res = false;
	}
	else if (hmac_256_kat() == false)
	{
		res = false;
	}
	else if (hmac_512_kat() == false)
	{
		res = false;
	}

	return res;
}

bool qsctest_sha3_test()
{
	bool res;

	res = true;

	if (cshake_256_kat() == false)
	{
		res = false;
	}
	else if (cshake_512_kat() == false)
	{
		res = false;
	}
	else if (kmac_256_kat() == false)
	{
		res = false;
	}
	else if (kmac_512_kat() == false)
	{
		res = false;
	}

	return res;
}

bool qsctest_selftest_run()
{
	bool res;

	res = true;

	if (qsctest_rhx_test() == false)
	{
		res = false;
	}
	else if (qsctest_sha2_test() == false)
	{
		res = false;
	}
	else if (qsctest_sha3_test() == false)
	{
		res = false;
	}

	return res;
}

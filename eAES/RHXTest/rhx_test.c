#include "rhx_test.h"
#include "hash.h"
#include "utils.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTR_OUTPUT_LENGTH 33
#define MONTE_CARLO_CYCLES 10000
#define HBA_TEST_CYCLES 100
#define RHX_TEST_CYCLES 100


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
		memcpy(inpf + (i * RHX_BLOCK_SIZE), message[i], RHX_BLOCK_SIZE);
		memcpy(expf + (i * RHX_BLOCK_SIZE), expected[i], RHX_BLOCK_SIZE);
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

static bool rhx256_ecb_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
{
	uint8_t enc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX_RHX256_KEY_SIZE };

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

	if (utils_memory_are_equal(expected, enc, RHX_BLOCK_SIZE) == false)
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

	if (utils_memory_are_equal(message, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool rhx512_ecb_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
{
	uint8_t enc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX_RHX512_KEY_SIZE };

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

	if (utils_memory_are_equal(expected, enc, RHX_BLOCK_SIZE) == false)
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

	if (utils_memory_are_equal(message, msg, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

bool qsctest_fips_aes128_cbc()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F2.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_fips_aes256_cbc()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_fips_aes128_ctr()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_fips_aes256_ctr()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_fips_aes128_ecb()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F1.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_fips_aes256_ecb()
{
	uint8_t exp[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, RHX_RHX256_KEY_SIZE);

	qsctest_hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], RHX_BLOCK_SIZE);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_rhx256_cbc_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivcopy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mlen;
	size_t elen;
	size_t outlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;
		outlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));

			if (mlen < RHX_BLOCK_SIZE || mlen % RHX_BLOCK_SIZE == 0)
			{
				mlen = 0;
			}
		}
		while (mlen == 0);

		elen = (mlen % RHX_BLOCK_SIZE) == 0 ? mlen : mlen + (RHX_BLOCK_SIZE - (mlen % RHX_BLOCK_SIZE));
		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(elen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, elen);
			utils_memory_clear(msg, mlen);

			/* generate the key and iv */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ivcopy, sizeof(ivcopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			memcpy(iv, ivcopy, sizeof(ivcopy));
			rhx_keyparams kp1 = { key, sizeof(key), iv, NULL, 0 };

			/* encrypt the message */
			rhx_initialize(&state1, &kp1, true, RHX256);
			rhx_cbc_encrypt(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the iv */
			memcpy(iv, ivcopy, sizeof(ivcopy));
			rhx_keyparams kp2 = { key, sizeof(key), iv, NULL, 0 };

			/* decrypt the message */
			rhx_initialize(&state2, &kp2, false, RHX256);
			rhx_cbc_decrypt(&state2, dec, &outlen, enc, elen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			/* compare decryption output to message */
			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_cbc_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ivcopy[RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mlen;
	size_t elen;
	size_t outlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;
		outlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));

			if (mlen < RHX_BLOCK_SIZE || mlen % RHX_BLOCK_SIZE == 0)
			{
				mlen = 0;
			}
		} 
		while (mlen == 0);

		elen = (mlen % RHX_BLOCK_SIZE) == 0 ? mlen : mlen + (RHX_BLOCK_SIZE - (mlen % RHX_BLOCK_SIZE));
		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(elen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, elen);
			utils_memory_clear(msg, mlen);

			/* generate the key and iv */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ivcopy, sizeof(ivcopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			memcpy(iv, ivcopy, sizeof(ivcopy));
			rhx_keyparams kp1 = { key, sizeof(key), iv, NULL, 0 };

			/* encrypt the message */
			rhx_initialize(&state1, &kp1, true, RHX512);
			rhx_cbc_encrypt(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the iv */
			memcpy(iv, ivcopy, sizeof(ivcopy));
			rhx_keyparams kp2 = { key, sizeof(key), iv, NULL, 0 };

			/* decrypt the message */
			rhx_initialize(&state2, &kp2, false, RHX512);
			rhx_cbc_decrypt(&state2, dec, &outlen, enc, elen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			/* compare decryption output to message */
			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx256_ctr_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, mlen);
			utils_memory_clear(msg, mlen);

			/* generate the key and nonce */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			rhx_initialize(&state1, &kp1, true, RHX256);

			/* encrypt the array */
			rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			rhx_initialize(&state2, &kp2, true, RHX256);

			/* test decryption by using ciphertest as input */
			rhx_ctrbe_transform(&state2, dec, enc, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_ctr_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, mlen);
			utils_memory_clear(msg, mlen);

			/* generate the key and nonce */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			rhx_initialize(&state1, &kp1, true, RHX512);

			/* encrypt the array */
			rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			rhx_initialize(&state2, &kp2, true, RHX512);

			/* test decryption by using ciphertest as input */
			rhx_ctrbe_transform(&state2, dec, enc, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

#if defined(RHX_WIDE_BLOCK_TESTS)

bool qsctest_rhx256_ctrbe_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, mlen);
			utils_memory_clear(msg, mlen);

			/* generate the key and nonce */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			rhx_initialize(&state1, &kp1, true, RHX256);

			/* encrypt the array */
			rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			rhx_initialize(&state2, &kp2, true, RHX256);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = utils_integer_min(RHX_BLOCK_SIZE, mctr);
				rhx_ctrbe_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_ctrbe_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, mlen);
			utils_memory_clear(msg, mlen);

			/* generate the key and nonce */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			rhx_initialize(&state1, &kp1, true, RHX512);

			/* encrypt the array */
			rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			rhx_initialize(&state2, &kp2, true, RHX512);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = utils_integer_min(RHX_BLOCK_SIZE, mctr);
				rhx_ctrbe_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx256_ctrle_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, mlen);
			utils_memory_clear(msg, mlen);

			/* generate the key and nonce */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			rhx_initialize(&state1, &kp1, true, RHX256);

			/* encrypt the array */
			rhx_ctrle_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			rhx_initialize(&state2, &kp2, true, RHX256);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = utils_integer_min(RHX_BLOCK_SIZE, mctr);
				rhx_ctrle_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_ctrle_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state1;
	rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			utils_memory_clear(dec, mlen);
			utils_memory_clear(enc, mlen);
			utils_memory_clear(msg, mlen);

			/* generate the key and nonce */
			utils_seed_generate(key, sizeof(key));
			utils_seed_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			utils_seed_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			rhx_initialize(&state1, &kp1, true, RHX512);

			/* encrypt the array */
			rhx_ctrle_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			rhx_initialize(&state2, &kp2, true, RHX512);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = utils_integer_min(RHX_BLOCK_SIZE, mctr);
				rhx_ctrle_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			rhx_dispose(&state2);

			if (utils_memory_are_equal(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

#endif

bool qsctest_rhx256_ecb_kat()
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
	qsctest_hex_to_bin("B93AF9A0635964EE2DD1600A95C56905", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	qsctest_hex_to_bin("356FE2F76E8954C8292C4FE4EFD52A2C", exp, RHX_BLOCK_SIZE);
#endif

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

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

bool qsctest_rhx512_ecb_kat()
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
	qsctest_hex_to_bin("4F9D61042EC51DADAB25F081A3E79AF1", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	qsctest_hex_to_bin("C23E5C88453124D46B81D7229C6A409F", exp, RHX_BLOCK_SIZE);
#endif

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX_RHX512_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

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

bool qsctest_rhx256_monte_carlo()
{
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	bool status;

	/* original vectors */

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

#if defined(RHX_SHAKE_EXTENSION)
	qsctest_hex_to_bin("6DED2973243BCD846C4D98C1BF636FB3", exp, RHX_BLOCK_SIZE);
#else
	qsctest_hex_to_bin("C4E3D76961144D5F1BAC6C0DE5078597", exp, RHX_BLOCK_SIZE);
#endif

	status = rhx256_ecb_monte_carlo(key, msg, exp);

	return status;
}

bool qsctest_rhx512_monte_carlo()
{
	uint8_t exp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[RHX_BLOCK_SIZE] = { 0 };
	bool status;

	/* original vectors */

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX_RHX512_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

#if defined(RHX_SHAKE_EXTENSION)
	qsctest_hex_to_bin("FB8977B80F5B0B7C2E4048DF590EB2F6", exp, RHX_BLOCK_SIZE);
#else
	qsctest_hex_to_bin("3CC3EB49D4328762000EB0D6DB3924E1", exp, RHX_BLOCK_SIZE);
#endif

	status = rhx512_ecb_monte_carlo(key, msg, exp);

	return status;
}

bool qsctest_rhx_padding_test()
{
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[1] = { 0 };
	size_t i;
	size_t mlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;
	mlen = 0;

	/* test padding random iv sizes */

	while (tctr < RHX_TEST_CYCLES)
	{
		do
		{
			utils_seed_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint8_t));

			while (mlen >= RHX_BLOCK_SIZE)
			{
				mlen >>= 1;
			} 
		} 
		while (mlen == 0);

		utils_memory_clear(iv, sizeof(iv));
		utils_seed_generate(iv, mlen);

		rhx_pkcs7_add_padding(iv, RHX_BLOCK_SIZE - mlen);

		if (rhx_pkcs7_padding_length(iv) != RHX_BLOCK_SIZE - mlen)
		{
			status = false;
			break;
		}

		++tctr;
	}

	/* test coincidental occurences */

	/* note that on an unpadded block, if the last byte in that block is coincidentally set to one,
	the padding will be counted, this is an expected limitation of the PKCS7 padding mode */

	for (i = 2; i < RHX_BLOCK_SIZE; ++i)
	{
		utils_seed_generate(iv, sizeof(iv));
		iv[RHX_BLOCK_SIZE - 1] = (uint8_t)i;

		if (rhx_pkcs7_padding_length(iv) != 0)
		{
			status = false;
			break;
		}
	}

	return status;
}

void qsctest_aes_run()
{
	if (qsctest_fips_aes128_cbc() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CBC(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CBC(AES-128) CBC KAT test. \n");
	}

	if (qsctest_fips_aes256_cbc() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CBC(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CBC(AES-256) CBC KAT test. \n");
	}

	if (qsctest_fips_aes128_ctr() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CTR(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CTR(AES-128) KAT test. \n");
	}

	if (qsctest_fips_aes256_ctr() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CTR(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CTR(AES-256) KAT test. \n");
	}

	if (qsctest_fips_aes128_ecb() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 ECB(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 ECB(AES-128) KAT test. \n");
	}

	if (qsctest_fips_aes256_ecb() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 ECB(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 ECB(AES-256) KAT test. \n");
	}
}

void qsctest_rhx_run()
{
	if (qsctest_rhx256_ecb_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ECB(RHX-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECB(RHX-256) KAT test. \n");
	}

	if (qsctest_rhx512_ecb_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ECB(RHX-512) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECB(RHX-512) KAT test. \n");
	}

	if (qsctest_rhx256_cbc_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CBC(RHX-256) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CBC(RHX-256) stress test. \n");
	}

	if (qsctest_rhx512_cbc_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CBC(RHX-512) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CBC(RHX-512) stress test. \n");
	}

	if (qsctest_rhx256_ctr_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CTR(RHX-256) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR(RHX-256) stress test. \n");
	}

	if (qsctest_rhx512_ctr_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CTR(RHX-512) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR(RHX-512) stress test. \n");
	}

#if defined(RHX_WIDE_BLOCK_TESTS)

	if (qsctest_rhx256_ctrbe_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-BE(RHX-256) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-BE(RHX-256) AVX512 equality test. \n");
	}

	if (qsctest_rhx512_ctrbe_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-BE(RHX-512) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-BE(RHX-512) AVX512 equality test. \n");
	}

	if (qsctest_rhx256_ctrle_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-LE(RHX-256) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-LE(RHX-256) AVX512 equality test. \n");
	}

	if (qsctest_rhx512_ctrle_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-LE(RHX-512) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-LE(RHX-512) AVX512 equality test. \n");
	}

#endif

	if (qsctest_rhx256_monte_carlo() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-256 Monte Carlo test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-256 Monte Carlo test. \n");
	}

	if (qsctest_rhx512_monte_carlo() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-512 Monte Carlo test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-512 Monte Carlo test. \n");
	}

	if (qsctest_rhx_padding_test() == true)
	{
		qsctest_print_safe("Success! Passed the PKCS7 padding mode stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the PKCS7 padding mode stress test. \n");
	}
}

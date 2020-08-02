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
	uint8_t key[RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE, nonce, NULL, 0 };
	memset(key, 0x01, sizeof(key));
	memset(msg, 0x80, sizeof(msg));
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
	uint8_t key[RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t nonce[RHX_BLOCK_SIZE] = { 0 };
	bool status;
	rhx_state state;

	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE, nonce, NULL, 0 };
	memset(key, 0x01, sizeof(key));
	memset(msg, 0x80, sizeof(msg));
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
	hex_to_bin("D1B1C7A44B0360C5B32F36865ABE458023175AA63B8F049D3256E14AE28319D8B5704C4DAE9BECFEEC6DC90F4290CA50", exp1, sizeof(exp1));
	hex_to_bin("72266262C11A694A022786517D1222C693EDB6D3F8FB4BD557D7DDEFB11AFC9E3FD3A186C91928B4641B5F7306FC3870831D62BC870667A243A46CEAE418DC35", exp2, sizeof(exp2));
	hex_to_bin("1B593A4FD95A25ED8EA645199BB5A4421F3B371354B83F78F1D97F42B882CBA2B245B310890BCE02AB5E86745837B447FED07B28F812FD16A8B32D9B65996E95"
		"F0C9C030776AC405E87C0E8D61DB7B70A4D24F0B301CBA7445D9FF4DBF75B598", exp3, sizeof(exp3));
#else
	hex_to_bin("2FC12BD6A4C0E6C8B6460A8AD6E3A751AD1A07E84E8EA48C85D235E5D8588DA88C511E2D9803FB2EE9512DC82578C765", exp1, sizeof(exp1));
	hex_to_bin("F905E342002A902C2F0EAAE6342292279C1D8780EAC682F5C0F7F92BA9BFAF6E402FA3E736ED76548B0A1BF2D58E201F448370906EAD11BC5D27B19EEC637DE4", exp2, sizeof(exp2));
	hex_to_bin("E71C0802B27B73EA162E507D2CC351D3B19A1C592D47A862CA90341CE2EA2C71B4A9F28769426F14E4D2C6427C7650195795E7C34BFFBB31F8832B79447B0015"
		"F939B976B33FF47AFDA3F83A73B28B7F27EBB66EE3C2A8397202D1A2E288A553", exp3, sizeof(exp3));
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
	hex_to_bin("3445EEABB15B39077D7A6FB7E7055FE49435BCA7CEAC9A834698FD26D60214AC4BC2146F9BD943044FAF62FA2185736D1CA3E09132C99604F620D000BE22331A"
		"23A4BD7D4C62EBF155EE63994C185976", exp1, sizeof(exp1));
	hex_to_bin("8238DFB8B88897E4C92490148AAFDB22C824FB1C7BD443FA0510D45BDFDFEC2EE89F3B64D4FF5FC5EC66FF81EAD38ADF73D45AE4E6D604FF8CE6FC7801805B3E"
		"2101B8E403B6516A95AA9650524B1E94E6850A2E886099EF87CAF0D783482F3E", exp2, sizeof(exp2));
	hex_to_bin("2CDC038A38D27F58B38AA2130D1AA61D525DD09ABCCCBBD7B45FB40851626482555B352F57B2913EFD722E2A4A3E525CD053C90B1DF89B212A0226D2BE3F7D77"
		"83B37EC9E7DF54B4538BCF45EFCB4C5FC6D941154468894D15F1D2FE9216938768D388F9FACCF1BECAB4418BFC68F67C0CF800F438A3FF9BCA1F24166F772319", exp3, sizeof(exp3));
#else
	hex_to_bin("84F2B6F882E63894ABA11DC69CCFF2E5F49A083459B0210B3C7E5CF9FF099E78389294F9936CFDDD6BDD31513F69C0AABF2E6A714A9547CCB3347B3944C8CBA0"
		"DF7F24AC4B107738E601886FE27AA20E", exp1, sizeof(exp1));
	hex_to_bin("84F547ECA80F39410F913EC877C1B8C53858A933C74C1F2011EF755CD97307A4339C1E42E6A93377101540B51C9CF585F33E04F779EB7FA06C1D2D6AC3166A0F"
		"7C5BC0EE36FCA7C69DA799B2E308EF8362C74EBEFFFBACE4D0AE7D0778C1242C", exp2, sizeof(exp2));
	hex_to_bin("3DC9E0B3539CF48827B5E9F0F789256E51083EDCF697D7277ADD38754BB5E23D5614425612B2ECF7B46E0E9D9D82853385D5E89191238BFB766D076260BB1613"
		"C67C6AB107988892FA1A255A0DBA710FB49C2F485F1ACBC968D5D39D94C4990FED9284E62FF306ECC87FB8DE4C762F359B3D6B46686F2DB15C44B82C43BDFBCE", exp3, sizeof(exp3));
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
			if (are_equal8(dec, msg, mlen) == false)
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
			if (are_equal8(dec, msg, mlen) == false)
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

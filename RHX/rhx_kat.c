#include "rhx_kat.h"
#include "intutils.h"
#include "rhx.h"
#include "sha2.h"
#include "sha3.h"
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

	/* copy iv to local */
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES128_KEY_SIZE, ivc };

	status = true;

	/* test the simplified api */

	/* copy split message and expected arrays to full input */
	for (i = 0; i < 4; ++i)
	{
		memcpy(inpf + (i * RHX_BLOCK_SIZE), message[i], RHX_BLOCK_SIZE);
		memcpy(expf + (i * RHX_BLOCK_SIZE), expected[i], RHX_BLOCK_SIZE);
	}

	/* reset the iv and encrypt */
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	aes128_cbc_encrypt(&kp, outf, inpf, sizeof(inpf));

	if (are_equal8(outf, expf, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* reset the iv and decrypt */
	clear8(outf, sizeof(outf));
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	aes128_cbc_decrypt(&kp, outf, expf, sizeof(expf));

	if (are_equal8(outf, inpf, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* test the long-form api */

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES128_ROUNDKEY_SIZE };

	/* initialize the state and create the round-keys */
	memcpy(kp.nonce, iv, RHX_BLOCK_SIZE);
	rhx_initialize(&state, &kp, true);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		cbc_encrypt_block(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the ive and test the cbc decryption function */
	memcpy(kp.nonce, iv, RHX_BLOCK_SIZE);
	rhx_initialize(&state, &kp, false);

	for (i = 0; i < 4; ++i)
	{
		cbc_decrypt_block(&state, out, expected[i]);

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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#endif

	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES256_KEY_SIZE, ivc };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		cbc_encrypt_block(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test decryption */
	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	rhx_initialize(&state, &kp, false);

	/* test the cbc decryption function */
	for (i = 0; i < 4; ++i)
	{
		cbc_decrypt_block(&state, out, expected[i]);

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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES128_ROUNDKEY_SIZE };
	/* initialize the key parameters struct with key and nonce, info not used in AES */
	memcpy(nce, nonce, RHX_BLOCK_SIZE);
	rhx_keyparams kp = { key, AES128_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		ctr_transform(&state, out, message[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	memcpy(state.nonce, nonce, RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	rhx_initialize(&state, &kp, true);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		ctr_transform(&state, out, expected[i], RHX_BLOCK_SIZE);

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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct with key and nonce, info is optional */
	memcpy(nce, nonce, RHX_BLOCK_SIZE);
	rhx_keyparams kp = { key, AES256_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		ctr_transform(&state, out, message[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	memcpy(state.nonce, nonce, RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	rhx_initialize(&state, &kp, true);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		ctr_transform(&state, out, expected[i], RHX_BLOCK_SIZE);

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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES128_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES128_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_encrypt(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_decrypt(&state, out, expected[i]);

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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES256_KEY_SIZE };
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_encrypt(&state, out, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state  */
	rhx_initialize(&state, &kp, false);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ecb_decrypt(&state, out, expected[i]);

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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE };

	memcpy(msg, message, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ecb encryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_encrypt(&state, enc, msg);
		memcpy(msg, enc, RHX_BLOCK_SIZE);
	}

	if (are_equal8(expected, enc, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false);

	/* test the ecb decryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_decrypt(&state, msg, enc);
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

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX512_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE };

	memcpy(msg, message, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ecb encryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_encrypt(&state, enc, msg);
		memcpy(msg, enc, RHX_BLOCK_SIZE);
	}

	if (are_equal8(expected, enc, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false);

	/* test the ecb decryption function */
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
	{
		rhx_ecb_decrypt(&state, msg, enc);
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
	uint8_t nonce[RHX_NONCE_SIZE] = { 0 };
	bool status;

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE, nonce, NULL, 0 };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* encrypt the array */
	ctr_transform(&state, enc, msg, CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(state.nonce, 0x00, RHX_NONCE_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	rhx_initialize(&state, &kp, true);

	/* test decryption by using ciphertest as input */
	ctr_transform(&state, dec, enc, CTR_OUTPUT_LENGTH);

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
	uint8_t nonce[RHX_NONCE_SIZE] = { 0 };
	bool status;

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX512_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE, nonce, NULL, 0 };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* encrypt the array */
	ctr_transform(&state, enc, msg, CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(state.nonce, 0x00, RHX_NONCE_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	rhx_initialize(&state, &kp, true);

	/* test decryption by using ciphertest as input */
	ctr_transform(&state, dec, enc, CTR_OUTPUT_LENGTH);

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

	/* vectors from CEX */
#ifdef RHX_CSHAKE_EXTENSION
	hex_to_bin("B93AF9A0635964EE2DD1600A95C56905", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("356FE2F76E8954C8292C4FE4EFD52A2C", exp, RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX256_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX256_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test encryption */
	rhx_ecb_encrypt(&state, otp, msg);

	if (are_equal8(otp, exp, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	rhx_initialize(&state, &kp, false);

	/* test decryption */
	rhx_ecb_decrypt(&state, dec, otp);

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

	/* vectors from CEX */
#ifdef RHX_CSHAKE_EXTENSION
	hex_to_bin("4F9D61042EC51DADAB25F081A3E79AF1", exp, RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("C23E5C88453124D46B81D7229C6A409F", exp, RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, RHX512_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, RHX_BLOCK_SIZE);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX512_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, RHX512_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test encryption */
	rhx_ecb_encrypt(&state, otp, msg);

	if (are_equal8(otp, exp, RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state for encryption */
	rhx_initialize(&state, &kp, false);

	/* test decryption */
	rhx_ecb_decrypt(&state, dec, otp);

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

#ifdef RHX_CSHAKE_EXTENSION
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

#ifdef RHX_CSHAKE_EXTENSION
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
	uint8_t otp1[RHX_BLOCK_SIZE + HBA256_MAC_LENGTH] = { 0 };
	uint8_t otp2[(RHX_BLOCK_SIZE * 2) + HBA256_MAC_LENGTH] = { 0 };
	uint8_t otp3[(RHX_BLOCK_SIZE * 4) + HBA256_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#ifdef HBA_KMAC_AUTH
	hex_to_bin("97A426E5C264C9799404F922412283AD6364D5C086F6F64334DCA0DAC5D39ABAEAA06B291F2219543A47E21BD847F30B", exp1, sizeof(exp1));
	hex_to_bin("F82FE9B1C8037BA1795831043266CE8BE6BEC8A76FFE72BB7FDAF94238CF176A87530549319C158633EBC2E3D552ED8B25AE808261DA87CBF54AD5DB9DFDB186", exp2, sizeof(exp2));
	hex_to_bin("390716796AF6BA451B48454DADACEA38904F0D8FED7B4CE88D12526D6472D1E07FDFB06EA9106DC39AA3EBD6D59A6F7FF06DBDECF27E03C4F98B299A026C4269"
		"A0C8B5967E3B7DB8BE9F6F6804C41D652803BDC7E4E39390CF0F83216B5C4CBA", exp3, sizeof(exp3));
#else
	hex_to_bin("3F5036E1986B0DA935257BB3703309D11F56F9891D1D379DE27C06352795A35C2A04A692A8248A7C6EDB3F4C5915860C", exp1, sizeof(exp1));
	hex_to_bin("F3515ECC444DD2CE58378FD09BFCBFCB9AC55859993BC68456D7404681A5DAE5646A53EBEFC55BBEDAF64462F039793B5232A6996CD6000CBD811D846C1C3CF6", exp2, sizeof(exp2));
	hex_to_bin("8A4C1E607EA8F85CDC9D1B3B3B9480FDDB8024AB59665212CFD393B66AA94364CBF9DF591D485403D2A6CC71939C181E9F731863DE0205ACEF1F37207E590E1C"
		"FFD926BFC9907B688146D91247D7337CF15E54EE806F277CF87880438D6F83E4", exp3, sizeof(exp3));
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

	hba_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0, aad1, sizeof(aad1) };

	if (hba_rhx256_encrypt(&kp1, otp1, msg1, sizeof(msg1)) != true)
	{
		status = false;
	}

	if (are_equal8(otp1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	memcpy(kp1.nonce, n1copy, RHX_BLOCK_SIZE);

	if (hba_rhx256_decrypt(&kp1, dec1, otp1, sizeof(msg1)) != true)
	{
		status = false;
	}

	if (are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	hba_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0, aad2, sizeof(aad2) };

	if (hba_rhx256_encrypt(&kp2, otp2, msg2, sizeof(msg2)) != true)
	{
		status = false;
	}

	if (are_equal8(otp2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	memcpy(kp2.nonce, n2copy, RHX_BLOCK_SIZE);

	if (hba_rhx256_decrypt(&kp2, dec2, otp2, sizeof(msg2)) != true)
	{
		status = false;
		// print msg/location on all of them, every kat, and/or assert
	}

	if (are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	hba_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0, aad3, sizeof(aad3) };

	if (hba_rhx256_encrypt(&kp3, otp3, msg3, sizeof(msg3)) != true)
	{
		status = false;
	}

	if (are_equal8(otp3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	memcpy(kp3.nonce, n3copy, RHX_BLOCK_SIZE);

	if (hba_rhx256_decrypt(&kp3, dec3, otp3, sizeof(msg3)) != true)
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
	uint8_t otp1[RHX_BLOCK_SIZE + HBA512_MAC_LENGTH] = { 0 };
	uint8_t otp2[(RHX_BLOCK_SIZE * 2) + HBA512_MAC_LENGTH] = { 0 };
	uint8_t otp3[(RHX_BLOCK_SIZE * 4) + HBA512_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#ifdef HBA_KMAC_AUTH
	hex_to_bin("59512A4AC06069679F9966F4A33536CAE1C7F44B7B7182FC0AF5E48B09F6943733DD4C7EDB1B028099C911BCFB442C37F90A838B1DE1F4286DD31F9DE8AE9E89"
		"54C5359D227B59B3E289CAD103C397B2", exp1, sizeof(exp1));
	hex_to_bin("5721130FB199F50828C90C76B45E4CA46E1A03276A4BBB0DF924807A7C1443B3C50437EA4FA8BFB1FC662E201715FE946DE8E65FB1459E41979D439993010DAF"
		"EE388E5FE93BC90DCD76A2DAC46C19ADC7316131044633EE7399F7A0F09E441F", exp2, sizeof(exp2));
	hex_to_bin("D9BFB2627B8CF85FF8DF2DCC41A03C135D11A86EDF4FA010ED9D6FF655B28549EA761E6296FBDEACA8C1D1EC2A0D9612ED79F4395D06ADA55F83F09BA22B53B8"
		"EED8EE28AD1BEAF7F31BEDFEA7BD2308E68BB8DA5B6698319BED70424B459BB15AD445716E227B1329A3AAD26B2506E6E4A98A1A517A6D0025B3469FA01FDA25", exp3, sizeof(exp3));
#else
	hex_to_bin("89A720738909E00A2284EC4A6D9B4A62D17C814E94CE77F4424E5FA4B808534B5ABB2C8E9803C2287D9A7FBA6C5A92AFA7529E57C3EE8A6FC0CE319BE63E0F98"
		"167352F9E770046C181CE715251552B3", exp1, sizeof(exp1));
	hex_to_bin("59D41490190DC32886B54369911C0245CA4BAAA77AF7ABA6F4CA9AF540C2945323B4AC23C566C872150088C5453D1B415B8B96F6D5A83BE3A2C3FAE8383D4B59"
		"7B549C69AA4D48E9D7D05D956F9A9AB430130A12A57B7AFBAAC7A4A88F075361", exp2, sizeof(exp2));
	hex_to_bin("8F6B5852D741A4E7A54FB7968BA45A2D0CFA8BE3FC69D89FFBAC4F347D5F787128207BCD876DD8CCAC2C068B884235CD41AAE299A4C5C9EDC4BAEEE228C75E3B"
		"3A139BE76880B10B3CA9033A27DB31DC37F49A9603F46B748A9DFC25CC068F45FF5E5A33EC6DCECB99918DC5F32B8876E545DF0585B40423C83B8F206451A7FF", exp3, sizeof(exp3));
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

	hba_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0, aad1, sizeof(aad1) };

	if (hba_rhx512_encrypt(&kp1, otp1, msg1, sizeof(msg1)) != true)
	{
		status = false;
	}

	if (are_equal8(otp1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	memcpy(kp1.nonce, n1copy, RHX_BLOCK_SIZE);

	if (hba_rhx512_decrypt(&kp1, dec1, otp1, sizeof(msg1)) != true)
	{
		status = false;
	}

	if (are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	hba_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0, aad2, sizeof(aad2) };

	if (hba_rhx512_encrypt(&kp2, otp2, msg2, sizeof(msg2)) != true)
	{
		status = false;
	}

	if (are_equal8(otp2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	memcpy(kp2.nonce, n2copy, RHX_BLOCK_SIZE);

	if (hba_rhx512_decrypt(&kp2, dec2, otp2, sizeof(msg2)) != true)
	{
		status = false;
		// print msg/location on all of them, every kat, and/or assert
	}

	if (are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	hba_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0, aad3, sizeof(aad3) };

	if (hba_rhx512_encrypt(&kp3, otp3, msg3, sizeof(msg3)) != true)
	{
		status = false;
	}

	if (are_equal8(otp3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	memcpy(kp3.nonce, n3copy, RHX_BLOCK_SIZE);

	if (hba_rhx512_decrypt(&kp3, dec3, otp3, sizeof(msg3)) != true)
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

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy)); // mcnt=33681

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

			hba_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0, aad, sizeof(aad) };

			/* encrypt the message */
			if (hba_rhx256_encrypt(&kp1, enc, msg, mlen) != true)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, RHX_BLOCK_SIZE);

			/* decrypt the message */
			if (hba_rhx256_decrypt(&kp1, dec, enc, mlen) != true)
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

			hba_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0, aad, sizeof(aad) };

			/* encrypt the message */
			if (hba_rhx512_encrypt(&kp1, enc, msg, mlen) != true)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, RHX_BLOCK_SIZE);

			/* decrypt the message */
			if (hba_rhx512_decrypt(&kp1, dec, enc, mlen) != true)
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

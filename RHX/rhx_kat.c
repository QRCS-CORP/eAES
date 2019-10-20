#include "rhx_kat.h"
#include "rhx.h"
#include <stdio.h>
#include <string.h>

#ifdef RHX_AESNI_ENABLED
#	if defined(_MSC_VER)
#		include <intrin.h>
#	elif defined(__GNUC__)
#		include <x86intrin.h>
#	endif
#endif

static bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

static void hex_to_bin(const char* str, uint8_t* output, size_t length)
{
	size_t  pos;
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	memset(output, 0, length);

	for (pos = 0; (pos < (length * 2)); pos += 2)
	{
		idx0 = ((uint8_t)str[pos + 0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)str[pos + 1] & 0x1F) ^ 0x10;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
}

static bool aes128_cbc_monte_carlo(uint8_t* key, const uint8_t* iv, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
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

	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_encrypt(&state, out, ivc, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	memcpy(ivc, iv, RHX_BLOCK_SIZE);

	/* test the cbc decryption function */
	rhx_initialize(&state, &kp, false);

	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_decrypt(&state, out, ivc, expected[i]);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes256_cbc_monte_carlo(uint8_t* key, const uint8_t* iv, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
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

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };
	/* initialize the key parameters struct, info is optional */
	rhx_keyparams kp = { key, AES256_KEY_SIZE };

	memcpy(ivc, iv, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_encrypt(&state, out, ivc, message[i]);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	memcpy(ivc, iv, RHX_BLOCK_SIZE);

	/* test decryption */
	rhx_initialize(&state, &kp, false);

	/* test the cbc decryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_cbc_decrypt(&state, out, ivc, expected[i]);

		if (are_equal8(out, message[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	rhx_dispose(&state);

	return status;
}

static bool aes128_ctr_monte_carlo(uint8_t* key, const uint8_t* nonce, const uint8_t message[4][RHX_BLOCK_SIZE], const uint8_t expected[4][RHX_BLOCK_SIZE])
{
	uint8_t ncc[RHX_BLOCK_SIZE] = { 0 };
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

	memcpy(ncc, nonce, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, ncc, message[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	memcpy(ncc, nonce, RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	rhx_initialize(&state, &kp, true);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, ncc, expected[i], RHX_BLOCK_SIZE);

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
	uint8_t ncc[RHX_BLOCK_SIZE] = { 0 };
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

	memcpy(ncc, nonce, RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, ncc, message[i], RHX_BLOCK_SIZE);

		if (are_equal8(out, expected[i], RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	memcpy(ncc, nonce, RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	rhx_initialize(&state, &kp, true);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		rhx_ctr_transform(&state, out, ncc, expected[i], RHX_BLOCK_SIZE);

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

static bool rhx512_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
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

bool aes128_cbc_kat_test()
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

bool aes256_cbc_kat_test()
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

bool aes128_ctr_kat_test()
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

bool aes256_ctr_kat_test()
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

bool aes128_ecb_kat_test()
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

bool aes256_ecb_kat_test()
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

bool ctr_mode_stress_test()
{
	uint8_t dec[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t enc[CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t key[RHX256_KEY_SIZE] = { 1 };
	uint8_t msg[CTR_OUTPUT_LENGTH] = { 128 };
	uint8_t nce[RHX_NONCE_SIZE] = { 0 };
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

	status = true;

	/* initialize the state and create the round-keys */
	rhx_initialize(&state, &kp, true);

	/* encrypt the array */
	rhx_ctr_transform(&state, enc, nce, msg, CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(nce, 0x00, RHX_NONCE_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	rhx_initialize(&state, &kp, true);

	/* test decryption by using ciphertest as input */
	rhx_ctr_transform(&state, dec, nce, enc, CTR_OUTPUT_LENGTH);

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

	status = rhx512_monte_carlo(key, msg, exp);

	return status;
}

bool rhx256_kat_test()
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

bool rhx512_kat_test()
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


#include "rhx.h"
#include "intutils.h"
#include <assert.h>
#include <stdlib.h>

#if defined RHX_CSHAKE_EXTENSION
#	define HBA256_MKEY_LENGTH 32
#	define HBA512_MKEY_LENGTH 64
#else
#	define HBA256_MKEY_LENGTH 64
#	define HBA512_MKEY_LENGTH 128
#endif

/* default info parameter string literals */
#ifdef RHX_CSHAKE_EXTENSION
/* RHXS256 */
static const uint8_t RHX_CSHAKE256_INFO[7] = { 82, 72, 88, 83, 50, 53, 54 };
/* RHXS512 */
static const uint8_t RHX_CSHAKE512_INFO[7] = { 82, 72, 88, 83, 53, 49, 50 };
#else
/* RHXH256 */
static const uint8_t RHX_HKDF256_INFO[7] = { 82, 72, 88, 72, 50, 53, 54 };
/* RHXH512 */
static const uint8_t RHX_HKDF512_INFO[7] = { 82, 72, 88, 72, 53, 49, 50 };
#endif

/* aes-ni and table-based fallback functions */

#ifdef RHX_AESNI_ENABLED

static void decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	const size_t RNDCNT = state->rndkeylen - 2;
	__m128i x;
	size_t keyctr;

	keyctr = 0;
	x = _mm_loadu_si128((const __m128i*)input);
	x = _mm_xor_si128(x, state->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		x = _mm_aesdec_si128(x, state->roundkeys[keyctr]);
	}

	++keyctr;
	_mm_storeu_si128((__m128i*)output, _mm_aesdeclast_si128(x, state->roundkeys[keyctr]));
}

static void encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	const size_t RNDCNT = state->rndkeylen - 2;
	__m128i x;
	size_t keyctr;

	keyctr = 0;
	x = _mm_loadu_si128((const __m128i*)input);
	x = _mm_xor_si128(x, state->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		x = _mm_aesenc_si128(x, state->roundkeys[keyctr]);
	}

	++keyctr;
	_mm_storeu_si128((__m128i*)output, _mm_aesenclast_si128(x, state->roundkeys[keyctr]));
}

static void expand_rot(__m128i* Key, size_t Index, size_t Offset)
{
	__m128i pkb;

	pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(Key[Index], 0xFF);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

static void expand_sub(__m128i* Key, size_t Index, size_t Offset)
{
	__m128i pkb;

	pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(Key[Index - 1], 0x0), 0xAA);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

static void le32_to_bytes(const uint32_t value, uint8_t* output, size_t offset)
{
	output[offset] = (uint8_t)value;
	output[offset + 1] = (uint8_t)(value >> 8);
	output[offset + 2] = (uint8_t)(value >> 16);
	output[offset + 3] = (uint8_t)(value >> 24);
}

static bytes_to_le128(uint8_t* input, size_t inplen, __m128i* output, size_t outlen)
{
	size_t i;
	uint32_t tmpk;

	for (i = 0; i < inplen; i += sizeof(uint32_t))
	{
		tmpk = be8to32(input + i);
		le32_to_bytes(tmpk, input, i);
	}

	for (i = 0; i < outlen; ++i)
	{
		output[i] = _mm_loadu_si128((__m128i*)(input + (i * sizeof(__m128i))));
	}
}

static void secure_expand(rhx_state* state, rhx_keyparams* keyparams)
{
	uint8_t* tmpi;
	uint16_t kblen;

	// allocate the info array
	tmpi = (uint8_t*)malloc(RHX_INFO_DEFLEN + keyparams->infolen);

	assert(tmpi != NULL);

	if (tmpi != NULL)
	{
		memset(tmpi, 0x00, RHX_INFO_DEFLEN + keyparams->infolen);

		/* add the ciphers string literal name */
		if (keyparams->keylen == RHX256_KEY_SIZE)
		{
#ifdef RHX_CSHAKE_EXTENSION
			/* RHXS256 */
			memcpy(tmpi, RHX_CSHAKE256_INFO, sizeof(RHX_CSHAKE256_INFO));
#else
			/* RHXH256 */
			memcpy(tmpi, RHX_HKDF256_INFO, sizeof(RHX_HKDF256_INFO));
#endif
		}
		else
		{
#ifdef RHX_CSHAKE_EXTENSION
			/* RHXS512 */
			memcpy(tmpi, RHX_CSHAKE512_INFO, sizeof(RHX_CSHAKE512_INFO));
#else
			/* RHXH512 */
			memcpy(tmpi, RHX_HKDF512_INFO, sizeof(RHX_HKDF512_INFO));
#endif
		}

		/* add the key size in bits to info array as a little endian ordered 16-bit integer */
		kblen = (uint16_t)(keyparams->keylen * 8);
		tmpi[7] = (uint8_t)kblen;
		tmpi[8] = (uint8_t)(kblen >> 8);

		/* copy user-defined tweak to the info array */
		if (keyparams->infolen != 0)
		{
			memcpy(tmpi + RHX_INFO_DEFLEN, keyparams->info, keyparams->infolen);
		}

#ifdef RHX_CSHAKE_EXTENSION
		if (keyparams->keylen == RHX256_KEY_SIZE)
		{
			uint8_t rk[(RHX256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE)] = { 0 };

			/* generate the round-key buffer with cSHAKE-256 */
			cshake256(rk, state->rndkeylen * sizeof(__m128i), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
			/* convert the bytes to little endian encoded 128-bit integers */
			bytes_to_le128(rk, state->rndkeylen * sizeof(__m128i), state->roundkeys, state->rndkeylen);
		}
		else
		{
			uint8_t rk[(RHX512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE)] = { 0 };

			/* generate the round-key buffer with cSHAKE-512 */
			cshake512(rk, state->rndkeylen * sizeof(__m128i), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
			/* convert the bytes to little endian encoded 128-bit integers */
			bytes_to_le128(rk, state->rndkeylen * sizeof(__m128i), state->roundkeys, state->rndkeylen);
		}
#else
		if (keyparams->keylen == RHX256_KEY_SIZE)
		{
			uint8_t rk[RHX256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE] = { 0 };

			/* generate the round-key buffer with HKDF(HMAC(SHA2-256)) */
			hkdf256_expand(rk, state->rndkeylen * sizeof(__m128i), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
			/* convert the bytes to little endian encoded 128-bit integers */
			bytes_to_le128(rk, state->rndkeylen * sizeof(__m128i), state->roundkeys, state->rndkeylen);
		}
		else
		{
			uint8_t rk[(RHX512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE)] = { 0 };

			/* generate the round-key buffer with HKDF(HMAC(SHA2-512)) */
			hkdf512_expand(rk, state->rndkeylen * sizeof(__m128i), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
			/* convert the bytes to little endian encoded 128-bit integers */
			bytes_to_le128(rk, state->rndkeylen * sizeof(__m128i), state->roundkeys, state->rndkeylen);
		}
#endif

		/* dispose of temp info */
		free(tmpi);
	}
}

static void standard_expand(rhx_state* state, rhx_keyparams* keyparams)
{
	size_t kwords;

	/* key in 32-bit words */
	kwords = keyparams->keylen / 4;

	if (kwords == 8)
	{
		state->roundkeys[0] = _mm_loadu_si128((__m128i*)keyparams->key);
		state->roundkeys[1] = _mm_loadu_si128((__m128i*)(keyparams->key + 16));
		state->roundkeys[2] = _mm_aeskeygenassist_si128(state->roundkeys[1], 0x01);
		expand_rot(state->roundkeys, 2, 2);
		expand_sub(state->roundkeys, 3, 2);
		state->roundkeys[4] = _mm_aeskeygenassist_si128(state->roundkeys[3], 0x02);
		expand_rot(state->roundkeys, 4, 2);
		expand_sub(state->roundkeys, 5, 2);
		state->roundkeys[6] = _mm_aeskeygenassist_si128(state->roundkeys[5], 0x04);
		expand_rot(state->roundkeys, 6, 2);
		expand_sub(state->roundkeys, 7, 2);
		state->roundkeys[8] = _mm_aeskeygenassist_si128(state->roundkeys[7], 0x08);
		expand_rot(state->roundkeys, 8, 2);
		expand_sub(state->roundkeys, 9, 2);
		state->roundkeys[10] = _mm_aeskeygenassist_si128(state->roundkeys[9], 0x10);
		expand_rot(state->roundkeys, 10, 2);
		expand_sub(state->roundkeys, 11, 2);
		state->roundkeys[12] = _mm_aeskeygenassist_si128(state->roundkeys[11], 0x20);
		expand_rot(state->roundkeys, 12, 2);
		expand_sub(state->roundkeys, 13, 2);
		state->roundkeys[14] = _mm_aeskeygenassist_si128(state->roundkeys[13], 0x40);
		expand_rot(state->roundkeys, 14, 2);
	}
	else
	{
		state->roundkeys[0] = _mm_loadu_si128((__m128i*)keyparams->key);
		state->roundkeys[1] = _mm_aeskeygenassist_si128(state->roundkeys[0], 0x01);
		expand_rot(state->roundkeys, 1, 1);
		state->roundkeys[2] = _mm_aeskeygenassist_si128(state->roundkeys[1], 0x02);
		expand_rot(state->roundkeys, 2, 1);
		state->roundkeys[3] = _mm_aeskeygenassist_si128(state->roundkeys[2], 0x04);
		expand_rot(state->roundkeys, 3, 1);
		state->roundkeys[4] = _mm_aeskeygenassist_si128(state->roundkeys[3], 0x08);
		expand_rot(state->roundkeys, 4, 1);
		state->roundkeys[5] = _mm_aeskeygenassist_si128(state->roundkeys[4], 0x10);
		expand_rot(state->roundkeys, 5, 1);
		state->roundkeys[6] = _mm_aeskeygenassist_si128(state->roundkeys[5], 0x20);
		expand_rot(state->roundkeys, 6, 1);
		state->roundkeys[7] = _mm_aeskeygenassist_si128(state->roundkeys[6], 0x40);
		expand_rot(state->roundkeys, 7, 1);
		state->roundkeys[8] = _mm_aeskeygenassist_si128(state->roundkeys[7], 0x80);
		expand_rot(state->roundkeys, 8, 1);
		state->roundkeys[9] = _mm_aeskeygenassist_si128(state->roundkeys[8], 0x1B);
		expand_rot(state->roundkeys, 9, 1);
		state->roundkeys[10] = _mm_aeskeygenassist_si128(state->roundkeys[9], 0x36);
		expand_rot(state->roundkeys, 10, 1);
	}
}

void rhx_initialize(rhx_state* state, rhx_keyparams* keyparams, bool encryption)
{
	/* null or illegal state values */
	assert(state->roundkeys != NULL);
	assert(state->rndkeylen != 0);

	if (keyparams->nonce != NULL)
	{
		state->nonce = keyparams->nonce;
	}

	if (state->rndkeylen == RHX256_ROUNDKEY_SIZE)
	{
		memset(state->roundkeys, 0x00, RHX256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		secure_expand(state, keyparams);
	}
	else if (state->rndkeylen == RHX512_ROUNDKEY_SIZE)
	{
		memset(state->roundkeys, 0x00, RHX512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		secure_expand(state, keyparams);
	}
	else if (state->rndkeylen == AES256_ROUNDKEY_SIZE)
	{
		memset(state->roundkeys, 0x00, AES256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		standard_expand(state, keyparams);
	}
	else if (state->rndkeylen == AES128_ROUNDKEY_SIZE)
	{
		memset(state->roundkeys, 0x00, AES128_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		standard_expand(state, keyparams);
	}
	else
	{
		state->rndkeylen = 0;
	}

	/* inverse cipher */
	if (encryption == false)
	{
		__m128i tmp;
		size_t i;
		size_t j;

		tmp = state->roundkeys[0];
		state->roundkeys[0] = state->roundkeys[state->rndkeylen - 1];
		state->roundkeys[state->rndkeylen - 1] = tmp;

		for (i = 1, j = state->rndkeylen - 2; i < j; ++i, --j)
		{
			tmp = _mm_aesimc_si128(state->roundkeys[i]);
			state->roundkeys[i] = _mm_aesimc_si128(state->roundkeys[j]);
			state->roundkeys[j] = tmp;
		}

		state->roundkeys[i] = _mm_aesimc_si128(state->roundkeys[i]);
	}
}

#else

/* rijndael rcon, and s-box constant tables */

static const uint8_t s_box[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t is_box[256] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const uint32_t rcon[30] =
{
	0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
	0x80000000UL, 0x1B000000UL, 0x36000000UL, 0x6C000000UL, 0xD8000000UL, 0xAB000000UL, 0x4D000000UL, 0x9A000000UL,
	0x2F000000UL, 0x5E000000UL, 0xBC000000UL, 0x63000000UL, 0xC6000000UL, 0x97000000UL, 0x35000000UL, 0x6A000000UL,
	0xD4000000UL, 0xB3000000UL, 0x7D000000UL, 0xFA000000UL, 0xEF000000UL, 0xC5000000UL
};

static void add_round_key(uint8_t* state, const uint32_t *skeys)
{
	size_t i;
	uint32_t k;

	for (i = 0; i < RHX_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		k = *skeys;
		state[i] ^= (uint8_t)(k >> 24);
		state[i + 1] ^= (uint8_t)(k >> 16) & 0xFF;
		state[i + 2] ^= (uint8_t)(k >> 8) & 0xFF;
		state[i + 3] ^= (uint8_t)k & 0xFF;
		++skeys;
	}
}

static uint8_t gf256red(uint32_t x)
{
	uint32_t y;

	y = x >> 8;

	return (x ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) & 0xFF;
}

static void inv_mix_columns(uint8_t* state)
{
	size_t i;
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (i = 0; i < RHX_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = state[i];
		s1 = state[i + 1];
		s2 = state[i + 2];
		s3 = state[i + 3];

		t0 = (s0 << 1) ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 1) ^ (s1 << 3)
			^ s2 ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 3);

		t1 = s0 ^ (s0 << 3) ^ (s1 << 1) ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 1) ^ (s2 << 3) ^ s3 ^ (s3 << 2) ^ (s3 << 3);

		t2 = s0 ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 3)
			^ (s2 << 1) ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 1) ^ (s3 << 3);

		t3 = s0 ^ (s0 << 1) ^ (s0 << 3) ^ s1 ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 3) ^ (s3 << 1) ^ (s3 << 2) ^ (s3 << 3);

		state[i] = gf256red(t0);
		state[i + 1] = gf256red(t1);
		state[i + 2] = gf256red(t2);
		state[i + 3] = gf256red(t3);
	}
}

static void inv_shift_rows(uint8_t* state)
{
	uint8_t tmp;

	tmp = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = tmp;

	tmp = state[2];
	state[2] = state[10];
	state[10] = tmp;
	tmp = state[6];
	state[6] = state[14];
	state[14] = tmp;

	tmp = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = tmp;
}

static void inv_sub_bytes(uint8_t* state)
{
	size_t i;

	for (i = 0; i < RHX_BLOCK_SIZE; ++i)
	{
		state[i] = is_box[state[i]];
	}
}

static void mix_columns(uint8_t* state)
{
	size_t i;
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (i = 0; i < RHX_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = state[i + 0];
		s1 = state[i + 1];
		s2 = state[i + 2];
		s3 = state[i + 3];

		t0 = (s0 << 1) ^ s1 ^ (s1 << 1) ^ s2 ^ s3;
		t1 = s0 ^ (s1 << 1) ^ s2 ^ (s2 << 1) ^ s3;
		t2 = s0 ^ s1 ^ (s2 << 1) ^ s3 ^ (s3 << 1);
		t3 = s0 ^ (s0 << 1) ^ s1 ^ s2 ^ (s3 << 1);

		state[i + 0] = t0 ^ ((~(t0 >> 8) + 1) & 0x0000011BUL);
		state[i + 1] = t1 ^ ((~(t1 >> 8) + 1) & 0x0000011BUL);
		state[i + 2] = t2 ^ ((~(t2 >> 8) + 1) & 0x0000011BUL);
		state[i + 3] = t3 ^ ((~(t3 >> 8) + 1) & 0x0000011BUL);
	}
}

static void shift_rows(uint8_t* state)
{
	uint8_t tmp;

	tmp = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = tmp;

	tmp = state[2];
	state[2] = state[10];
	state[10] = tmp;
	tmp = state[6];
	state[6] = state[14];
	state[14] = tmp;

	tmp = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = tmp;
}

static void sub_bytes(uint8_t* state, uint8_t* sbox)
{
	size_t i;

	for (i = 0; i < RHX_BLOCK_SIZE; ++i)
	{
		state[i] = sbox[state[i]];
	}
}

static uint32_t sub_word(uint32_t rot)
{
	uint32_t val;
	uint32_t res;

	val = rot & 0xFF;
	res = s_box[val];
	val = (rot >> 8) & 0xFF;
	res |= ((uint32_t)s_box[val] << 8);
	val = (rot >> 16) & 0xFF;
	res |= ((uint32_t)s_box[val] << 16);
	val = (rot >> 24) & 0xFF;

	return res | ((uint32_t)(s_box[val]) << 24);
}

static void decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	uint8_t* buf;
	uint8_t s[16];
	size_t i;

	buf = input;
	memcpy(s, buf, RHX_BLOCK_SIZE);
	add_round_key(s, state->roundkeys + (state->rounds << 2));

	for (i = state->rounds - 1; i > 0; i--)
	{
		inv_shift_rows(s);
		inv_sub_bytes(s);
		add_round_key(s, state->roundkeys + (i << 2));
		inv_mix_columns(s);
	}

	inv_shift_rows(s);
	inv_sub_bytes(s);
	add_round_key(s, state->roundkeys);
	memcpy(output, s, RHX_BLOCK_SIZE);
}

static void encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	uint8_t buf[RHX_BLOCK_SIZE];
	size_t i;

	memcpy(buf, input, RHX_BLOCK_SIZE);
	add_round_key(buf, state->roundkeys);

	for (i = 1; i < state->rounds; ++i)
	{
		sub_bytes(buf, s_box);
		shift_rows(buf);
		mix_columns(buf);
		add_round_key(buf, state->roundkeys + (i << 2));
	}

	sub_bytes(buf, s_box);
	shift_rows(buf);
	add_round_key(buf, state->roundkeys + (state->rounds << 2));
	memcpy(output, buf, RHX_BLOCK_SIZE);
}

static void expand_rot(uint32_t* key, uint32_t keyindex, uint32_t keyoffset, uint32_t rconindex)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = key[subkey] ^ sub_word((uint32_t)(key[keyindex - 1] << 8) | (uint32_t)(key[keyindex - 1] >> 24) & 0xFF) ^ rcon[rconindex];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
}

static void expand_sub(uint32_t* key, uint32_t keyindex, uint32_t keyoffset)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = sub_word(key[keyindex - 1]) ^ key[subkey];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
}

static void prefetch_sbox(bool encryption)
{
	size_t i;
	volatile uint32_t dummy;

	dummy = 0;

	if (encryption)
	{
		for (i = 0; i < 256; ++i)
		{
			dummy += s_box[i];
		}
	}
	else
	{
		for (i = 0; i < 256; ++i)
		{
			dummy += is_box[i];
		}
	}
}

static void secure_expand(rhx_state* state, rhx_keyparams* keyparams)
{
	uint8_t* tmpi;
	uint16_t kblen;

	/* allocate the info array */
	tmpi = (uint8_t*)malloc(RHX_INFO_DEFLEN + keyparams->infolen);

	assert(tmpi != NULL);

	if (tmpi != NULL)
	{
		memset(tmpi, 0x00, RHX_INFO_DEFLEN + keyparams->infolen);

		/* add the ciphers string literal name */
		if (keyparams->keylen == RHX256_KEY_SIZE)
		{
#ifdef RHX_CSHAKE_EXTENSION
			/* RHXS256 */
			memcpy(tmpi, RHX_CSHAKE256_INFO, sizeof(RHX_CSHAKE256_INFO));
#else
			/* RHXH256 */
			memcpy(tmpi, RHX_HKDF256_INFO, sizeof(RHX_HKDF256_INFO));
#endif
		}
		else
		{
#ifdef RHX_CSHAKE_EXTENSION
			/* RHXS512 */
			memcpy(tmpi, RHX_CSHAKE512_INFO, sizeof(RHX_CSHAKE512_INFO));
#else
			/* RHXH512 */
			memcpy(tmpi, RHX_HKDF512_INFO, sizeof(RHX_HKDF512_INFO));
#endif
		}

		/* add the key size in bits to info array as a little endian ordered 16-bit integer */
		kblen = (uint16_t)(keyparams->keylen * 8);
		tmpi[7] = (uint8_t)kblen;
		tmpi[8] = (uint8_t)(kblen >> 8);

		/* copy in user supplied tweak to info array */
		if (keyparams->infolen != 0)
		{
			memcpy(tmpi + RHX_INFO_DEFLEN, keyparams->info, keyparams->infolen);
		}

		/* seed the rng and generate the round key array */
#ifdef RHX_CSHAKE_EXTENSION
		if (keyparams->keylen == RHX256_KEY_SIZE)
		{
			/* info is used as cSHAKE name parameter */
			cshake256((uint8_t*)state->roundkeys, state->rndkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
		}
		else
		{
			cshake512((uint8_t*)state->roundkeys, state->rndkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
		}
#else
		if (keyparams->keylen == RHX256_KEY_SIZE)
		{
			/* info is HKDF Expand info parameter */
			hkdf256_expand((uint8_t*)state->roundkeys, state->rndkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
		}
		else
		{
			hkdf512_expand((uint8_t*)state->roundkeys, state->rndkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
		}
#endif

		free(tmpi);
	}
}

static void standard_expand(rhx_state* state, rhx_keyparams* keyparams)
{
	/* key in 32 bit words */
	size_t kwords;

	kwords = keyparams->keylen / sizeof(uint32_t);

	if (kwords == 8)
	{
		state->roundkeys[0] = be8to32(keyparams->key);
		state->roundkeys[1] = be8to32(keyparams->key + 4);
		state->roundkeys[2] = be8to32(keyparams->key + 8);
		state->roundkeys[3] = be8to32(keyparams->key + 12);
		state->roundkeys[4] = be8to32(keyparams->key + 16);
		state->roundkeys[5] = be8to32(keyparams->key + 20);
		state->roundkeys[6] = be8to32(keyparams->key + 24);
		state->roundkeys[7] = be8to32(keyparams->key + 28);

		/* k256 r: 8,16,24,32,40,48,56 s: 12,20,28,36,44,52 */
		expand_rot(state->roundkeys, 8, 8, 1);
		expand_sub(state->roundkeys, 12, 8);
		expand_rot(state->roundkeys, 16, 8, 2);
		expand_sub(state->roundkeys, 20, 8);
		expand_rot(state->roundkeys, 24, 8, 3);
		expand_sub(state->roundkeys, 28, 8);
		expand_rot(state->roundkeys, 32, 8, 4);
		expand_sub(state->roundkeys, 36, 8);
		expand_rot(state->roundkeys, 40, 8, 5);
		expand_sub(state->roundkeys, 44, 8);
		expand_rot(state->roundkeys, 48, 8, 6);
		expand_sub(state->roundkeys, 52, 8);
		expand_rot(state->roundkeys, 56, 8, 7);
	}
	else
	{
		state->roundkeys[0] = be8to32(keyparams->key);
		state->roundkeys[1] = be8to32(keyparams->key + 4);
		state->roundkeys[2] = be8to32(keyparams->key + 8);
		state->roundkeys[3] = be8to32(keyparams->key + 12);

		/* k128 r: 4,8,12,16,20,24,28,32,36,40 */
		expand_rot(state->roundkeys, 4, 4, 1);
		expand_rot(state->roundkeys, 8, 4, 2);
		expand_rot(state->roundkeys, 12, 4, 3);
		expand_rot(state->roundkeys, 16, 4, 4);
		expand_rot(state->roundkeys, 20, 4, 5);
		expand_rot(state->roundkeys, 24, 4, 6);
		expand_rot(state->roundkeys, 28, 4, 7);
		expand_rot(state->roundkeys, 32, 4, 8);
		expand_rot(state->roundkeys, 36, 4, 9);
		expand_rot(state->roundkeys, 40, 4, 10);
	}
}

void rhx_initialize(rhx_state* state, rhx_keyparams* keyparams, bool encryption)
{
	/* null or illegal state values */
	assert(state->roundkeys != NULL);
	assert(state->rndkeylen != 0);

	if (keyparams->nonce != NULL)
	{
		state->nonce = keyparams->nonce;
	}

	if (state->rndkeylen == RHX256_ROUNDKEY_SIZE)
	{
		memset(state->roundkeys, 0x00, RHX256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		state->rounds = 22;
		secure_expand(state, keyparams);
	}
	else if (state->rndkeylen == RHX512_ROUNDKEY_SIZE)
	{
		state->rounds = 30;
		memset(state->roundkeys, 0x00, RHX512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		secure_expand(state, keyparams);
	}
	else if (state->rndkeylen == AES256_ROUNDKEY_SIZE)
	{
		state->rounds = 14;
		memset(state->roundkeys, 0x00, AES256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		standard_expand(state, keyparams);
	}
	else if (state->rndkeylen == AES128_ROUNDKEY_SIZE)
	{
		state->rounds = 10;
		memset(state->roundkeys, 0x00, AES128_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE);
		standard_expand(state, keyparams);
	}
	else
	{
		state->rounds = 0;
		state->rndkeylen = 0;
	}
#ifdef RHX_RIJNDAEL_TABLES
#ifdef RHX_PREFETCH_TABLES
	prefetch_sbox(encryption);
#endif

	/* reverse array for inverse cipher */
	if (encryption == false)
	{
		uint32_t tmpk;
		size_t i;
		size_t j;
		size_t k;

		/* reverse key */
		for (i = 0, k = state->rndkeylen - 4; i < k; i += 4, k -= 4)
		{
			for (j = 0; j < 4; j++)
			{
				tmpk = state->roundkeys[i + j];
				state->roundkeys[i + j] = state->roundkeys[k + j];
				state->roundkeys[k + j] = tmpk;
			}
		}

		/* sbox inversion */
		for (i = 4; i < state->rndkeylen - 4; i++)
		{
			state->roundkeys[i] = it_0[s_box[(state->roundkeys[i] >> 24)]] ^
				it_1[s_box[(uint8_t)(state->roundkeys[i] >> 16)]] ^
				it_2[s_box[(uint8_t)(state->roundkeys[i] >> 8)]] ^
				it_3[s_box[(uint8_t)(state->roundkeys[i])]];
		}
	}
#endif
}

#endif

/* cbc long-form */

void cbc_decrypt(rhx_state* state, const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t tmpb[RHX_BLOCK_SIZE] = { 0 };
	size_t nlen;
	size_t oftb;

	nlen = 0;
	oftb = 0;

	while (inputlen > RHX_BLOCK_SIZE)
	{
		cbc_decrypt_block(state, output + oftb, input + oftb);
		inputlen -= RHX_BLOCK_SIZE;
		oftb += RHX_BLOCK_SIZE;
	}

	cbc_decrypt_block(state, tmpb, input + oftb);
	nlen = pkcs7_padding_length(tmpb, 0, RHX_BLOCK_SIZE);
	memcpy(output + oftb, tmpb, RHX_BLOCK_SIZE - nlen);
}

void cbc_encrypt(rhx_state* state, const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t tmpb[RHX_BLOCK_SIZE] = { 0 };
	size_t oftb;

	rhx_initialize(state, keyparams, true);
	oftb = 0;

	while (inputlen > RHX_BLOCK_SIZE)
	{
		cbc_encrypt_block(state, output + oftb, input + oftb);
		inputlen -= RHX_BLOCK_SIZE;
		oftb += RHX_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		memcpy(tmpb, input + oftb, inputlen);

		if (inputlen < RHX_BLOCK_SIZE)
		{
			pkcs7_add_padding(tmpb, inputlen, RHX_BLOCK_SIZE - inputlen);
		}

		cbc_encrypt_block(state, output + oftb, tmpb);
	}
}

void cbc_decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	uint8_t tmpv[RHX_BLOCK_SIZE] = { 0 };

	memcpy(tmpv, input, RHX_BLOCK_SIZE);
	decrypt_block(state, output, input);

	for (i = 0; i < RHX_BLOCK_SIZE; ++i)
	{
		output[i] ^= state->nonce[i];
	}

	memcpy(state->nonce, tmpv, RHX_BLOCK_SIZE);
}

void cbc_encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;

	for (i = 0; i < RHX_BLOCK_SIZE; ++i)
	{
		state->nonce[i] ^= input[i];
	}

	encrypt_block(state, output, state->nonce);
	memcpy(state->nonce, output, RHX_BLOCK_SIZE);
}

/* cbc simplified */

void aes128_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES128_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, false);
	cbc_decrypt(&state, keyparams, output, input, inputlen);
}

void aes256_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, false);
	cbc_decrypt(&state, keyparams, output, input, inputlen);
}

void rhx256_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, false);
	cbc_decrypt(&state, keyparams, output, input, inputlen);
}

void rhx512_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX512_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, false);
	cbc_decrypt(&state, keyparams, output, input, inputlen);
}

void aes128_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES128_ROUNDKEY_SIZE, AES128_ROUND_COUNT };

	rhx_initialize(&state, keyparams, true);
	cbc_encrypt(&state, keyparams, output, input, inputlen);
}

void aes256_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, true);
	cbc_encrypt(&state, keyparams, output, input, inputlen);
}

void rhx256_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, true);
	cbc_encrypt(&state, keyparams, output, input, inputlen);
}

void rhx512_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX512_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, true);
	cbc_encrypt(&state, keyparams, output, input, inputlen);
}

void rhx_dispose(rhx_state* state)
{
	/* check for null state */
	assert(state != NULL);

	memset(state->roundkeys, 0x00, state->rndkeylen * ROUNDKEY_ELEMENT_SIZE);
	state->roundkeys = NULL;
	state->rndkeylen = 0;
}

/* Block-cipher counter mode with hash based authentication (HBA) AEAD authenticated mode */

static const uint8_t hba_version_info[HBA_INFO_LENGTH] =
{
	0x48, 0x42, 0x41, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x61
};

static bool hba_rhx256_initialize(const hba_keyparams* keyparams, uint8_t* cprk, uint8_t* mack)
{
#ifdef HBA_KMAC_AUTH
	const uint8_t rhx256_hba_name[HBA_NAME_LENGTH] =
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 
		0x58, 0x53, 0x32, 0x35, 0x36, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x32, 0x35, 0x36
	};
#else
	const uint8_t rhx256_hba_name[HBA_NAME_LENGTH] =
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 
		0x58, 0x48, 0x32, 0x35, 0x36, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36
	};
#endif

	shake_state shks;
	uint8_t sbuf[KMAC_256_RATE] = { 0 };
	uint8_t* cust;
	const size_t CLEN = sizeof(hba_version_info) + keyparams->infolen;

	cust = (uint8_t*)malloc(CLEN);

	if (cust != NULL)
	{
		memset(cust, 0x00, CLEN);
		clear64(shks.state, SHAKE_STATE_SIZE);

		/* copy hba info to the cSHAKE customization string */
		memcpy(cust, hba_version_info, HBA_INFO_LENGTH);

		/* copy the user info to custom */
		if (keyparams->infolen != 0)
		{
			memcpy(cust + sizeof(hba_version_info), keyparams->info, keyparams->infolen);
		}

		/* initialize an instance of cSHAKE */
		cshake256_initialize(&shks, keyparams->key, keyparams->keylen, rhx256_hba_name, HBA_NAME_LENGTH, cust, CLEN);
		free(cust);

		/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
		cshake256_squeezeblocks(&shks, sbuf, 1);
		memcpy(cprk, sbuf, keyparams->keylen);
		cshake256_squeezeblocks(&shks, sbuf, 1);
		memcpy(mack, sbuf, HBA256_MKEY_LENGTH);
		/* clear the shake buffer */
		clear64(shks.state, SHAKE_STATE_SIZE);
	}
}

static bool hba_rhx512_initialize(const hba_keyparams* keyparams, uint8_t* cprk, uint8_t* mack)
{
#ifdef HBA_KMAC_AUTH
	static const uint8_t rhx512_hba_name[HBA_NAME_LENGTH] =
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 
		0x58, 0x53, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x35, 0x31, 0x32
	};
#else
	static const uint8_t rhx512_hba_name[HBA_NAME_LENGTH] =
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
		0x58, 0x48, 0x35, 0x31, 0x32, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x35, 0x31, 0x32
	};
#endif

	shake_state shks;
#if defined RHX_CSHAKE_EXTENSION
	uint8_t sbuf[KMAC_512_RATE] = { 0 };
#else
	uint8_t sbuf[KMAC_512_RATE * 2] = { 0 };
#endif
	uint8_t* cust;
	const size_t CLEN = sizeof(hba_version_info) + keyparams->infolen;

	cust = (uint8_t*)malloc(CLEN);

	if (cust != NULL)
	{
		memset(cust, 0x00, CLEN);
		clear64(shks.state, SHAKE_STATE_SIZE);

		/* copy hba info to the cSHAKE customization string */
		memcpy(cust, hba_version_info, HBA_INFO_LENGTH);

		/* copy the user info to custom */
		if (keyparams->infolen != 0)
		{
			memcpy(cust + sizeof(hba_version_info), keyparams->info, keyparams->infolen);
		}

		/* initialize an instance of cSHAKE */
		cshake512_initialize(&shks, keyparams->key, keyparams->keylen, rhx512_hba_name, HBA_NAME_LENGTH, cust, CLEN);
		free(cust);
		/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */

		cshake512_squeezeblocks(&shks, sbuf, 1);
		memcpy(cprk, sbuf, keyparams->keylen);
#if defined RHX_CSHAKE_EXTENSION
		cshake512_squeezeblocks(&shks, sbuf, 1);
		memcpy(mack, sbuf, HBA512_MKEY_LENGTH);
#else
		cshake512_squeezeblocks(&shks, sbuf, 2);
		memcpy(mack, sbuf, HBA512_MKEY_LENGTH);
#endif
		/* clear the shake buffer */
		clear64(shks.state, SHAKE_STATE_SIZE);
	}
}

bool hba_rhx256_decrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t code[HBA256_MAC_LENGTH] = { 0 };
	uint8_t cprk[RHX256_KEY_SIZE] = { 0 };
	uint8_t mack[HBA256_MKEY_LENGTH] = { 0 };
	uint8_t* minp;
	uint64_t mctr;
	const size_t TLEN = RHX_BLOCK_SIZE + inputlen + keyparams->aadlen + sizeof(uint64_t);
	bool res;

	res = false;

	/* allocate the mac input array */
	minp = (uint8_t*)malloc(TLEN);
	
	if (minp != NULL)
	{
		/* initialize the rhx-256 cipher instance */
		hba_rhx256_initialize(keyparams, cprk, mack);

		/* copy the cipher nonce, ciphertext, aad, and mac counter to the input array */
		memcpy(minp, keyparams->nonce, RHX_BLOCK_SIZE);

		if (inputlen != 0)
		{
			memcpy(minp + RHX_BLOCK_SIZE, input, inputlen);
		}

		if (inputlen != keyparams->aadlen)
		{
			memcpy(minp + RHX_BLOCK_SIZE + inputlen, keyparams->aad, keyparams->aadlen);
		}

		/* append the total number of processed bytes + 1, to the end of the mac input array */
		mctr = 0x00000001ULL + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen;
		le64to8(minp + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen, mctr);

#ifdef HBA_KMAC_AUTH
		/* mac the data and generate the mac code */
		kmac256(code, KMAC_256_MAC, minp, TLEN, mack, sizeof(mack), NULL, 0);
#else
		/* mac the data and generate the mac code */
		hmac256_compute(code, minp, TLEN, mack, sizeof(mack));
#endif

		free(minp);

		/* constant-time comparison of the newly generated mac code with the one appended to the cipher-text array */
		res = verify(code, input + inputlen, KMAC_256_MAC) == 0;

		/* only decrypt if the cipher-text mac-code matches */
		if (res == true)
		{
			rhx_keyparams kp = { cprk, sizeof(cprk), keyparams->nonce, keyparams->info, keyparams->infolen };
			rhx256_ctr_transform(&kp, output, input, inputlen);
		}
	}

	return res;
}

bool hba_rhx256_encrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t cprk[RHX256_KEY_SIZE] = { 0 };
	uint8_t mack[HBA256_MKEY_LENGTH] = { 0 };
	uint8_t* minp;
	uint64_t mctr;
	const size_t TLEN = RHX_BLOCK_SIZE + inputlen + keyparams->aadlen + sizeof(uint64_t);
	bool res;

	res = false;

	/* allocate the input array */
	minp = (uint8_t*)malloc(TLEN);

	if (minp != NULL)
	{
		clear8(minp, TLEN);

		/* initialize the hba cipher and mac keys */
		hba_rhx256_initialize(keyparams, cprk, mack);

		/* copy the starting position of the nonce to the mac buffer array */
		memcpy(minp, keyparams->nonce, RHX_BLOCK_SIZE);

		/* key the rhx-256 counter mode, and encrypt the array */
		rhx_keyparams kp = { cprk, sizeof(cprk), keyparams->nonce, keyparams->info, keyparams->infolen };
		rhx256_ctr_transform(&kp, output, input, inputlen);

		/* copy the ciphertext, aad, and mac counter to the buffer array */
		if (inputlen != 0)
		{
			memcpy(minp + RHX_BLOCK_SIZE, output, inputlen);
		}

		if (keyparams->aadlen != 0)
		{
			memcpy(minp + RHX_BLOCK_SIZE + inputlen, keyparams->aad, keyparams->aadlen);
		}

		/* add 1 + the nonce, input, and aad sizes to the counter */
		mctr = 0x00000001ULL + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen;
		/* append the counter to the end of the mac input array */
		le64to8(minp + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen, mctr);


#ifdef HBA_KMAC_AUTH
		/* mac the data and add the code to the end of the cipher-text output array */
		kmac256(output + inputlen, KMAC_256_MAC, minp, TLEN, mack, sizeof(mack), NULL, 0);
#else
		/* mac the data and add the code to the end of the cipher-text output array */
		hmac256_compute(output + inputlen, minp, TLEN, mack, sizeof(mack));
#endif

		clear8(minp, TLEN);
		free(minp);
		res = true;
	}

	return res;
}

bool hba_rhx512_decrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t code[HBA512_MAC_LENGTH] = { 0 };
	uint8_t cprk[RHX512_KEY_SIZE] = { 0 };
	uint8_t mack[HBA512_MKEY_LENGTH] = { 0 };
	uint8_t* minp;
	uint64_t mctr;
	const size_t TLEN = RHX_BLOCK_SIZE + inputlen + keyparams->aadlen + sizeof(uint64_t);
	bool res;

	res = false;

	/* allocate the mac input array */
	minp = (uint8_t*)malloc(TLEN);

	if (minp != NULL)
	{
		/* initialize the rhx-512 cipher instance */
		hba_rhx512_initialize(keyparams, cprk, mack);

		/* copy the cipher nonce, aad, ciphertext, and mac counter to the input array */
		memcpy(minp, keyparams->nonce, RHX_BLOCK_SIZE);
		memcpy(minp + RHX_BLOCK_SIZE, input, inputlen);
		memcpy(minp + RHX_BLOCK_SIZE + inputlen, keyparams->aad, keyparams->aadlen);

		/* append the total number of processed bytes + 1, to the end of the mac input array */
		mctr = 0x00000001ULL + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen;
		le64to8(minp + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen, mctr);

#ifdef HBA_KMAC_AUTH
		/* mac the data and add the code to the end of the cipher-text output array */
		kmac512(code, KMAC_512_MAC, minp, TLEN, mack, sizeof(mack), NULL, 0);
#else
		/* mac the data and add the code to the end of the cipher-text output array */
		hmac512_compute(code, minp, TLEN, mack, sizeof(mack));
#endif

		free(minp);

		/* constant-time comparison of the newly generated mac code with the one appended to the cipher-text array */
		res = verify(code, input + inputlen, KMAC_512_MAC) == 0;

		/* only decrypt if the cipher-text mac-code matches */
		if (res == true)
		{
			rhx_keyparams kp = { cprk, sizeof(cprk), keyparams->nonce, keyparams->info, keyparams->infolen };
			rhx512_ctr_transform(&kp, output, input, inputlen);
		}
	}

	return res;
}

bool hba_rhx512_encrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t cprk[RHX512_KEY_SIZE] = { 0 };
	uint8_t mack[HBA512_MKEY_LENGTH] = { 0 };
	uint8_t* minp;
	uint64_t mctr;
	const size_t TLEN = RHX_BLOCK_SIZE + inputlen + keyparams->aadlen + sizeof(uint64_t);
	bool res;

	res = false;

	/* allocate the input array */
	minp = (uint8_t*)malloc(TLEN);

	if (minp != NULL)
	{
		clear8(minp, TLEN);

		/* initialize the hba cipher and mac keys */
		hba_rhx512_initialize(keyparams, cprk, mack);

		/* copy the starting position of the nonce to the mac buffer array */
		memcpy(minp, keyparams->nonce, RHX_BLOCK_SIZE);

		/* key the rhx-512 counter mode, and encrypt the array */
		rhx_keyparams kp = { cprk, sizeof(cprk), keyparams->nonce, keyparams->info, keyparams->infolen };
		rhx512_ctr_transform(&kp, output, input, inputlen);

		/* copy the ciphertext, aad, and mac counter to the buffer array */
		if (inputlen != 0)
		{
			memcpy(minp + RHX_BLOCK_SIZE, output, inputlen);
		}

		if (keyparams->aadlen != 0)
		{
			memcpy(minp + RHX_BLOCK_SIZE + inputlen, keyparams->aad, keyparams->aadlen);
		}

		/* add 1 + the nonce, input, and aad sizes to the counter */
		mctr = 0x00000001ULL + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen;
		/* append the counter to the end of the mac input array */
		le64to8(minp + RHX_BLOCK_SIZE + inputlen + keyparams->aadlen, mctr);

#ifdef HBA_KMAC_AUTH
		/* mac the data and add the code to the end of the cipher-text output array */
		kmac512(output + inputlen, KMAC_512_MAC, minp, TLEN, mack, sizeof(mack), NULL, 0);
#else
		/* mac the data and add the code to the end of the cipher-text output array */
		hmac512_compute(output + inputlen, minp, TLEN, mack, sizeof(mack));
#endif

		clear8(minp, TLEN);
		free(minp);
		res = true;
	}

	return res;
}

/* ctr long-form */

void ctr_transform(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	size_t poff;

	poff = 0;

	while (inputlen >= RHX_BLOCK_SIZE)
	{
		encrypt_block(state, output + poff, state->nonce);

		for (i = 0; i < RHX_BLOCK_SIZE; ++i)
		{
			output[poff + i] ^= input[poff + i];
		}

		be8increment(state->nonce, RHX_BLOCK_SIZE);

		inputlen -= RHX_BLOCK_SIZE;
		poff += RHX_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[RHX_BLOCK_SIZE] = { 0 };

		encrypt_block(state, tmpb, state->nonce);

		for (i = 0; i < inputlen; ++i)
		{
			output[poff + i] = tmpb[i] ^ input[poff + i];
		}

		be8increment(state->nonce, RHX_BLOCK_SIZE);
	}
}

/* ctr simplified */

void aes128_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES128_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES128_ROUNDKEY_SIZE  };

	rhx_initialize(&state, keyparams, true);
	ctr_transform(&state, keyparams, output, input, inputlen);
}

void aes256_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[AES256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, AES256_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, true);
	ctr_transform(&state, keyparams, output, input, inputlen);
}

void rhx256_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, true);
	ctr_transform(&state, output, input, inputlen);
}

void rhx512_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(keyparams->key != NULL);
	assert(keyparams->nonce != NULL);
	assert(input != NULL);
	assert(output != NULL);

	/* initialize the state round-key array */
#if defined(RHX_AESNI_ENABLED)
	__m128i rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#else
	uint32_t rkeys[RHX512_ROUNDKEY_SIZE] = { 0 };
#endif

	/* initialize the state and set the round-key array size */
	rhx_state state = { rkeys, RHX512_ROUNDKEY_SIZE };

	rhx_initialize(&state, keyparams, true);
	ctr_transform(&state, output, input, inputlen);
}

/* ecb long-form only */

void rhx_ecb_decrypt(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	decrypt_block(state, output, input);
}

void rhx_ecb_encrypt(rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	encrypt_block(state, output, input);
}

/* pkcs7 padding */

void pkcs7_add_padding(uint8_t* input, size_t offset, size_t length)
{
	assert(input != NULL);

	size_t i;
	uint8_t code;

	code = (uint8_t)(length - offset);

	for (i = offset; i < length; ++i)
	{
		input[i] = code;
	}
}

size_t pkcs7_padding_length(const uint8_t* input, size_t offset, size_t length)
{
	assert(input != NULL);

	size_t pos;
	int32_t i;
	uint8_t code;

	pos = length - (offset + 1);
	code = input[length - 1];

	if ((int32_t)code > pos)
	{
		code = 0x00;
	}
	else
	{
		for (i = (int32_t)length - 1; i >= (int32_t)length - code; --i)
		{
			if (input[i] != code)
			{
				code = 0;
				break;
			}
		}
	}

	return (size_t)code;
}
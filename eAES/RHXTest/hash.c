#include "hash.h"
#include "utils.h"

/* SHA3 */

/* keccak round constants */
static const uint64_t KECCAK_ROUND_CONSTANTS[KECCAK_PERMUTATION_MAX_ROUNDS] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
	0x8000000080008082ULL, 0x800000008000800AULL, 0x8000000000000003ULL, 0x8000000080000009ULL,
	0x8000000000008082ULL, 0x0000000000008009ULL, 0x8000000000000080ULL, 0x0000000000008083ULL,
	0x8000000000000081ULL, 0x0000000000000001ULL, 0x000000000000800BULL, 0x8000000080008001ULL,
	0x0000000000000080ULL, 0x8000000000008000ULL, 0x8000000080008001ULL, 0x0000000000000009ULL,
	0x800000008000808BULL, 0x0000000000000081ULL, 0x8000000000000082ULL, 0x000000008000008BULL,
	0x8000000080008009ULL, 0x8000000080000000ULL, 0x0000000080000080ULL, 0x0000000080008003ULL
};

static void keccak_fast_absorb(uint64_t* state, const uint8_t* message, size_t msglen)
{
#if defined(SYSTEM_IS_LITTLE_ENDIAN)
	utils_memory_xor((uint8_t*)state, message, msglen);
#else
	for (size_t i = 0; i < msglen / sizeof(uint64_t); ++i)
	{
		state[i] ^= utils_integer_le8to64((message + (sizeof(uint64_t) * i)));
	}
#endif
}

static size_t keccak_left_encode(uint8_t* buffer, size_t value)
{
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && n < sizeof(size_t); ++n, v >>= 8) { /* increments n */ }

	if (n == 0)
	{
		n = 1;
	}

	for (size_t i = 1; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[0] = (uint8_t)n;

	return n + 1;
}

static size_t keccak_right_encode(uint8_t* buffer, size_t value)
{
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) { /* increments n */ }

	if (n == 0)
	{
		n = 1;
	}

	for (size_t i = 1; i <= n; ++i)
	{
		buffer[i - 1] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return n + 1;
}

/* Keccak */

void keccak_absorb(keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen, uint8_t domain, size_t rounds)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (ctx != NULL && message != NULL)
	{
		uint8_t msg[KECCAK_STATE_BYTE_SIZE];

		while (msglen >= (size_t)rate)
		{
#if defined(SYSTEM_IS_LITTLE_ENDIAN)
			utils_memory_xor((uint8_t*)ctx->state, message, rate);
#else
			for (size_t i = 0; i < rate / sizeof(uint64_t); ++i)
			{
				ctx->state[i] ^= utils_integer_le8to64((message + (sizeof(uint64_t) * i)));
			}
#endif
			keccak_permute(ctx, rounds);
			msglen -= rate;
			message += rate;
	}

		utils_memory_copy(msg, message, msglen);
		msg[msglen] = domain;
		utils_memory_clear((msg + msglen + 1), rate - msglen + 1);
		msg[rate - 1] |= 128U;

#if defined(SYSTEM_IS_LITTLE_ENDIAN)
		utils_memory_xor((uint8_t*)ctx->state, msg, rate);
#else
		for (size_t i = 0; i < rate / 8; ++i)
		{
			ctx->state[i] ^= utils_integer_le8to64((msg + (8 * i)));
		}
#endif
	}
}

void keccak_absorb_custom(keccak_state* ctx, keccak_rate rate, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	assert(ctx != NULL);

	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t i;
	size_t oft;

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), namelen * 8);

	if (name != NULL)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = name[i];
			++oft;
		}
	}

	oft += keccak_left_encode((pad + oft), custlen * 8);

	if (custom != NULL)
	{
		for (i = 0; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = custom[i];
			++oft;
		}
	}

	utils_memory_clear((pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	keccak_permute(ctx, rounds);
}

void keccak_absorb_key_custom(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	assert(ctx != NULL);

	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t oft;
	size_t i;

	utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), namelen * 8);

	if (name != NULL)
	{
		for (i = 0; i < namelen; ++i)
		{
			pad[oft + i] = name[i];
		}
	}

	oft += namelen;
	oft += keccak_left_encode((pad + oft), custlen * 8);

	if (custom != NULL)
	{
		for (i = 0; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = custom[i];
			++oft;
		}
	}

	utils_memory_clear((pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	keccak_permute(ctx, rounds);


	/* stage 2: key */

	utils_memory_clear(pad, rate);

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), keylen * 8);

	if (key != NULL)
	{
		for (i = 0; i < keylen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = key[i];
			++oft;
		}
	}

	utils_memory_clear((pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	keccak_permute(ctx, rounds);
}

void keccak_dispose(keccak_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0;
	}
}

void keccak_finalize(keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen, uint8_t domain, size_t rounds)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t bitlen;

	utils_memory_copy(pad, ctx->buffer, ctx->position);
	bitlen = keccak_right_encode(buf, outlen * 8);

	if (ctx->position + bitlen >= (size_t)rate)
	{
		keccak_fast_absorb(ctx->state, pad, ctx->position);
		keccak_permute(ctx, rounds);
		ctx->position = 0;
	}

	utils_memory_copy((pad + ctx->position), buf, bitlen);

	pad[ctx->position + bitlen] = domain;
	pad[rate - 1] |= 128U;
	keccak_fast_absorb(ctx->state, pad, rate);

	while (outlen >= (size_t)rate)
	{
		keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		utils_memory_copy(output, pad, rate);
		output += rate;
		outlen -= rate;
	}

	if (outlen > 0)
	{
		keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		utils_memory_copy(output, pad, outlen);
	}

	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;
}

void keccak_incremental_absorb(keccak_state* ctx, uint32_t rate, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	uint8_t t[8] = { 0 };
	size_t i;

	if ((ctx->position & 7) > 0)
	{
		i = ctx->position & 7;

		while (i < 8 && msglen > 0)
		{
			t[i] = *message;
			message++;
			i++;
			msglen--;
			ctx->position++;
		}

		ctx->state[(ctx->position - i) / 8] ^= utils_integer_le8to64(t);
	}

	if (ctx->position && msglen >= rate - ctx->position)
	{
		for (i = 0; i < (rate - ctx->position) / 8; ++i)
		{
			ctx->state[(ctx->position / 8) + i] ^= utils_integer_le8to64(message + (8 * i));
		}

		message += rate - ctx->position;
		msglen -= rate - ctx->position;
		ctx->position = 0;
		keccak_permute_p1600c(ctx->state, KECCAK_PERMUTATION_ROUNDS);
	}

	while (msglen >= rate)
	{
		for (i = 0; i < rate / 8; i++)
		{
			ctx->state[i] ^= utils_integer_le8to64(message + (8 * i));
		}

		message += rate;
		msglen -= rate;
		keccak_permute_p1600c(ctx->state, KECCAK_PERMUTATION_ROUNDS);
	}

	for (i = 0; i < msglen / 8; ++i)
	{
		ctx->state[(ctx->position / 8) + i] ^= utils_integer_le8to64(message + (8 * i));
	}

	message += 8 * i;
	msglen -= 8 * i;
	ctx->position += 8 * i;

	if (msglen > 0)
	{
		for (i = 0; i < 8; ++i)
		{
			t[i] = 0;
		}

		for (i = 0; i < msglen; ++i)
		{
			t[i] = message[i];
		}

		ctx->state[ctx->position / 8] ^= utils_integer_le8to64(t);
		ctx->position += msglen;
	}
}

void keccak_incremental_finalize(keccak_state* ctx, uint32_t rate, uint8_t domain)
{
	assert(ctx != NULL);
	
	size_t i;
	size_t j;

	i = ctx->position >> 3;
	j = ctx->position & 7;
	ctx->state[i] ^= ((uint64_t)domain << (8 * j));
	ctx->state[(rate / 8) - 1] ^= 1ULL << 63;
	ctx->position = 0;
}

void keccak_incremental_squeeze(keccak_state* ctx, size_t rate, uint8_t* output, size_t outlen)
{
	assert(ctx != NULL);
	assert(output != NULL);

	size_t i;
	uint8_t t[8];

	if ((ctx->position & 7) > 0)
	{
		utils_integer_le64to8(t, ctx->state[ctx->position / 8]);
		i = ctx->position & 7;

		while (i < 8 && outlen > 0)
		{
			*output = t[i];
			output++;
			i++;
			outlen--;
			ctx->position++;
		}
	}

	if (ctx->position && outlen >= rate - ctx->position)
	{
		for (i = 0; i < (rate - ctx->position) / 8; ++i)
		{
			utils_integer_le64to8(output + (8 * i), ctx->state[(ctx->position / 8) + i]);
		}

		output += rate - ctx->position;
		outlen -= rate - ctx->position;
		ctx->position = 0;
	}

	while (outlen >= rate)
	{
		keccak_permute_p1600c(ctx->state, KECCAK_PERMUTATION_ROUNDS);

		for (i = 0; i < rate / 8; ++i)
		{
			utils_integer_le64to8(output + (8 * i), ctx->state[i]);
		}

		output += rate;
		outlen -= rate;
	}

	if (outlen > 0)
	{
		if (ctx->position == 0)
		{
			keccak_permute_p1600c(ctx->state, KECCAK_PERMUTATION_ROUNDS);
		}

		for (i = 0; i < outlen / 8; ++i)
		{
			utils_integer_le64to8(output + (8 * i), ctx->state[(ctx->position / 8) + i]);
		}

		output += 8 * i;
		outlen -= 8 * i;
		ctx->position += 8 * i;

		utils_integer_le64to8(t, ctx->state[ctx->position / 8]);

		for (i = 0; i < outlen; ++i)
		{
			output[i] = t[i];
		}

		ctx->position += outlen;
	}
}

void keccak_permute(keccak_state* ctx, size_t rounds)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		keccak_permute_p1600c(ctx->state, rounds);
	}
}

void keccak_permute_p1600c(uint64_t* state, size_t rounds)
{
	assert(state != NULL);
	assert(rounds % 2 == 0);

	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t BCa;
	uint64_t BCe;
	uint64_t BCi;
	uint64_t BCo;
	uint64_t BCu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	/* copyFromState(A, state) */
	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	for (size_t i = 0; i < rounds; i += 2)
	{
		/* prepareTheta */
		BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ utils_integer_rotl64(BCe, 1);
		De = BCa ^ utils_integer_rotl64(BCi, 1);
		Di = BCe ^ utils_integer_rotl64(BCo, 1);
		Do = BCi ^ utils_integer_rotl64(BCu, 1);
		Du = BCo ^ utils_integer_rotl64(BCa, 1);

		Aba ^= Da;
		BCa = Aba;
		Age ^= De;
		BCe = utils_integer_rotl64(Age, 44);
		Aki ^= Di;
		BCi = utils_integer_rotl64(Aki, 43);
		Amo ^= Do;
		BCo = utils_integer_rotl64(Amo, 21);
		Asu ^= Du;
		BCu = utils_integer_rotl64(Asu, 14);
		Eba = BCa ^ ((~BCe) & BCi);
		Eba ^= KECCAK_ROUND_CONSTANTS[i];
		Ebe = BCe ^ ((~BCi) & BCo);
		Ebi = BCi ^ ((~BCo) & BCu);
		Ebo = BCo ^ ((~BCu) & BCa);
		Ebu = BCu ^ ((~BCa) & BCe);

		Abo ^= Do;
		BCa = utils_integer_rotl64(Abo, 28);
		Agu ^= Du;
		BCe = utils_integer_rotl64(Agu, 20);
		Aka ^= Da;
		BCi = utils_integer_rotl64(Aka, 3);
		Ame ^= De;
		BCo = utils_integer_rotl64(Ame, 45);
		Asi ^= Di;
		BCu = utils_integer_rotl64(Asi, 61);
		Ega = BCa ^ ((~BCe) & BCi);
		Ege = BCe ^ ((~BCi) & BCo);
		Egi = BCi ^ ((~BCo) & BCu);
		Ego = BCo ^ ((~BCu) & BCa);
		Egu = BCu ^ ((~BCa) & BCe);

		Abe ^= De;
		BCa = utils_integer_rotl64(Abe, 1);
		Agi ^= Di;
		BCe = utils_integer_rotl64(Agi, 6);
		Ako ^= Do;
		BCi = utils_integer_rotl64(Ako, 25);
		Amu ^= Du;
		BCo = utils_integer_rotl64(Amu, 8);
		Asa ^= Da;
		BCu = utils_integer_rotl64(Asa, 18);
		Eka = BCa ^ ((~BCe) & BCi);
		Eke = BCe ^ ((~BCi) & BCo);
		Eki = BCi ^ ((~BCo) & BCu);
		Eko = BCo ^ ((~BCu) & BCa);
		Eku = BCu ^ ((~BCa) & BCe);

		Abu ^= Du;
		BCa = utils_integer_rotl64(Abu, 27);
		Aga ^= Da;
		BCe = utils_integer_rotl64(Aga, 36);
		Ake ^= De;
		BCi = utils_integer_rotl64(Ake, 10);
		Ami ^= Di;
		BCo = utils_integer_rotl64(Ami, 15);
		Aso ^= Do;
		BCu = utils_integer_rotl64(Aso, 56);
		Ema = BCa ^ ((~BCe) & BCi);
		Eme = BCe ^ ((~BCi) & BCo);
		Emi = BCi ^ ((~BCo) & BCu);
		Emo = BCo ^ ((~BCu) & BCa);
		Emu = BCu ^ ((~BCa) & BCe);

		Abi ^= Di;
		BCa = utils_integer_rotl64(Abi, 62);
		Ago ^= Do;
		BCe = utils_integer_rotl64(Ago, 55);
		Aku ^= Du;
		BCi = utils_integer_rotl64(Aku, 39);
		Ama ^= Da;
		BCo = utils_integer_rotl64(Ama, 41);
		Ase ^= De;
		BCu = utils_integer_rotl64(Ase, 2);
		Esa = BCa ^ ((~BCe) & BCi);
		Ese = BCe ^ ((~BCi) & BCo);
		Esi = BCi ^ ((~BCo) & BCu);
		Eso = BCo ^ ((~BCu) & BCa);
		Esu = BCu ^ ((~BCa) & BCe);

		/* prepareTheta */
		BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ utils_integer_rotl64(BCe, 1);
		De = BCa ^ utils_integer_rotl64(BCi, 1);
		Di = BCe ^ utils_integer_rotl64(BCo, 1);
		Do = BCi ^ utils_integer_rotl64(BCu, 1);
		Du = BCo ^ utils_integer_rotl64(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = utils_integer_rotl64(Ege, 44);
		Eki ^= Di;
		BCi = utils_integer_rotl64(Eki, 43);
		Emo ^= Do;
		BCo = utils_integer_rotl64(Emo, 21);
		Esu ^= Du;
		BCu = utils_integer_rotl64(Esu, 14);
		Aba = BCa ^ ((~BCe) & BCi);
		Aba ^= KECCAK_ROUND_CONSTANTS[i + 1];
		Abe = BCe ^ ((~BCi) & BCo);
		Abi = BCi ^ ((~BCo) & BCu);
		Abo = BCo ^ ((~BCu) & BCa);
		Abu = BCu ^ ((~BCa) & BCe);

		Ebo ^= Do;
		BCa = utils_integer_rotl64(Ebo, 28);
		Egu ^= Du;
		BCe = utils_integer_rotl64(Egu, 20);
		Eka ^= Da;
		BCi = utils_integer_rotl64(Eka, 3);
		Eme ^= De;
		BCo = utils_integer_rotl64(Eme, 45);
		Esi ^= Di;
		BCu = utils_integer_rotl64(Esi, 61);
		Aga = BCa ^ ((~BCe) & BCi);
		Age = BCe ^ ((~BCi) & BCo);
		Agi = BCi ^ ((~BCo) & BCu);
		Ago = BCo ^ ((~BCu) & BCa);
		Agu = BCu ^ ((~BCa) & BCe);

		Ebe ^= De;
		BCa = utils_integer_rotl64(Ebe, 1);
		Egi ^= Di;
		BCe = utils_integer_rotl64(Egi, 6);
		Eko ^= Do;
		BCi = utils_integer_rotl64(Eko, 25);
		Emu ^= Du;
		BCo = utils_integer_rotl64(Emu, 8);
		Esa ^= Da;
		BCu = utils_integer_rotl64(Esa, 18);
		Aka = BCa ^ ((~BCe) & BCi);
		Ake = BCe ^ ((~BCi) & BCo);
		Aki = BCi ^ ((~BCo) & BCu);
		Ako = BCo ^ ((~BCu) & BCa);
		Aku = BCu ^ ((~BCa) & BCe);

		Ebu ^= Du;
		BCa = utils_integer_rotl64(Ebu, 27);
		Ega ^= Da;
		BCe = utils_integer_rotl64(Ega, 36);
		Eke ^= De;
		BCi = utils_integer_rotl64(Eke, 10);
		Emi ^= Di;
		BCo = utils_integer_rotl64(Emi, 15);
		Eso ^= Do;
		BCu = utils_integer_rotl64(Eso, 56);
		Ama = BCa ^ ((~BCe) & BCi);
		Ame = BCe ^ ((~BCi) & BCo);
		Ami = BCi ^ ((~BCo) & BCu);
		Amo = BCo ^ ((~BCu) & BCa);
		Amu = BCu ^ ((~BCa) & BCe);

		Ebi ^= Di;
		BCa = utils_integer_rotl64(Ebi, 62);
		Ego ^= Do;
		BCe = utils_integer_rotl64(Ego, 55);
		Eku ^= Du;
		BCi = utils_integer_rotl64(Eku, 39);
		Ema ^= Da;
		BCo = utils_integer_rotl64(Ema, 41);
		Ese ^= De;
		BCu = utils_integer_rotl64(Ese, 2);
		Asa = BCa ^ ((~BCe) & BCi);
		Ase = BCe ^ ((~BCi) & BCo);
		Asi = BCi ^ ((~BCo) & BCu);
		Aso = BCo ^ ((~BCu) & BCa);
		Asu = BCu ^ ((~BCa) & BCe);
	}

	/* copy to state */
	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

void keccak_squeezeblocks(keccak_state* ctx, uint8_t* output, size_t nblocks, keccak_rate rate, size_t rounds)
{
	assert(ctx != NULL);
	assert(output != NULL);

	if (ctx != NULL && output != NULL)
	{
		while (nblocks > 0)
		{
			keccak_permute(ctx, rounds);

#if defined(SYSTEM_IS_LITTLE_ENDIAN)
			utils_memory_copy(output, (uint8_t*)ctx->state, rate);
#else
			for (size_t i = 0; i < (rate >> 3); ++i)
			{
				utils_integer_le64to8((output + sizeof(uint64_t) * i), ctx->state[i]);
			}
#endif
			output += rate;
			nblocks--;
		}
	}
}

void keccak_initialize_state(keccak_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0;
	}
}

void keccak_update(keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen, size_t rounds)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (ctx != NULL && message != NULL && msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= (size_t)rate))
		{
			const size_t RMDLEN = rate - ctx->position;

			if (RMDLEN != 0)
			{
				utils_memory_copy((ctx->buffer + ctx->position), message, RMDLEN);
			}

			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			keccak_permute(ctx, rounds);
			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, message, rate);
			keccak_permute(ctx, rounds);
			message += rate;
			msglen -= rate;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			utils_memory_copy((ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

/* cSHAKE */

void cshake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / KECCAK_256_RATE;
	keccak_state ctx;
	uint8_t hash[KECCAK_256_RATE] = { 0 };

	if (custlen + namelen != 0)
	{
		cshake_initialize(&ctx, keccak_rate_256, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		shake_initialize(&ctx, keccak_rate_256, key, keylen);
	}

	cshake_squeezeblocks(&ctx, keccak_rate_256, output, nblocks);

	output += (nblocks * KECCAK_256_RATE);
	outlen -= (nblocks * KECCAK_256_RATE);

	if (outlen != 0)
	{
		cshake_squeezeblocks(&ctx, keccak_rate_256, hash, 1);
		utils_memory_copy(output, hash, outlen);
	}

	keccak_dispose(&ctx);
}

void cshake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / KECCAK_512_RATE;
	keccak_state ctx;
	uint8_t hash[KECCAK_512_RATE] = { 0 };

	if (custlen + namelen != 0)
	{
		cshake_initialize(&ctx, keccak_rate_512, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		shake_initialize(&ctx, keccak_rate_512, key, keylen);
	}

	cshake_squeezeblocks(&ctx, keccak_rate_512, output, nblocks);
	output += (nblocks * KECCAK_512_RATE);
	outlen -= (nblocks * KECCAK_512_RATE);

	if (outlen != 0)
	{
		cshake_squeezeblocks(&ctx, keccak_rate_512, hash, 1);
		utils_memory_copy(output, hash, outlen);
	}

	keccak_dispose(&ctx);
}

void shake_initialize(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	keccak_initialize_state(ctx);
	keccak_absorb(ctx, rate, key, keylen, KECCAK_SHAKE_DOMAIN_ID, KECCAK_PERMUTATION_ROUNDS);
}

void cshake_initialize(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	keccak_initialize_state(ctx);
	/* absorb the custom and name arrays */
	keccak_absorb_custom(ctx, rate, custom, custlen, name, namelen, KECCAK_PERMUTATION_ROUNDS);
	/* finalize the key */
	keccak_absorb(ctx, rate, key, keylen, KECCAK_CSHAKE_DOMAIN_ID, KECCAK_PERMUTATION_ROUNDS);
}

void cshake_squeezeblocks(keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(ctx, output, nblocks, rate, KECCAK_PERMUTATION_ROUNDS);
}

void cshake_update(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	while (keylen >= (size_t)rate)
	{
		keccak_fast_absorb(ctx->state, key, keylen);
		keccak_permute(ctx, KECCAK_PERMUTATION_ROUNDS);
		keylen -= rate;
		key += rate;
	}

	if (keylen != 0)
	{
		keccak_fast_absorb(ctx->state, key, keylen);
		keccak_permute(ctx, KECCAK_PERMUTATION_ROUNDS);
	}
}

/* KMAC */

void kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	keccak_state ctx;

	kmac_initialize(&ctx, keccak_rate_256, key, keylen, custom, custlen);
	kmac_update(&ctx, keccak_rate_256, message, msglen);
	kmac_finalize(&ctx, keccak_rate_256, output, outlen);
}

void kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	keccak_state ctx;

	kmac_initialize(&ctx, keccak_rate_512, key, keylen, custom, custlen);
	kmac_update(&ctx, keccak_rate_512, message, msglen);
	kmac_finalize(&ctx, keccak_rate_512, output, outlen);
}

void kmac_finalize(keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen)
{
	keccak_finalize(ctx, rate, output, outlen, KECCAK_KMAC_DOMAIN_ID, KECCAK_PERMUTATION_ROUNDS);
}

void kmac_initialize(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	const uint8_t name[4] = { 0x4B, 0x4D, 0x41, 0x43 };

	keccak_absorb_key_custom(ctx, rate, key, keylen, custom, custlen, name, sizeof(name), KECCAK_PERMUTATION_ROUNDS);
}

void kmac_update(keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	keccak_update(ctx, rate, message, msglen, KECCAK_PERMUTATION_ROUNDS);
}

/* SHA2 */

/* SHA2-256 */

static const uint32_t sha256_iv[8] =
{
	0x6A09E667UL,
	0xBB67AE85UL,
	0x3C6EF372UL,
	0xA54FF53AUL,
	0x510E527FUL,
	0x9B05688CUL,
	0x1F83D9ABUL,
	0x5BE0CD19UL
};

static void sha256_increase(sha256_state* ctx, size_t msglen)
{
	ctx->t += msglen;
}

SYSTEM_OPTIMIZE_IGNORE
void sha256_dispose(sha256_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->t = 0;
		ctx->position = 0;
	}
}
SYSTEM_OPTIMIZE_RESUME

void sha256_compute(uint8_t* output, const uint8_t* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);

	sha256_state ctx;

	sha256_initialize(&ctx);
	sha256_update(&ctx, message, msglen);
	sha256_finalize(&ctx, output);
}

void sha256_finalize(sha256_state* ctx, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint8_t pad[SHA2_256_RATE] = { 0 };
	uint64_t bitLen;

	utils_memory_copy(pad, ctx->buffer, ctx->position);
	sha256_increase(ctx, ctx->position);
	bitLen = (ctx->t << 3);

	if (ctx->position == SHA2_256_RATE)
	{
		sha256_permute(ctx->state, pad);
		ctx->position = 0;
	}

	pad[ctx->position] = 128;
	++ctx->position;

	/* padding */
	if (ctx->position < SHA2_256_RATE)
	{
		utils_memory_clear((pad + ctx->position), SHA2_256_RATE - ctx->position);
	}

	if (ctx->position > 56)
	{
		sha256_permute(ctx->state, pad);
		utils_memory_clear(pad, SHA2_256_RATE);
	}

	/* finalize state with counter and last compression */
	utils_integer_be32to8((pad + 56), (uint32_t)(bitLen >> 32));
	utils_integer_be32to8((pad + 60), (uint32_t)bitLen);
	sha256_permute(ctx->state, pad);

#if defined(SYSTEM_IS_BIG_ENDIAN)
	utils_memory_copy(output, (uint8_t*)ctx->state, SHA2_256_HASH_SIZE);
#else
	for (size_t i = 0; i < SHA2_256_HASH_SIZE; i += sizeof(uint32_t))
	{
		utils_integer_be32to8((output + i), ctx->state[i / sizeof(uint32_t)]);
	}
#endif

	sha256_dispose(ctx);
}

void sha256_initialize(sha256_state* ctx)
{
	assert(ctx != NULL);

	utils_memory_copy((uint8_t*)ctx->state, (const uint8_t*)sha256_iv, sizeof(ctx->state));
	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->t = 0;
	ctx->position = 0;
}

void sha256_permute(uint32_t* output, const uint8_t* message)
{
	assert(output != NULL);
	assert(message != NULL);

	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;
	uint32_t r;
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;
	uint32_t w4;
	uint32_t w5;
	uint32_t w6;
	uint32_t w7;
	uint32_t w8;
	uint32_t w9;
	uint32_t w10;
	uint32_t w11;
	uint32_t w12;
	uint32_t w13;
	uint32_t w14;
	uint32_t w15;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];
	e = output[4];
	f = output[5];
	g = output[6];
	h = output[7];

	w0 = utils_integer_be8to32(message);
	w1 = utils_integer_be8to32(message + 4);
	w2 = utils_integer_be8to32(message + 8);
	w3 = utils_integer_be8to32(message + 12);
	w4 = utils_integer_be8to32(message + 16);
	w5 = utils_integer_be8to32(message + 20);
	w6 = utils_integer_be8to32(message + 24);
	w7 = utils_integer_be8to32(message + 28);
	w8 = utils_integer_be8to32(message + 32);
	w9 = utils_integer_be8to32(message + 36);
	w10 = utils_integer_be8to32(message + 40);
	w11 = utils_integer_be8to32(message + 44);
	w12 = utils_integer_be8to32(message + 48);
	w13 = utils_integer_be8to32(message + 52);
	w14 = utils_integer_be8to32(message + 56);
	w15 = utils_integer_be8to32(message + 60);

	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0x428a2f98UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0x71374491UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0xb5c0fbcfUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0xe9b5dba5UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x3956c25bUL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x59f111f1UL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x923f82a4UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0xab1c5ed5UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0xd807aa98UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0x12835b01UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0x243185beUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0x550c7dc3UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0x72be5d74UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0x80deb1feUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0x9bdc06a7UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0xc19bf174UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	w0 += (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)) + w9 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0xe49b69c1UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w1 += (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)) + w10 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0xefbe4786UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w2 += (((w0 >> 17) | (w0 << 15)) ^ ((w0 >> 19) | (w0 << 13)) ^ (w0 >> 10)) + w11 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0x0fc19dc6UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w3 += (((w1 >> 17) | (w1 << 15)) ^ ((w1 >> 19) | (w1 << 13)) ^ (w1 >> 10)) + w12 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0x240ca1ccUL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w4 += (((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)) + w13 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x2de92c6fUL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w5 += (((w3 >> 17) | (w3 << 15)) ^ ((w3 >> 19) | (w3 << 13)) ^ (w3 >> 10)) + w14 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x4a7484aaUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w6 += (((w4 >> 17) | (w4 << 15)) ^ ((w4 >> 19) | (w4 << 13)) ^ (w4 >> 10)) + w15 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x5cb0a9dcUL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w7 += (((w5 >> 17) | (w5 << 15)) ^ ((w5 >> 19) | (w5 << 13)) ^ (w5 >> 10)) + w0 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0x76f988daUL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	w8 += (((w6 >> 17) | (w6 << 15)) ^ ((w6 >> 19) | (w6 << 13)) ^ (w6 >> 10)) + w1 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0x983e5152UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w9 += (((w7 >> 17) | (w7 << 15)) ^ ((w7 >> 19) | (w7 << 13)) ^ (w7 >> 10)) + w2 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0xa831c66dUL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w10 += (((w8 >> 17) | (w8 << 15)) ^ ((w8 >> 19) | (w8 << 13)) ^ (w8 >> 10)) + w3 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0xb00327c8UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w11 += (((w9 >> 17) | (w9 << 15)) ^ ((w9 >> 19) | (w9 << 13)) ^ (w9 >> 10)) + w4 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0xbf597fc7UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w12 += (((w10 >> 17) | (w10 << 15)) ^ ((w10 >> 19) | (w10 << 13)) ^ (w10 >> 10)) + w5 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0xc6e00bf3UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w13 += (((w11 >> 17) | (w11 << 15)) ^ ((w11 >> 19) | (w11 << 13)) ^ (w11 >> 10)) + w6 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0xd5a79147UL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w14 += (((w12 >> 17) | (w12 << 15)) ^ ((w12 >> 19) | (w12 << 13)) ^ (w12 >> 10)) + w7 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0x06ca6351UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w15 += (((w13 >> 17) | (w13 << 15)) ^ ((w13 >> 19) | (w13 << 13)) ^ (w13 >> 10)) + w8 + (((w0 >> 7) | (w0 << 25)) ^ ((w0 >> 18) | (w0 << 14)) ^ (w0 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0x14292967UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	w0 += (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)) + w9 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0x27b70a85UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w1 += (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)) + w10 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0x2e1b2138UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w2 += (((w0 >> 17) | (w0 << 15)) ^ ((w0 >> 19) | (w0 << 13)) ^ (w0 >> 10)) + w11 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0x4d2c6dfcUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w3 += (((w1 >> 17) | (w1 << 15)) ^ ((w1 >> 19) | (w1 << 13)) ^ (w1 >> 10)) + w12 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0x53380d13UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w4 += (((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)) + w13 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x650a7354UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w5 += (((w3 >> 17) | (w3 << 15)) ^ ((w3 >> 19) | (w3 << 13)) ^ (w3 >> 10)) + w14 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x766a0abbUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w6 += (((w4 >> 17) | (w4 << 15)) ^ ((w4 >> 19) | (w4 << 13)) ^ (w4 >> 10)) + w15 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x81c2c92eUL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w7 += (((w5 >> 17) | (w5 << 15)) ^ ((w5 >> 19) | (w5 << 13)) ^ (w5 >> 10)) + w0 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0x92722c85UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	w8 += (((w6 >> 17) | (w6 << 15)) ^ ((w6 >> 19) | (w6 << 13)) ^ (w6 >> 10)) + w1 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0xa2bfe8a1UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w9 += (((w7 >> 17) | (w7 << 15)) ^ ((w7 >> 19) | (w7 << 13)) ^ (w7 >> 10)) + w2 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0xa81a664bUL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w10 += (((w8 >> 17) | (w8 << 15)) ^ ((w8 >> 19) | (w8 << 13)) ^ (w8 >> 10)) + w3 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0xc24b8b70UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w11 += (((w9 >> 17) | (w9 << 15)) ^ ((w9 >> 19) | (w9 << 13)) ^ (w9 >> 10)) + w4 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0xc76c51a3UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w12 += (((w10 >> 17) | (w10 << 15)) ^ ((w10 >> 19) | (w10 << 13)) ^ (w10 >> 10)) + w5 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0xd192e819UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w13 += (((w11 >> 17) | (w11 << 15)) ^ ((w11 >> 19) | (w11 << 13)) ^ (w11 >> 10)) + w6 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0xd6990624UL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w14 += (((w12 >> 17) | (w12 << 15)) ^ ((w12 >> 19) | (w12 << 13)) ^ (w12 >> 10)) + w7 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0xf40e3585UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w15 += (((w13 >> 17) | (w13 << 15)) ^ ((w13 >> 19) | (w13 << 13)) ^ (w13 >> 10)) + w8 + (((w0 >> 7) | (w0 << 25)) ^ ((w0 >> 18) | (w0 << 14)) ^ (w0 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0x106aa070UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	w0 += (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)) + w9 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0x19a4c116UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w1 += (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)) + w10 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0x1e376c08UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w2 += (((w0 >> 17) | (w0 << 15)) ^ ((w0 >> 19) | (w0 << 13)) ^ (w0 >> 10)) + w11 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0x2748774cUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w3 += (((w1 >> 17) | (w1 << 15)) ^ ((w1 >> 19) | (w1 << 13)) ^ (w1 >> 10)) + w12 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0x34b0bcb5UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w4 += (((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)) + w13 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x391c0cb3UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w5 += (((w3 >> 17) | (w3 << 15)) ^ ((w3 >> 19) | (w3 << 13)) ^ (w3 >> 10)) + w14 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x4ed8aa4aUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w6 += (((w4 >> 17) | (w4 << 15)) ^ ((w4 >> 19) | (w4 << 13)) ^ (w4 >> 10)) + w15 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x5b9cca4fUL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w7 += (((w5 >> 17) | (w5 << 15)) ^ ((w5 >> 19) | (w5 << 13)) ^ (w5 >> 10)) + w0 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0x682e6ff3UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	w8 += (((w6 >> 17) | (w6 << 15)) ^ ((w6 >> 19) | (w6 << 13)) ^ (w6 >> 10)) + w1 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0x748f82eeUL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w9 += (((w7 >> 17) | (w7 << 15)) ^ ((w7 >> 19) | (w7 << 13)) ^ (w7 >> 10)) + w2 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0x78a5636fUL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w10 += (((w8 >> 17) | (w8 << 15)) ^ ((w8 >> 19) | (w8 << 13)) ^ (w8 >> 10)) + w3 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0x84c87814UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w11 += (((w9 >> 17) | (w9 << 15)) ^ ((w9 >> 19) | (w9 << 13)) ^ (w9 >> 10)) + w4 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0x8cc70208UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w12 += (((w10 >> 17) | (w10 << 15)) ^ ((w10 >> 19) | (w10 << 13)) ^ (w10 >> 10)) + w5 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0x90befffaUL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w13 += (((w11 >> 17) | (w11 << 15)) ^ ((w11 >> 19) | (w11 << 13)) ^ (w11 >> 10)) + w6 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0xa4506cebUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w14 += (((w12 >> 17) | (w12 << 15)) ^ ((w12 >> 19) | (w12 << 13)) ^ (w12 >> 10)) + w7 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0xbef9a3f7UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w15 += (((w13 >> 17) | (w13 << 15)) ^ ((w13 >> 19) | (w13 << 13)) ^ (w13 >> 10)) + w8 + (((w0 >> 7) | (w0 << 25)) ^ ((w0 >> 18) | (w0 << 14)) ^ (w0 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0xc67178f2UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
	output[4] += e;
	output[5] += f;
	output[6] += g;
	output[7] += h;
}

void sha256_update(sha256_state* ctx, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= SHA2_256_RATE))
		{
			const size_t RMDLEN = SHA2_256_RATE - ctx->position;

			if (RMDLEN != 0)
			{
				utils_memory_copy((ctx->buffer + ctx->position), message, RMDLEN);
			}

			sha256_permute(ctx->state, ctx->buffer);
			sha256_increase(ctx, SHA2_256_RATE);
			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= SHA2_256_RATE)
		{
			sha256_permute(ctx->state, message);
			sha256_increase(ctx, SHA2_256_RATE);
			message += SHA2_256_RATE;
			msglen -= SHA2_256_RATE;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			utils_memory_copy((ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

/* SHA2-512 */

static const uint64_t sha512_iv[8] =
{
	0x6A09E667F3BCC908ULL,
	0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL,
	0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL,
	0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL,
	0x5BE0CD19137E2179ULL
};

static void sha512_increase(sha512_state* ctx, size_t length)
{
	ctx->t[0] += length;

	if (ctx->t[0] > 0x1FFFFFFFFFFFFFFFULL)
	{
		ctx->t[1] += (ctx->t[0] >> 61);
		ctx->t[0] &= 0x1FFFFFFFFFFFFFFFULL;
	}
}

void sha512_compute(uint8_t* output, const uint8_t* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);

	sha512_state ctx;

	sha512_initialize(&ctx);
	sha512_update(&ctx, message, msglen);
	sha512_finalize(&ctx, output);
}

SYSTEM_OPTIMIZE_IGNORE
void sha512_dispose(sha512_state* ctx)
{
	assert(ctx != NULL);
	
	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->t[0] = 0;
		ctx->t[1] = 0;
		ctx->position = 0;
	}
}
SYSTEM_OPTIMIZE_RESUME

void sha512_finalize(sha512_state* ctx, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint8_t pad[SHA2_512_RATE] = { 0 };
	uint64_t bitLen;

	sha512_increase(ctx, ctx->position);
	bitLen = (ctx->t[0] << 3);
	utils_memory_copy(pad, ctx->buffer, ctx->position);

	if (ctx->position == SHA2_512_RATE)
	{
		sha512_permute(ctx->state, pad);
		ctx->position = 0;
	}

	pad[ctx->position] = 128;
	++ctx->position;

	/* padding */
	if (ctx->position < SHA2_512_RATE)
	{
		utils_memory_clear((pad + ctx->position), SHA2_512_RATE - ctx->position);
	}

	if (ctx->position > 112)
	{
		sha512_permute(ctx->state, pad);
		utils_memory_clear(pad, SHA2_512_RATE);
	}

	/* finalize state with counter and last compression */
	utils_integer_be64to8((pad + 112), ctx->t[1]);
	utils_integer_be64to8((pad + 120), bitLen);
	sha512_permute(ctx->state, pad);

#if defined(SYSTEM_IS_BIG_ENDIAN)
	utils_memory_copy(output, (uint8_t*)ctx->state, SHA2_512_HASH_SIZE);
#else
	for (size_t i = 0; i < SHA2_512_HASH_SIZE; i += 8)
	{
		utils_integer_be64to8((output + i), ctx->state[i / 8]);
	}
#endif

	sha512_dispose(ctx);
}

void sha512_initialize(sha512_state* ctx)
{
	assert(ctx != NULL);

	utils_memory_copy((uint8_t*)ctx->state, sha512_iv, sizeof(ctx->state));
	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->t[0] = 0;
	ctx->t[1] = 0;
	ctx->position = 0;
}

void sha512_permute(uint64_t* output, const uint8_t* message)
{
	assert(output != NULL);
	assert(message != NULL);

	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;
	uint64_t r;
	uint64_t w0;
	uint64_t w1;
	uint64_t w2;
	uint64_t w3;
	uint64_t w4;
	uint64_t w5;
	uint64_t w6;
	uint64_t w7;
	uint64_t w8;
	uint64_t w9;
	uint64_t w10;
	uint64_t w11;
	uint64_t w12;
	uint64_t w13;
	uint64_t w14;
	uint64_t w15;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];
	e = output[4];
	f = output[5];
	g = output[6];
	h = output[7];

	w0 = utils_integer_be8to64(message);
	w1 = utils_integer_be8to64(message + 8);
	w2 = utils_integer_be8to64(message + 16);
	w3 = utils_integer_be8to64(message + 24);
	w4 = utils_integer_be8to64(message + 32);
	w5 = utils_integer_be8to64(message + 40);
	w6 = utils_integer_be8to64(message + 48);
	w7 = utils_integer_be8to64(message + 56);
	w8 = utils_integer_be8to64(message + 64);
	w9 = utils_integer_be8to64(message + 72);
	w10 = utils_integer_be8to64(message + 80);
	w11 = utils_integer_be8to64(message + 88);
	w12 = utils_integer_be8to64(message + 96);
	w13 = utils_integer_be8to64(message + 104);
	w14 = utils_integer_be8to64(message + 112);
	w15 = utils_integer_be8to64(message + 120);

	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x428a2f98d728ae22ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x7137449123ef65cdULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0xb5c0fbcfec4d3b2fULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0xe9b5dba58189dbbcULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x3956c25bf348b538ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x59f111f1b605d019ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x923f82a4af194f9bULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0xab1c5ed5da6d8118ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0xd807aa98a3030242ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x12835b0145706fbeULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x243185be4ee4b28cULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x550c7dc3d5ffb4e2ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x72be5d74f27b896fULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0x80deb1fe3b1696b1ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x9bdc06a725c71235ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0xc19bf174cf692694ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0xe49b69c19ef14ad2ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0xefbe4786384f25e3ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x0fc19dc68b8cd5b5ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x240ca1cc77ac9c65ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x2de92c6f592b0275ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x4a7484aa6ea6e483ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x5cb0a9dcbd41fbd4ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x76f988da831153b5ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x983e5152ee66dfabULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0xa831c66d2db43210ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0xb00327c898fb213fULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0xbf597fc7beef0ee4ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0xc6e00bf33da88fc2ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xd5a79147930aa725ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x06ca6351e003826fULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x142929670a0e6e70ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x27b70a8546d22ffcULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x2e1b21385c26c926ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x4d2c6dfc5ac42aedULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x53380d139d95b3dfULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x650a73548baf63deULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x766a0abb3c77b2a8ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x81c2c92e47edaee6ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x92722c851482353bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0xa2bfe8a14cf10364ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0xa81a664bbc423001ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0xc24b8b70d0f89791ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0xc76c51a30654be30ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0xd192e819d6ef5218ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xd69906245565a910ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0xf40e35855771202aULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x106aa07032bbd1b8ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x19a4c116b8d2d0c8ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x1e376c085141ab53ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x2748774cdf8eeb99ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x34b0bcb5e19b48a8ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x391c0cb3c5c95a63ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x4ed8aa4ae3418acbULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x5b9cca4f7763e373ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x682e6ff3d6b2b8a3ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x748f82ee5defb2fcULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x78a5636f43172f60ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x84c87814a1f0ab72ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x8cc702081a6439ecULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x90befffa23631e28ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xa4506cebde82bde9ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0xbef9a3f7b2c67915ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0xc67178f2e372532bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0xca273eceea26619cULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0xd186b8c721c0c207ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0xeada7dd6cde0eb1eULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0xf57d4f7fee6ed178ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x06f067aa72176fbaULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x0a637dc5a2c898a6ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x113f9804bef90daeULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x1b710b35131c471bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x28db77f523047d84ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x32caab7b40c72493ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x3c9ebe0a15c9bebcULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x431d67c49c100d4cULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x4cc5d4becb3e42b6ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0x597f299cfc657e2aULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x5fcb6fab3ad6faecULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x6c44198c4a475817ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
	output[4] += e;
	output[5] += f;
	output[6] += g;
	output[7] += h;
}

void sha512_update(sha512_state* ctx, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= SHA2_512_RATE))
		{
			const size_t RMDLEN = SHA2_512_RATE - ctx->position;

			if (RMDLEN != 0)
			{
				utils_memory_copy((ctx->buffer + ctx->position), message, RMDLEN);
			}

			sha512_permute(ctx->state, ctx->buffer);
			sha512_increase(ctx, SHA2_512_RATE);
			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= SHA2_512_RATE)
		{
			sha512_permute(ctx->state, message);
			sha512_increase(ctx, SHA2_512_RATE);
			message += SHA2_512_RATE;
			msglen -= SHA2_512_RATE;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			utils_memory_copy((ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

/* HMAC-256 */

void hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	hmac256_state ctx;

	hmac256_initialize(&ctx, key, keylen);
	hmac256_update(&ctx, message, msglen);
	hmac256_finalize(&ctx, output);
}

SYSTEM_OPTIMIZE_IGNORE
void hmac256_dispose(hmac256_state* ctx)
{
	assert(ctx != NULL);
	
	if (ctx != NULL)
	{
		utils_memory_clear(ctx->ipad, sizeof(ctx->ipad));
		utils_memory_clear(ctx->opad, sizeof(ctx->ipad));
		sha256_dispose(&ctx->pstate);
	}
}
SYSTEM_OPTIMIZE_RESUME

void hmac256_finalize(hmac256_state* ctx, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint8_t tmpv[SHA2_256_HASH_SIZE] = { 0 };

	sha256_finalize(&ctx->pstate, tmpv);
	sha256_initialize(&ctx->pstate);
	sha256_update(&ctx->pstate, ctx->opad, sizeof(ctx->opad));
	sha256_update(&ctx->pstate, tmpv, sizeof(tmpv));
	sha256_finalize(&ctx->pstate, output);
	hmac256_dispose(ctx);
}

void hmac256_initialize(hmac256_state* ctx, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	const uint8_t IPAD = 0x36;
	const uint8_t OPAD = 0x5C;

	utils_memory_clear(ctx->ipad, SHA2_256_RATE);

	if (keylen > SHA2_256_RATE)
	{
		sha256_initialize(&ctx->pstate);
		sha256_update(&ctx->pstate, key, keylen);
		sha256_finalize(&ctx->pstate, ctx->ipad);
	}
	else
	{
		utils_memory_copy(ctx->ipad, key, keylen);
	}

	utils_memory_copy(ctx->opad, ctx->ipad, SHA2_256_RATE);
	utils_memory_xorv(ctx->opad, OPAD, SHA2_256_RATE);
	utils_memory_xorv(ctx->ipad, IPAD, SHA2_256_RATE);

	sha256_initialize(&ctx->pstate);
	sha256_update(&ctx->pstate, ctx->ipad, sizeof(ctx->ipad));
}

void hmac256_update(hmac256_state* ctx, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	sha256_update(&ctx->pstate, message, msglen);
}

/* HMAC-512 */

void hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	hmac512_state ctx;

	hmac512_initialize(&ctx, key, keylen);
	hmac512_update(&ctx, message, msglen);
	hmac512_finalize(&ctx, output);
}

SYSTEM_OPTIMIZE_IGNORE
void hmac512_dispose(hmac512_state* ctx)
{
	assert(ctx != NULL);
	
	if (ctx != NULL)
	{
		utils_memory_clear(ctx->ipad, sizeof(ctx->ipad));
		utils_memory_clear(ctx->opad, sizeof(ctx->ipad));
		sha512_dispose(&ctx->pstate);
	}
}
SYSTEM_OPTIMIZE_RESUME

void hmac512_finalize(hmac512_state* ctx, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint8_t tmpv[SHA2_512_HASH_SIZE] = { 0 };

	sha512_finalize(&ctx->pstate, tmpv);
	sha512_initialize(&ctx->pstate);
	sha512_update(&ctx->pstate, ctx->opad, sizeof(ctx->opad));
	sha512_update(&ctx->pstate, tmpv, sizeof(tmpv));
	sha512_finalize(&ctx->pstate, output);
	hmac512_dispose(ctx);
}

void hmac512_initialize(hmac512_state* ctx, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	const uint8_t IPAD = 0x36;
	const uint8_t OPAD = 0x5C;

	utils_memory_clear(ctx->ipad, SHA2_512_RATE);

	if (keylen > SHA2_512_RATE)
	{
		sha512_initialize(&ctx->pstate);
		sha512_update(&ctx->pstate, key, keylen);
		sha512_finalize(&ctx->pstate, ctx->ipad);
	}
	else
	{
		utils_memory_copy(ctx->ipad, key, keylen);
	}

	utils_memory_copy(ctx->opad, ctx->ipad, SHA2_512_RATE);
	utils_memory_xorv(ctx->opad, OPAD, SHA2_512_RATE);
	utils_memory_xorv(ctx->ipad, IPAD, SHA2_512_RATE);

	sha512_initialize(&ctx->pstate);
	sha512_update(&ctx->pstate, ctx->ipad, sizeof(ctx->ipad));
}

void hmac512_update(hmac512_state* ctx, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	sha512_update(&ctx->pstate, message, msglen);
}

/* HKDF-256 */

void hkdf256_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen)
{
	assert(output != NULL);
	assert(key != NULL);

	hmac256_state ctx;
	uint8_t buf[SHA2_256_HASH_SIZE] = { 0 };
	uint8_t ctr[1] = { 0 };

	while (outlen != 0)
	{
		hmac256_initialize(&ctx, key, keylen);

		if (ctr[0] != 0)
		{
			hmac256_update(&ctx, buf, sizeof(buf));
		}

		if (infolen != 0)
		{
			hmac256_update(&ctx, info, infolen);
		}

		++ctr[0];
		hmac256_update(&ctx, ctr, sizeof(ctr));
		hmac256_finalize(&ctx, buf);

		const size_t RMDLEN = utils_integer_min(outlen, (size_t)SHA2_256_HASH_SIZE);
		utils_memory_copy(output, buf, RMDLEN);

		outlen -= RMDLEN;
		output += RMDLEN;
	}
}

void hkdf256_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen)
{
	assert(output != NULL);
	assert(key != NULL);

	if (outlen >= 32)
    {
        hmac256_state ctx;

        if (saltlen != 0)
        {
            hmac256_initialize(&ctx, salt, saltlen);
        }
        else
        {
            uint8_t tmp[HMAC_256_MAC_SIZE] = { 0 };
            hmac256_initialize(&ctx, tmp, sizeof(tmp));
        }

        hmac256_update(&ctx, key, keylen);
        hmac256_finalize(&ctx, output);
    }
}

/* HKDF-512 */

void hkdf512_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen)
{
	assert(output != NULL);
	assert(key != NULL);

	hmac512_state ctx;
	uint8_t buf[SHA2_512_HASH_SIZE] = { 0 };
	uint8_t ctr[1] = { 0 };

	while (outlen != 0)
	{
		hmac512_initialize(&ctx, key, keylen);

		if (ctr[0] != 0)
		{
			hmac512_update(&ctx, buf, sizeof(buf));
		}

		if (infolen != 0)
		{
			hmac512_update(&ctx, info, infolen);
		}

		++ctr[0];
		hmac512_update(&ctx, ctr, sizeof(ctr));
		hmac512_finalize(&ctx, buf);

		const size_t RMDLEN = utils_integer_min(outlen, (size_t)SHA2_512_HASH_SIZE);
		utils_memory_copy(output, buf, RMDLEN);

		outlen -= RMDLEN;
		output += RMDLEN;
	}
}

void hkdf512_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen)
{
	assert(output != NULL);
	assert(key != NULL);

    if (outlen >= 64)
    {
        hmac512_state ctx;

        if (saltlen != 0)
        {
            hmac512_initialize(&ctx, salt, saltlen);
        }
        else
        {
            uint8_t tmp[HMAC_512_MAC_SIZE] = { 0 };
            hmac512_initialize(&ctx, tmp, sizeof(tmp));
        }

        hmac512_update(&ctx, key, keylen);
        hmac512_finalize(&ctx, output);
    }
}

#include "cipher_speed.h"
#include "testutils.h"
#include "utils.h"
#include "rhx.h"

/* bs*sc = 1GB */
#define BUFFER_SIZE 1024
#define SAMPLE_COUNT 1024000
#define ONE_GIGABYTE 1024000000

static void aes128_cbc_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t olen;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, false, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	rhx_dispose(&state);
}

static void aes256_cbc_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t olen;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, false, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	rhx_dispose(&state);
}

static void rhx256_cbc_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t olen;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-256 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, false, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-256 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	rhx_dispose(&state);
}

static void rhx512_cbc_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t olen;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-512 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, false, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-512 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	rhx_dispose(&state);
}

static void aes128_ctrbe_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrbe_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes128_ctrle_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrbe_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrbe_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrle_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_ctrbe_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrbe_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-256 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_ctrle_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-256 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_ctrbe_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-512 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_ctrle_speed_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_initialize(&state, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-512 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_hba_speed_test()
{
	uint8_t enc[BUFFER_SIZE + RHX_HBA256_MAC_LENGTH] = { 0 };
	uint8_t key[RHX_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_hba256_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_hba256_initialize(&state, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_hba256_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-256 HBA Encryption processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_hba_speed_test()
{
	uint8_t enc[BUFFER_SIZE + RHX_HBA512_MAC_LENGTH] = { 0 };
	uint8_t key[RHX_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	rhx_hba512_state state;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	utils_seed_generate(key, sizeof(key));
	utils_seed_generate(iv, sizeof(iv));
	utils_seed_generate(msg, sizeof(msg));
	rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = utils_stopwatch_start();

	rhx_hba512_initialize(&state, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		rhx_hba512_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	qsctest_print_safe("RHX-512 HBA Encryption processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

void qsctest_aes_speed_run()
{
	qsctest_print_line("Running the AES-128 performance benchmarks.");
	aes128_cbc_speed_test();
	aes128_ctrbe_speed_test();
	aes128_ctrle_speed_test();

	qsctest_print_line("Running the AES-256 performance benchmarks.");
	aes256_cbc_speed_test();
	aes256_ctrbe_speed_test();
	aes256_ctrle_speed_test();
}

void qsctest_rhx_speed_run()
{
	qsctest_print_line("Running the RHX-256 performance benchmarks.");
	rhx256_cbc_speed_test();
	rhx256_ctrbe_speed_test();
	rhx256_ctrle_speed_test();
	rhx256_hba_speed_test();

	qsctest_print_line("Running the RHX-512 performance benchmarks.");
	rhx512_cbc_speed_test();
	rhx512_ctrbe_speed_test();
	rhx512_ctrle_speed_test();
	rhx512_hba_speed_test();
}
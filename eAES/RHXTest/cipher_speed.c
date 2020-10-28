#include "cipher_speed.h"
#include "testutils.h"
#include "timer.h"
#include "../RHX/csp.h"
#include "../RHX/rhx.h"

/* bs*sc = 1GB */
#define BUFFER_SIZE 1000
#define SAMPLE_COUNT 1000000
#define ONE_GIGABYTE 1000000000

static void aes128_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, false, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&state);
}

static void aes256_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, false, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&state);
}

static void rhx256_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, false, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&state);
}

static void rhx512_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, false, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&state, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&state);
}

static void aes128_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrbe_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes128_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrbe_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrbe_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&state, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_hba_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_hba256_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_hba256_initialize(&state, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_hba256_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 HBA Encryption processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_hba_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_hba512_state state;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_hba512_initialize(&state, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_hba512_transform(&state, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
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
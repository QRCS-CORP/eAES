#include "aesavs_test.h"
#include "filetools.h"
#include "intutils.h"
#include "rhx.h"
#include "testutils.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool aesavs_cbc128_kat(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES128_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	fp = NULL;
	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					rhx_state state;
					memcpy(ivc, iv, sizeof(iv));
					rhx_keyparams kp1 = { key, AES128_KEY_SIZE, ivc };
					rhx_initialize(&state, &kp1, true, AES128);
					rhx_cbc_encrypt_block(&state, otp, pln);
					rhx_dispose(&state);

					if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					memcpy(ivc, iv, sizeof(iv));
					rhx_keyparams kp2 = { key, AES128_KEY_SIZE, ivc };
					rhx_initialize(&state, &kp2, false, AES128);
					rhx_cbc_decrypt_block(&state, dec, otp);
					rhx_dispose(&state);

					if (are_equal8(pln, dec, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_cbc256_kat(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES256_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	fp = NULL;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					for (i = 0; i < 4; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					rhx_state state;
					memcpy(ivc, iv, sizeof(iv));
					rhx_keyparams kp1 = { key, AES256_KEY_SIZE, ivc };
					rhx_initialize(&state, &kp1, true, AES256);
					rhx_cbc_encrypt_block(&state, otp, pln);
					rhx_dispose(&state);

					if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					memcpy(ivc, iv, sizeof(iv));
					rhx_keyparams kp2 = { key, AES256_KEY_SIZE, ivc };
					rhx_initialize(&state, &kp2, false, AES256);
					rhx_cbc_decrypt_block(&state, dec, otp);
					rhx_dispose(&state);

					if (are_equal8(pln, dec, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_ecb128_kat(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES128_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	fp = NULL;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else
						{
							res = false;
							break;
						}
					}

					rhx_state state;
					rhx_keyparams kp = { key, AES128_KEY_SIZE };
					rhx_initialize(&state, &kp, true, AES128);
					rhx_ecb_encrypt_block(&state, otp, pln);
					rhx_dispose(&state);

					if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					rhx_initialize(&state, &kp, false, AES128);
					rhx_ecb_decrypt_block(&state, dec, otp);
					rhx_dispose(&state);

					if (are_equal8(pln, dec, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_ecb256_kat(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES256_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	fp = NULL;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else
						{
							res = false;
							break;
						}
					}

					rhx_state state;
					rhx_keyparams kp = { key, AES256_KEY_SIZE };
					rhx_initialize(&state, &kp, true, AES256);
					rhx_ecb_encrypt_block(&state, otp, pln);
					rhx_dispose(&state);

					if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					rhx_initialize(&state, &kp, false, AES256);
					rhx_ecb_decrypt_block(&state, dec, otp);
					rhx_dispose(&state);

					if (are_equal8(pln, dec, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_cbc128_mct(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES128_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	uint8_t plnc[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t count;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	count = 0;
	res = true;
	line = NULL;
	fp = NULL;
	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					if (count <= 100)
					{
						rhx_state state;
						memcpy(ivc, iv, sizeof(iv));
						memcpy(plnc, pln, RHX_BLOCK_SIZE);

						rhx_keyparams kp = { key, AES128_KEY_SIZE, ivc };
						rhx_initialize(&state, &kp, true, AES128);
						uint8_t otpc[RHX_BLOCK_SIZE] = { 0 };

						for (i = 0; i < 1000; ++i)
						{
							if (i != 0)
							{
								memcpy(otpc, otp, RHX_BLOCK_SIZE);
								rhx_cbc_encrypt_block(&state, otp, plnc);
								memcpy(plnc, otpc, RHX_BLOCK_SIZE);
							}
							else
							{
								rhx_cbc_encrypt_block(&state, otp, plnc);
								memcpy(plnc, iv, RHX_BLOCK_SIZE);
							}
						}

						rhx_dispose(&state);

						if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
						{
							res = false;
							break;
						}
					}
					else
					{
						// todo: need example
						break;
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_cbc256_mct(const char* filepath)
{
	FILE* fp;
	const char* CBC_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* CBC_KEY = "KEY = ";
	const char* CBC_PLAINTEXT = "PLAINTEXT = ";
	const char* CBC_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES256_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	uint8_t plnc[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t count;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	count = 0;
	res = true;
	line = NULL;
	fp = NULL;
	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, CBC_COUNT, strlen(CBC_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, CBC_KEY, strlen(CBC_KEY)) == 0)
						{
							hex_to_bin(line + strlen(CBC_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_PLAINTEXT, strlen(CBC_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, CBC_CIPHERTEXT, strlen(CBC_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(CBC_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else
						{
							res = false;
							break;
						}
					}

					if (count <= 100)
					{
						rhx_state state;
						memcpy(ivc, iv, sizeof(iv));
						memcpy(plnc, pln, RHX_BLOCK_SIZE);

						rhx_keyparams kp = { key, AES256_KEY_SIZE, ivc };
						rhx_initialize(&state, &kp, true, AES256);
						uint8_t otpc[RHX_BLOCK_SIZE] = { 0 };

						for (i = 0; i < 1000; ++i)
						{
							if (i != 0)
							{
								memcpy(otpc, otp, RHX_BLOCK_SIZE);
								rhx_cbc_encrypt_block(&state, otp, plnc);
								memcpy(plnc, otpc, RHX_BLOCK_SIZE);
							}
							else
							{
								rhx_cbc_encrypt_block(&state, otp, plnc);
								memcpy(plnc, iv, RHX_BLOCK_SIZE);
							}
						}

						rhx_dispose(&state);

						if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
						{
							res = false;
							break;
						}
					}
					else
					{
						// todo: need example
						break;
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_ecb128_mct(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES128_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	uint8_t plnc[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	fp = NULL;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else
						{
							res = false;
							break;
						}
					}

					rhx_state state;
					rhx_keyparams kp = { key, AES128_KEY_SIZE };
					rhx_initialize(&state, &kp, true, AES128);
					memcpy(plnc, pln, RHX_BLOCK_SIZE);

					for (i = 0; i < 1000; ++i)
					{
						rhx_ecb_encrypt_block(&state, otp, plnc);
						memcpy(plnc, otp, RHX_BLOCK_SIZE);
					}

					rhx_dispose(&state);

					if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					rhx_initialize(&state, &kp, false, AES128);

					for (i = 0; i < 1000; ++i)
					{
						rhx_ecb_decrypt_block(&state, dec, otp);
						memcpy(otp, dec, RHX_BLOCK_SIZE);
					}

					rhx_dispose(&state);

					if (are_equal8(pln, dec, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_ecb256_mct(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t cpt[RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES256_KEY_SIZE] = { 0 };
	uint8_t otp[RHX_BLOCK_SIZE] = { 0 };
	uint8_t pln[RHX_BLOCK_SIZE] = { 0 };
	uint8_t plnc[RHX_BLOCK_SIZE] = { 0 };
	int64_t read;
	size_t i;
	size_t len;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	fp = NULL;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &len, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = getline(&line, &len, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, sizeof(pln));
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, sizeof(cpt));
						}
						else
						{
							res = false;
							break;
						}
					}

					rhx_state state;
					rhx_keyparams kp = { key, AES256_KEY_SIZE };
					rhx_initialize(&state, &kp, true, AES256);
					memcpy(plnc, pln, RHX_BLOCK_SIZE);

					for (i = 0; i < 1000; ++i)
					{
						rhx_ecb_encrypt_block(&state, otp, plnc);
						memcpy(plnc, otp, RHX_BLOCK_SIZE);
					}

					rhx_dispose(&state);

					if (are_equal8(cpt, otp, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}

					rhx_initialize(&state, &kp, false, AES256);

					for (i = 0; i < 1000; ++i)
					{
						rhx_ecb_decrypt_block(&state, dec, otp);
						memcpy(otp, dec, RHX_BLOCK_SIZE);
					}

					rhx_dispose(&state);

					if (are_equal8(pln, dec, RHX_BLOCK_SIZE) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_cbc128_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* cpt;
	uint8_t* dec;
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES128_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t count;
	size_t i;
	size_t alen;
	size_t rlen;
	errno_t err;
	bool res;

	cpt = NULL;
	dec = NULL;
	otp = NULL;
	pln = NULL;
	line = NULL;
	fp = NULL;
	res = true;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		alen = 0;
		count = 0;
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &rlen, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = getline(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)malloc(alen);

							if (pln != NULL)
							{
								memset(pln, 0x00, alen);
								hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							cpt = (uint8_t*)malloc(alen);
							dec = (uint8_t*)malloc(alen);
							otp = (uint8_t*)malloc(alen);

							if (cpt != NULL && otp != NULL)
							{
								memset(cpt, 0x00, alen);
								memset(dec, 0x00, alen);
								memset(otp, 0x00, alen);
								hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, alen);
							}
							else
							{
								res = false;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (count <= 10)
					{
						if (pln != NULL && cpt != NULL && dec != NULL && otp != NULL)
						{
							rhx_state state;
							memcpy(ivc, iv, RHX_BLOCK_SIZE);
							rhx_keyparams kp = { key, AES128_KEY_SIZE, ivc };
							rhx_initialize(&state, &kp, true, AES128);

							for (i = 0; i < alen / RHX_BLOCK_SIZE; ++i)
							{
								rhx_cbc_encrypt_block(&state, otp + (i * RHX_BLOCK_SIZE), pln + (i * RHX_BLOCK_SIZE));
							}

							rhx_dispose(&state);

							if (are_equal8(cpt, otp, alen) == false)
							{
								res = false;
								break;
							}

							free(cpt);
							free(dec);
							free(pln);
							free(otp);
						}
					}
					else
					{
						if (pln != NULL && cpt != NULL && dec != NULL && otp != NULL)
						{
							rhx_state state;
							memcpy(ivc, iv, RHX_BLOCK_SIZE);
							rhx_keyparams kp = { key, AES128_KEY_SIZE, ivc };
							rhx_initialize(&state, &kp, false, AES128);

							for (i = 0; i < alen / RHX_BLOCK_SIZE; ++i)
							{
								rhx_cbc_decrypt_block(&state, dec + (i * RHX_BLOCK_SIZE), cpt + (i * RHX_BLOCK_SIZE));
							}

							rhx_dispose(&state);

							if (are_equal8(dec, pln, alen) == false)
							{
								res = false;
								break;
							}

							free(cpt);
							free(dec);
							free(pln);
							free(otp);
						}
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_cbc256_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* CBC_IV = "IV = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* cpt;
	uint8_t* dec;
	uint8_t iv[RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivc[RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[AES256_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t count;
	size_t i;
	size_t alen;
	size_t rlen;
	errno_t err;
	bool res;

	cpt = NULL;
	dec = NULL;
	otp = NULL;
	pln = NULL;
	line = NULL;
	fp = NULL;
	res = true;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		alen = 0;
		count = 0;
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &rlen, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					++count;

					for (i = 0; i < 4; ++i)
					{
						read = getline(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, CBC_IV, strlen(CBC_IV)) == 0)
						{
							hex_to_bin(line + strlen(CBC_IV), iv, sizeof(iv));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)malloc(alen);

							if (pln != NULL)
							{
								memset(pln, 0x00, alen);
								hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							cpt = (uint8_t*)malloc(alen);
							dec = (uint8_t*)malloc(alen);
							otp = (uint8_t*)malloc(alen);

							if (cpt != NULL && otp != NULL)
							{
								memset(cpt, 0x00, alen);
								memset(dec, 0x00, alen);
								memset(otp, 0x00, alen);
								hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, alen);
							}
							else
							{
								res = false;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (count <= 10)
					{
						if (pln != NULL && cpt != NULL && dec != NULL && otp != NULL)
						{
							rhx_state state;
							memcpy(ivc, iv, RHX_BLOCK_SIZE);
							rhx_keyparams kp = { key, AES256_KEY_SIZE, ivc };
							rhx_initialize(&state, &kp, true, AES256);

							for (i = 0; i < alen / RHX_BLOCK_SIZE; ++i)
							{
								rhx_cbc_encrypt_block(&state, otp + (i * RHX_BLOCK_SIZE), pln + (i * RHX_BLOCK_SIZE));
							}

							rhx_dispose(&state);

							if (are_equal8(cpt, otp, alen) == false)
							{
								res = false;
								break;
							}

							free(cpt);
							free(dec);
							free(pln);
							free(otp);
						}
					}
					else
					{
						if (pln != NULL && cpt != NULL && dec != NULL && otp != NULL)
						{
							rhx_state state;
							memcpy(ivc, iv, RHX_BLOCK_SIZE);
							rhx_keyparams kp = { key, AES256_KEY_SIZE, ivc };
							rhx_initialize(&state, &kp, false, AES256);

							for (i = 0; i < alen / RHX_BLOCK_SIZE; ++i)
							{
								rhx_cbc_decrypt_block(&state, dec + (i * RHX_BLOCK_SIZE), cpt + (i * RHX_BLOCK_SIZE));
							}

							rhx_dispose(&state);

							if (are_equal8(dec, pln, alen) == false)
							{
								res = false;
								break;
							}

							free(cpt);
							free(dec);
							free(pln);
							free(otp);
						}
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_ecb128_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* cpt;
	uint8_t key[AES128_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t i;
	size_t alen;
	size_t rlen;
	errno_t err;
	bool res;

	cpt = NULL;
	otp = NULL;
	pln = NULL;
	line = NULL;
	fp = NULL;
	res = true;
	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		alen = 0;
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &rlen, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = getline(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)malloc(alen);

							if (pln != NULL)
							{
								memset(pln, 0x00, alen);
								hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							cpt = (uint8_t*)malloc(alen);
							otp = (uint8_t*)malloc(alen);

							if (cpt != NULL && otp != NULL)
							{
								memset(cpt, 0x00, alen);
								memset(otp, 0x00, alen);

								hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, alen);
							}
							else
							{
								res = false;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (pln != NULL && cpt != NULL && otp != NULL)
					{
						rhx_state state;
						rhx_keyparams kp = { key, AES128_KEY_SIZE };
						rhx_initialize(&state, &kp, true, AES128);

						for (i = 0; i < alen / RHX_BLOCK_SIZE; ++i)
						{
							rhx_ecb_encrypt_block(&state, otp + (i * RHX_BLOCK_SIZE), pln + (i * RHX_BLOCK_SIZE));
						}

						rhx_dispose(&state);

						if (are_equal8(cpt, otp, alen) == false)
						{
							res = false;
							break;
						}

						free(cpt);
						free(pln);
						free(otp);
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

static bool aesavs_ecb256_mmt(const char* filepath)
{
	FILE* fp;
	const char* ECB_COUNT = "COUNT = ";
	const char* ECB_KEY = "KEY = ";
	const char* ECB_PLAINTEXT = "PLAINTEXT = ";
	const char* ECB_CIPHERTEXT = "CIPHERTEXT = ";
	char* line;
	uint8_t* cpt;
	uint8_t key[AES256_KEY_SIZE] = { 0 };
	uint8_t* otp;
	uint8_t* pln;
	int64_t read;
	size_t i;
	size_t alen;
	size_t rlen;
	errno_t err;
	bool res;

	cpt = NULL;
	otp = NULL;
	pln = NULL;
	line = NULL;
	fp = NULL;
	res = true;
	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		alen = 0;
		read = 0;

		while (read != -1)
		{
			read = getline(&line, &rlen, fp);

			if (read > 0)
			{
				if (memcmp(line, ECB_COUNT, strlen(ECB_COUNT)) == 0)
				{
					for (i = 0; i < 3; ++i)
					{
						read = getline(&line, &rlen, fp);

						if (memcmp(line, ECB_KEY, strlen(ECB_KEY)) == 0)
						{
							hex_to_bin(line + strlen(ECB_KEY), key, sizeof(key));
						}
						else if (memcmp(line, ECB_PLAINTEXT, strlen(ECB_PLAINTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_PLAINTEXT) + 1)) / 2;
							pln = (uint8_t*)malloc(alen);

							if (pln != NULL)
							{
								memset(pln, 0x00, alen);
								hex_to_bin(line + strlen(ECB_PLAINTEXT), pln, alen);
							}
							else
							{
								res = false;
							}
						}
						else if (memcmp(line, ECB_CIPHERTEXT, strlen(ECB_CIPHERTEXT)) == 0)
						{
							alen = ((size_t)read - (strlen(ECB_CIPHERTEXT) + 1)) / 2;
							cpt = (uint8_t*)malloc(alen);
							otp = (uint8_t*)malloc(alen);

							if (cpt != NULL && otp != NULL)
							{
								memset(cpt, 0x00, alen);
								memset(otp, 0x00, alen);

								hex_to_bin(line + strlen(ECB_CIPHERTEXT), cpt, alen);
							}
							else
							{
								res = false;
							}
						}
						else
						{
							res = false;
							break;
						}
					}

					if (res == false)
					{
						break;
					}

					if (pln != NULL && cpt != NULL && otp != NULL)
					{
						rhx_state state;
						rhx_keyparams kp = { key, AES256_KEY_SIZE };
						rhx_initialize(&state, &kp, true, AES256);

						for (i = 0; i < alen / RHX_BLOCK_SIZE; ++i)
						{
							rhx_ecb_encrypt_block(&state, otp + (i * RHX_BLOCK_SIZE), pln + (i * RHX_BLOCK_SIZE));
						}

						rhx_dispose(&state);

						if (are_equal8(cpt, otp, alen) == false)
						{
							res = false;
							break;
						}

						free(cpt);
						free(pln);
						free(otp);
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	if (fp != NULL)
	{
		fclose(fp);
	}

#if defined(QSC_COMPILER_MSC)
	if (line != NULL)
	{
		free(line);
	}
#endif

	return res;
}

bool aesavs_cbc_kat()
{
	const char* CBC128_VARKEY = "AESAVS/CBC/KAT/CBCVarKey128.rsp";
	const char* CBC128_VARTXT = "AESAVS/CBC/KAT/CBCVarTxt128.rsp";
	const char* CBC256_VARKEY = "AESAVS/CBC/KAT/CBCVarKey256.rsp";
	const char* CBC256_VARTXT = "AESAVS/CBC/KAT/CBCVarTxt256.rsp";
	bool res;

	if (file_exists(CBC128_VARKEY) && file_exists(CBC128_VARTXT) && file_exists(CBC256_VARKEY) && file_exists(CBC256_VARTXT) == true)
	{
		res = true;

		if (aesavs_cbc128_kat(CBC128_VARKEY) == false)
		{
			printf_s("AESAVS failed CBC(AES-128) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_cbc128_kat(CBC128_VARTXT) == false)
		{
			printf_s("AESAVS failed CBC(AES-128) variable text KAT test. \n");
			res = false;
		}

		if (aesavs_cbc256_kat(CBC256_VARKEY) == false)
		{
			printf_s("AESAVS failed CBC(AES-256) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_cbc256_kat(CBC256_VARTXT) == false)
		{
			printf_s("AESAVS failed CBC(AES-256) variable text KAT test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_ecb_kat()
{
	const char* ECB128_VARKEY = "AESAVS/ECB/KAT/ECBVarKey128.rsp";
	const char* ECB128_VARTXT = "AESAVS/ECB/KAT/ECBVarTxt128.rsp";
	const char* ECB256_VARKEY = "AESAVS/ECB/KAT/ECBVarKey256.rsp";
	const char* ECB256_VARTXT = "AESAVS/ECB/KAT/ECBVarTxt256.rsp";
	bool res;

	if (file_exists(ECB128_VARKEY) && file_exists(ECB128_VARTXT) && file_exists(ECB256_VARKEY) && file_exists(ECB256_VARTXT) == true)
	{
		res = true;

		if (aesavs_ecb128_kat(ECB128_VARKEY) == false)
		{
			printf_s("AESAVS failed ECB(AES-128) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_ecb128_kat(ECB128_VARTXT) == false)
		{
			printf_s("AESAVS failed ECB(AES-128) variable text KAT test. \n");
			res = false;
		}

		if (aesavs_ecb256_kat(ECB256_VARKEY) == false)
		{
			printf_s("AESAVS failed ECB(AES-256) variable key KAT test. \n");
			res = false;
		}

		if (aesavs_ecb256_kat(ECB256_VARTXT) == false)
		{
			printf_s("AESAVS failed ECB(AES-256) variable text KAT test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_cbc_mct()
{
	const char* CBC128_MCT = "AESAVS/CBC/MCT/CBCMCT128.rsp";
	const char* CBC256_MCT = "AESAVS/CBC/MCT/CBCMCT256.rsp";
	bool res;

	if (file_exists(CBC128_MCT) && file_exists(CBC256_MCT) == true)
	{
		res = true;

		if (aesavs_cbc128_mct(CBC128_MCT) == false)
		{
			printf_s("AESAVS failed CBC(AES-128) monte carlo test. \n");
			res = false;
		}

		if (aesavs_cbc256_mct(CBC256_MCT) == false)
		{
			printf_s("AESAVS failed CBC(AES-256) monte carlo test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_ecb_mct()
{
	const char* ECB128_MCT = "AESAVS/ECB/MCT/ECBMCT128.rsp";
	const char* ECB256_MCT = "AESAVS/ECB/MCT/ECBMCT256.rsp";
	bool res;

	if (file_exists(ECB128_MCT) && file_exists(ECB256_MCT) == true)
	{
		res = true;

		if (aesavs_ecb128_mct(ECB128_MCT) == false)
		{
			printf_s("AESAVS failed ECB(AES-128) monte carlo test. \n");
			res = false;
		}

		if (aesavs_ecb256_mct(ECB256_MCT) == false)
		{
			printf_s("AESAVS failed ECB(AES-256) monte carlo test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_cbc_mmt()
{
	const char* CBC128_MMT = "AESAVS/CBC/MMT/CBCMMT128.rsp";
	const char* CBC256_MMT = "AESAVS/CBC/MMT/CBCMMT256.rsp";
	bool res;

	if (file_exists(CBC128_MMT) && file_exists(CBC256_MMT) == true)
	{
		res = true;

		if (aesavs_cbc128_mmt(CBC128_MMT) == false)
		{
			printf_s("AESAVS failed CBC(AES-128) multi-block message test. \n");
			res = false;
		}

		if (aesavs_cbc256_mmt(CBC256_MMT) == false)
		{
			printf_s("AESAVS failed CBC(AES-256) multi-block message test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

bool aesavs_ecb_mmt()
{
	const char* ECB128_MMT = "AESAVS/ECB/MMT/ECBMMT128.rsp";
	const char* ECB256_MMT = "AESAVS/ECB/MMT/ECBMMT256.rsp";
	bool res;

	if (file_exists(ECB128_MMT) && file_exists(ECB256_MMT) == true)
	{
		res = true;

		if (aesavs_ecb128_mmt(ECB128_MMT) == false)
		{
			printf_s("AESAVS failed ECB(AES-128) multi-block message test. \n");
			res = false;
		}

		if (aesavs_ecb256_mmt(ECB256_MMT) == false)
		{
			printf_s("AESAVS failed ECB(AES-256) multi-block message test. \n");
			res = false;
		}
	}
	else
	{
		res = false;
	}

	return res;
}

/* The GPL version 3 License (GPLv3)
* 
* Copyright (c) 2019 vtdev.com
* This file is part of the CEX Cryptographic library.
* 
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
* 
*
* Implementation Details:
* An implementation of the Rijndael Hash eXtension (RHX/RSX=eAES) symmetric block cipher.
* Written by John G. Underhill
* Updated on December 18, 2019
* Contact: develop@vtdev.com */

/*!
* \mainpage <b>The RHX cipher</b>
* \section intro_sec Welcome
* <p>The RHX (Rijndael Hash eXtension) cipher, is a hybrid of Rijndael (AES) and a cryptographically strong pseudo-random generator function.
* The cryptographic PRNG, is used to generate the round keys for the Rijndael rounds function, enabling the safe addition of increased mixing rounds, 
* and replacing the differentially-weak native Rijndael key-schedule expansion function. \n
* The cipher also increases the number of mixing rounds from 14 used by AES-256, to 22 used by RHX-256, twice the best known classical computer attack.
* The cipher also has a 512-bit key configuration, which uses 30 rounds of mixing. 
* There are attacks now being proposed, that strongly indicate this larger key sizes will be necessary, against future quantum-based attacks on symmetric ciphers.</p>
* 
* <p>The default extension used by this cipher is the Keccak cSHAKE extended output function (XOF).
* The fallback generator is HKDF(HMAC(SHA2)) Expand.
* Both genertors are implemented in 256 and 512-bit forms of those functions, and implemented correlating to the input cipher-key size.
* The cipher code names are based on which generator is used; RHX for Rijndael HKDF eXtension, and RSX for Rijndael SHAKE eXtension, 
* with the ciphers formal name now being 'eAES', or extended AES.
* The cipher has four modes, AES128 and AES256, which are the standard AES configurations, and the two extended modes, RSX/RHX-256 and RSX/RHX-512.
* In extended mode, the key schedules round-key expansion function has been replaced by cSHAKE or HKDF, and can now can safely produce a larger round-key array,
* unlocking an increased number of mixing rounds, and preventing many serious forms of attack on the Rijndael cipher.</p>
*
* <p>This is a 'tweakable cipher', the initialization parameters for the cipher include an info parameter.
* Internally, the info parameter is used to customize the SHAKE output, using the 'name' parameter to pre-initialize the SHAKE state. 
* If using the HKDF extension, this parameter is used as the HKDF Expand 'info' parameter, added to the input key and internal counter, and processed by the HMAC pseudo-random function.
* The default value for this information parameter is the cipher name, the extension type H or S, the size of the extension generators security in bits, 
* and the size of the key in bits, as a 16-bit Little Endian integer, ex. RHX using the SHAKE extension, and a 256-bit key would be: RHXS25610.
* The info parameter can be tweaked, using a user defined string. This tweak can be used as a secondary 'domain key', 
* or to differentiate cipher-text output from other implementations.</p>
* 
* \section HBA
* <p>The Hash Based Authentication mode (HBA). Is an authenticated encryption with associated data (AEAD) cipher mode.
* It uses the extended forms of Rijndael (RHX/RSX), wrapped in a segmented integer counter mode (CTR).
* The AAD parameter can be used to add additional data to the MAC generators input, like packet data, or a custom code.
* The info parameter is a user-defined array, and can be used as a secret secondary domain or group key.
* It uses the keyed hash-based MAC funtion; KMAC, to generate the authentication code, 
* which is appended to the cipher-text output of an encryption call.</p>

* \section Implementation
* <p>The base cipher, Rijndael, and the extended form of the cipher, can operate using one of the three provided cipher modes of operation: \n
* Electronic Code Book mode (ECB), which can be used for testing or creating more complex algorithms,  \n
* a segmented integer counter (CTR), and the Cipher Block Chaining mode (CBC). \n
* GCM will soon be added to this implementations modes.
* This implementation has both a C reference, and an implementation that uses the AES-NI instructions that are used in the AES and RHX cipher variants. \n
* The AES-NI implementation can be enabled by adding the RHX_AESNI_ENABLED constant to your preprocessor definitions. \n
* The AES128 and AES256 implementations along with the CBC, CTR, and CBC modes are tested using vectors from NIST SP800-38a. \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a> \n
* See the documentation and the rhx_kat.h tests for usage examples.</p>
*
* \ section Links
* Towards post-quantum symmetric cryptography
* https://eprint.iacr.org/2019/553
* Towards Post-Quantum Secure Symmetric Cryptography: A Mathematical Perspective
* https://eprint.iacr.org/2019/1208
* 
*
* \author    John G. Underhill
* \version   1.0.0.0a
* \date      October 20, 2019
* \copyright GPL version 3 license (GPLv3)
*/

/**
* \file rhx.h
* \brief <b>RHX header definition</b> \n
* Rijndael Hash Extended.
*
* \author John Underhill
* \date October 20, 2019
*

* <b>RHX-256 CTR short-form api example</b> \n
* \code
* // external message, key and custom-info arrays
* const size_t MSG_LEN = 200;
* const size_t CST_LEN = 20;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[RHX256_KEY_SIZE] = {...};
* uint8_t nonce[RHX_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* uint8_t output[MSG_LEN] = { 0 };
* rhx_keyparams kp = { key, RHX256_KEY_SIZE, nonce, cust, CST_LEN };
*
* rhx256_ctr_transform(&kp, output, msg, MSG_LEN)
* \endcode
*
* <b>RHX-256 CTR long-form api example</b> \n
* \code
*
*
* // initialize the state round-key array
*#if defined(RHX_AESNI_ENABLED)
*	__m128i rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
*#else
*	uint32_t rkeys[RHX256_ROUNDKEY_SIZE] = { 0 };
*#endif
*
* // initialize the state and set the round-key array size
* rhx_state state = { rkeys, RHX256_ROUNDKEY_SIZE };
* // initialize the keyparams structure using an externally generated random key
* rhx_keyparams kp = { key, RHX256_KEY_SIZE, nonce };
* uint8_t out[133];
*
* // initialize the cipher with user key and state
* rhx_initialize(&state, &kp, true);
*
* // pass in the nonce and message (user-supplied byte arrays; for best security, nonce should be random), and encrypt the message to output
* rhx_ctr_transform(&state, output, message, sizeof(message));
*
* // erase the round-key array and reset the state
* rhx_dispose(&state);
* \endcode
*
*
* <b>HBA RHX-512 encryption example</b> \n
* \code
* // external message, key and custom-info arrays
* const size_t MSG_LEN = 200;
* const size_t CST_LEN = 20;
* const size_t AAD_LEN = 20;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[RHX256_KEY_SIZE] = {...};
* uint8_t nonce[RHX_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* uint8_t aad[CST_LEN] = {...};
* ...
*
* // mac-code will be appended to the cipher-text
* uint8_t output[MSG_LEN + HBA512_MAC_LENGTH] = { 0 };
* hba_keyparams kp = { key, RHX512_KEY_SIZE, nonce, cust, CST_LEN, aad, AAD_LEN };
*
* if (hba_rhx512_encrypt(&kp, output, msg, MSG_LEN) == false)
* {
*	// encryption has failed, do something..
* }
* \endcode
*
*
* <b>HBA RHX-512 decryption example</b> \n
* \code
* // external cipher-text, key and custom-info arrays
* const size_t CTXT_LEN = 200;
* const size_t CUST_LEN = 20;
* const size_t AAD_LEN = 20;
* // the cipher-text containing the encrypted plain-text and the mac-code
* uint8_t cprtxt[CTXT_LEN] = { hba_encrypt(k,p) }
* uint8_t key[RHX256_KEY_SIZE] = {...};
* uint8_t nonce[RHX_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* // subtract the mac-code length from the overall cipher-text length for the message size
* const size_t MSG_LEN = CTXT_LEN - HBA512_MAC_LENGTH;
* uint8_t output[MSG_LEN] = { 0 };
* hba_keyparams kp = { key, RHX512_KEY_SIZE, nonce, cust, CST_LEN, aad, AAD_LEN };
*
* if (hba_rhx512_decrypt(&kp, output, cprtxt, MSG_LEN) == false)
* {
*	// decryption has failed, do something..
* }
* \endcode
*
*
* \remarks
* Toggle between the cSHAKE (default) and the HKDF(SHA2) extensions by defining the RHX_CSHAKE_EXTENSION definition in this file. \n
* The RHX cSHAKE extension is enabled by default, removing the RHX_CSHAKE_EXTENSION reverts to the HKDF implementation of the key-schedule generator function. \n
* To enable the AES-NI implementation, uncomment the definition in this file or add RHX_AESNI_ENABLED or add it to the compiler preprocessor definitions. \n
* To change the HBA authentication function from the KMAC Keccak-based to the HMAC(SHA2) authentication MAC protocol,
* add the RHX_HMAC_EXTENSION flag to the preprocessor definitions.
*
* For usage examples, see rhx_kat.h. \n
*/

#ifndef QSC_RHX_H
#define QSC_RHX_H

#include "common.h"
#include "sha3.h"
#include "sha2.h"

/*! \enum cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	AES128 = 1,	/*!< The AES-128 block cipher */
	AES256 = 2,	/*!< The AES-256 block cipher */
	RHX256 = 3,	/*!< The RHX-256 block cipher */
	RHX512 = 4,	/*!< The RHX-512 block cipher */
} cipher_type;

/*! \enum cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	CBC = 1,	/*!< Cipher Block Chaining */
	CTR = 2,	/*!< segmented integer counter */
	ECB = 3,	/*!< Electronic CodeBook mode (insecure) */
	HBA = 4,	/*!< Hash Based Authentication block-cipher Counter Mode */
} cipher_mode;

/***********************************
*    USER CONFIGURABLE SETTINGS    *
***********************************/

/*!
\def RHX_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the RHX_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/
#ifndef RHX_AESNI_ENABLED
//#	define RHX_AESNI_ENABLED
#endif 
#ifdef RHX_AESNI_ENABLED
#	include <wmmintrin.h>
#endif

/*!
\def RHX_HMAC_EXTENSION
* Enables the HMAC extensions for the cipher (alternate mode of operation).
* If not defined, the default cSHAKE extensions are used.
*/
#ifndef RHX_HMAC_EXTENSION
#	define RHX_HMAC_EXTENSION
#endif

/*!
\def RHX_CSHAKE_EXTENSION
* Enables the cSHAKE extensions for the cipher (default mode of operation).
* If not defined, the HKDF(SHA2) extensions are used.
* If the the RHX_HMAC_EXTENSION extension flag is defined, HBA reverts to HMAC(SHA2) authentication.
*/
#ifndef RHX_CSHAKE_EXTENSION
#	ifndef RHX_HMAC_EXTENSION
#		define RHX_CSHAKE_EXTENSION
#	endif
#endif


/***********************************
*     RHX CONSTANTS AND SIZES      *
***********************************/

/*!
\def AES128_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-128.
*/
#define AES128_ROUND_COUNT 10

/*!
\def AES256_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-256.
*/
#define AES256_ROUND_COUNT 14

/*!
\def RHX256_ROUND_COUNT
* The number of Rijndael mixing rounds used by RHX-256.
*/
#define RHX256_ROUND_COUNT 22

/*!
\def RHX512_ROUND_COUNT
* The number of Rijndael ming rounds used by RHX-512.
*/
#define RHX512_ROUND_COUNT 30

/*!
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#if defined(RHX_AESNI_ENABLED)
#	define ROUNDKEY_ELEMENT_SIZE 16
#else
#	define ROUNDKEY_ELEMENT_SIZE 4
#	define RHX_PREFETCH_TABLES
#endif

/*!
\def RHX_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions
*/
#define RHX_BLOCK_SIZE 16

/*!
\def RHX_NONCE_SIZE
* The size byte size of the CTR nonce and CBC initialization vector
*/
#define RHX_NONCE_SIZE RHX_BLOCK_SIZE

/*!
\def AES128_ROUNDKEY_SIZE
* The size of the AES-128 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an rhx_state struct.
*/
#define AES128_ROUNDKEY_SIZE ((AES128_ROUND_COUNT + 1) * (RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def AES256_ROUNDKEY_SIZE
* The size of the AES-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an rhx_state struct.
*/
#define AES256_ROUNDKEY_SIZE ((AES256_ROUND_COUNT + 1) * (RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RHX256_ROUNDKEY_SIZE
* The size of the RHX-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an rhx_state struct.
*/
#define RHX256_ROUNDKEY_SIZE ((RHX256_ROUND_COUNT + 1) * (RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RHX512_ROUNDKEY_SIZE
* The size of the RHX-512 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an rhx_state struct.
*/
#define RHX512_ROUNDKEY_SIZE ((RHX512_ROUND_COUNT + 1) * (RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RHX_INFO_DEFLEN
* The size in bytes of the internal default information string.
*/
#define RHX_INFO_DEFLEN 9

/*!
\def AES128_KEY_SIZE
* The size in bytes of the AES-128 input cipher-key
*/
#define AES128_KEY_SIZE 16

/*!
\def AES256_KEY_SIZE
* The size in bytes of the AES-256 input cipher-key
*/
#define AES256_KEY_SIZE 32

/*!
\def RHX256_KEY_SIZE
* The size in bytes of the RHX-256 input cipher-key
*/
#define RHX256_KEY_SIZE 32

/*!
\def RHX512_KEY_SIZE
* The size in bytes of the RHX-512 input cipher-key
*/
#define RHX512_KEY_SIZE 64

/* HBA */

/*!
\def HBA_KMAC_AUTH
* Use KMAC to authenticate HBA; removing this macro is enabled when running in SHAKE extension mode.
* If the RHX_CSHAKE_EXTENSION is disabled, HMAC(SHA2) is the default authentication mode in HBA.
*/
#if defined RHX_CSHAKE_EXTENSION
#	define HBA_KMAC_AUTH
#endif

/*!
\def HBA_INFO_LENGTH
* The HBA version information array length
*/
#define HBA_INFO_LENGTH 16

/*!
\def HBA256_MAC_LENGTH
* The HBA-256 MAC code array length in bytes
*/
#define HBA256_MAC_LENGTH 32

/*!
\def HBA512_MAC_LENGTH
* The HBA-512 MAC code array length in bytes
*/
#define HBA512_MAC_LENGTH 64

/*!
\def HBA_NAME_LENGTH
* The HBA implementation specific name array length
*/
#if defined RHX_CSHAKE_EXTENSION
#	define HBA_NAME_LENGTH 29
#else
#	define HBA_NAME_LENGTH 32
#endif

/*! \struct rhx_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the rhx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
typedef struct rhx_keyparams
{
	uint8_t* key;					/*!< The input cipher key */
	size_t keylen;					/*!< The length in bytes of the cipher key */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
	uint8_t* info;					/*!< The information tweak */
	size_t infolen;					/*!< The length in bytes of the information tweak */
} rhx_keyparams;

/*! \struct rhx_state
* The internal state structure containing the round-key array.
* This structure must be pre-initialized with the round-key array and size, before being passed into the rhx_initialize function.
/* use the XXXXXX_ROUNDKEY_SIZE macros to initialize the array and set the correct size.
*/
typedef struct rhx_state
{
#if defined(RHX_AESNI_ENABLED)
	__m128i* roundkeys;				/*!< The 128-bit integer round-key array */
#else
	uint32_t* roundkeys;			/*!< The round-keys 32-bit subkey array */
#endif
	size_t rndkeylen;				/*!< The round-key array length */
	size_t rounds;					/*!< The number of transformation rounds */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
} rhx_state;

/* cbc simplified api */

void aes128_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void aes256_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void rhx256_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void rhx512_cbc_decrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void aes128_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void aes256_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void rhx256_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void rhx512_cbc_encrypt(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

/* cbc long-form api */

void cbc_decrypt(rhx_state* state, const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void cbc_encrypt(rhx_state* state, const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void cbc_decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input);

void cbc_encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input);

/* ctr long-form */

void ctr_transform(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/* ctr simplified */

void aes128_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void aes256_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void rhx256_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

void rhx512_ctr_transform(const rhx_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

/* ecb mode */

/**
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
void rhx_ecb_decrypt(rhx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
* 
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
void rhx_ecb_encrypt(rhx_state* state, uint8_t* output, const uint8_t* input);

/* HBA */

/*! \struct hba_keyparams
* The HBA key parameters structure; pointers for the key, nonce, and optional user-info and AAD arrays
*/
typedef struct
{
	uint8_t* key;		/*!< the primary key array */
	size_t keylen;		/*!< the primary key array length */
	uint8_t* nonce;		/*!< the block cipher nonce, always 16-bytes in size */
	uint8_t* info;		/*!< the cipher info array */
	size_t infolen;		/*!< the cipher info array length */
	uint8_t* aad;		/*!< the additional data array */
	size_t aadlen;		/*!< the additional data array length */
} hba_keyparams;

/**
* \brief Verify the MAC code, and then decrypt an array of bytes using RHX-256.
* The cipher-text array is first processed with KMAC-256 (or HMAC(SHA2-256) in legacy mode), producing an internal MAC code.
* If the internal MAC code comparison to the code appended to the end of the cipher-text fails, 
* the cipher-text is not decrypted and the function will return false.
* the decrypted output does not contain the MAC code, only the decrypted plain-text.
* 
* \warning The output array must be large enough to accomodate the entire decrypted cipher-text.
*
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param output: The output byte array receives the decrypted cipher-text; the cipher-text will not be decrypted on authentication failure
* \param input: [const] The input byte array; containing the cipher-text and mac code
* \param inputlen: The number of input bytes to decrypt
* 
* \return: returns true if the MAC authentication check has succeeded and the cipher-text decrypted
*/
bool hba_rhx256_decrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Encrypt an array of bytes using RHX-256, and append a 32-byte MAC code to the end of the output array.
* The output array is first encrypted, then processed with KMAC-256 (or HMAC(SHA2-256) in legacy mode), 
* producing a 32-byte MAC code that is appended to the output cipher-text.
*
* \warning The full plain-text and its appended MAC code must be contained in the input array.
*
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param output: The output byte array that receives the cipher-text and the MAC code
* \param input: [const] The input byte array; containing the plain-text to be encrypted
* \param inputlen: The number of input bytes to encrypt and MAC
*
* \return: returns true if the plain-text has been encrypted, and the MAC code appended to the output
*/
bool hba_rhx256_encrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Verify the MAC code, and then decrypt an array of bytes using RHX-512.
* The cipher-text array is first processed with KMAC-512 (or HMAC(SHA2-512) in legacy mode), producing an internal MAC code.
* If the internal MAC code comparison to the code appended to the end of the cipher-text fails,
* the cipher-text is not decrypted and the function will return false.
* the decrypted output does not contain the MAC code, only the decrypted plain-text.
*
* \warning The output array must be large enough to accommodate the entire decrypted cipher-text.
*
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param output: The output byte array receives the decrypted cipher-text; the cipher-text will not be decrypted on authentication failure
* \param input: [const] The input byte array; containing the cipher-text and mac code
* \param inputlen: The number of input bytes to decrypt
*
* \return: returns true if the MAC authentication check has succeeded and the cipher-text decrypted
*/
bool hba_rhx512_decrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Encrypt an array of bytes using RHX-512, and append a 64-byte MAC code to the end of the output array.
* The output array is first encrypted, then processed with KMAC-512 (or HMAC(SHA2-512) in legacy mode), 
* producing a 64-byte MAC code that is appended to the output cipher-text.
*
* \warning The full plain-text and its appended MAC code must be contained in the input array.
*
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param output: The output byte array that receives the cipher-text and the MAC code
* \param input: [const] The input byte array; containing the plain-text to be encrypted
* \param inputlen: The number of input bytes to encrypt and MAC
*
* \return: returns true if the plain-text has been encrypted, and the MAC code appended to the output
*/
bool hba_rhx512_encrypt(const hba_keyparams* keyparams, uint8_t* output, const uint8_t* input, size_t inputlen);

/* common functions */

/**
* \brief Erase the round-key array and size
*/
void rhx_dispose(rhx_state* state);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak. 
* The rhx_state round-key array must be initialized and size set before passing the state to this function.
*
* \param state: [struct] The rhx_state structure
* \param keyparams: The input cipher-key, expanded to the state round-key array
* \param encryption: Initialize the cipher for encryption, false for decryption mode
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
void rhx_initialize(rhx_state* state, rhx_keyparams* keyparams, bool encryption);

/* pkcs7 */

/**
* \brief Add padding to a plaintext block pad before encryption.
*
* \param input: The block of input plaintext
* \param offset: The first byte in the block to pad
* \param length: The length of the plaintext block
*/
void pkcs7_add_padding(uint8_t* input, size_t offset, size_t length);

/**
* \brief Get the number of padded bytes in a block of decrypted cipher-text.
*
* \param input: [const] The block of input plaintext
* \param offset: The first byte in the block to pad
* \param length: The length of the plaintext block
* 
* \return: The length of the block padding
*/
size_t pkcs7_padding_length(const uint8_t* input, size_t offset, size_t length);

#endif

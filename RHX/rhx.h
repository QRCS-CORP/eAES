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
* \version   1.0.0.0
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
* <b>RHX-256 CTR Example</b> \n
* \code
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
* rhx_keyparams kp = { key, RHX256_KEY_SIZE };
* uint8_t out[133];
*
* // initialize the cipher with user key and state
* rhx_initialize(&state, &kp, true);
*
* // pass in the nonce and message (user-supplied byte arrays; for best security, nonce should be random), and encrypt the message to output
* rhx_ctr_transform(&state, output, nonce, message, sizeof(message));
*
* // erase the round-key array and reset the state
* rhx_dispose(&state);
* \endcode
*
* \remarks For usage examples, see rhx_kat.h. \n
* Toggle between the cSHAKE (default) and the HKDF(SHA2) extensions by defining the RHX_CSHAKE_EXTENSION macro in this file. \n
* The cSHAKE extension is enabled by default, removing the RHX_CSHAKE_EXTENSION reverts to the HKDF extensions. \n
* To enable the AES-NI implementation, uncomment the definition in this file or add RHX_AESNI_ENABLED or add it to the compiler preprocessor definitions.
*/

#ifndef RHX_H
#define RHX_H

#include <stdbool.h>
#include <stdint.h>

/*! \enum cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	CBC = 1,	/*!< Cipher Block Chaining */
	CTR = 2,	/*!< segmented integer counter */
	ECB = 3,	/*!< Electronic CodeBook mode (insecure) */
	//GCM = 4,	/*!< Galois Counter Mode */
} cipher_mode;

/*!
\def RHX_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, use a preprocessor definition to enable SIMD and AES-NI.
*/
//#define RHX_AESNI_ENABLED

#if defined(RHX_AESNI_ENABLED)
#	include <wmmintrin.h>
#endif

/*!
\def RHX_CSHAKE_EXTENSION
* Enables the cSHAKE extensions for the cipher (default mode of operation).
* If not defined, the HKDF(SHA2) extensions are used.
*/
#define RHX_CSHAKE_EXTENSION

/*!
\def AES128_ROUND_COUNT
* The number of Rijndael ming rounds used by AES-128.
*/
#define AES128_ROUND_COUNT 10

/*!
\def AES256_ROUND_COUNT
* The number of Rijndael ming rounds used by AES-256.
*/
#define AES256_ROUND_COUNT 14

/*!
\def RHX256_ROUND_COUNT
* The number of Rijndael ming rounds used by RHX-256.
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

/*! \struct rhx_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the rhx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
typedef struct rhx_keyparams
{
	uint8_t* key;		/*!< The input cipher key */
	size_t keylen;		/*!< The length in bytes of the cipher key */
	uint8_t* info;		/*!< The information tweak */
	size_t infolen;		/*!< The length in bytes of the information tweak */
} rhx_keyparams;

/*! \struct rhx_state
* The internal state structure containing the round-key array.
* This structure must be pre-initialized with the round-key array and size, before being passed into the rhx_initialize function.
/* use the XXXXXX_ROUNDKEY_SIZE macros to initialize the array and set the correct size.
*/
typedef struct rhx_state
{
#if defined(RHX_AESNI_ENABLED)
	__m128i* roundkeys;		/*!< The 128-bit integer round-key array */
#else
	uint32_t* roundkeys;	/*!< The round-keys 32-bit subkey array */
#endif
	size_t rndkeylen;		/*!< The round-key array length */
} rhx_state;

/* Public API */

/**
* \brief Decrypt one 16-byte block of cipher-text using Cipher Block Chaining mode.
*
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the decrypted plain-text
* \param iv The initialization vector; must be 16 bytes in length
* \param input The input cipher-text block of bytes
*/
void rhx_cbc_decrypt(rhx_state* state, uint8_t* output, uint8_t* iv, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of plain-text using Cipher Block Chaining mode.
*
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the encrypted cipher-text
* \param iv The initialization vector; must be 16 bytes in length
* \param input The input plain-text block of bytes
*/
void rhx_cbc_encrypt(rhx_state* state, uint8_t* output, uint8_t* iv, const uint8_t* input);

/**
* \brief Encrypt/Decrypt one (16 byte) block of plain-text using a segmented integer counter (CTR) mode.
*
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the encrypted cipher-text
* \param nonce The initialization vector; must be 16 bytes in length
* \param input The input plain-text block of bytes
* \param inputlen The length in bytes to transform
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
void rhx_ctr_transform(rhx_state* state, uint8_t* output, uint8_t* nonce, const uint8_t* input, size_t inputlen);

/**
* \brief Erase the round-key array and size
*/
void rhx_dispose(rhx_state* state);

/**
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the decrypted plain-text
* \param input The input cipher-text block of bytes
*/
void rhx_ecb_decrypt(rhx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
* 
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the encrypted cipher-text
* \param input The input plain-text block of bytes
*/
void rhx_ecb_encrypt(rhx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Decrypt one 16-byte block of cipher-text using Galois Counter Mode. \n
*
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the decrypted plain-text
* \param input The input cipher-text bytes
* \param inputlen The length in bytes to decrypt
*/
/*void rhx_gcm_decrypt(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);*/

/**
* \brief Encrypt one 16-byte block of cipher-text using Galois Counter Mode.
*
* \param state The initialized rhx_state structure
* \param output The output byte array; receives the encrypted cipher-text
* \param input The input plain-text bytes
* \param inputlen The length in bytes to transform
*/
/*void rhx_gcm_encrypt(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);*/

/**
* \brief Initialize the state with the input cipher-key and optional info tweak. 
* The rhx_state round-key array must be initialized and size set before passing the state to this function.
*
* \param state The rhx_state structure
* \param keyparams The input cipher-key, expanded to the state round-key array
* \param encryption Initialize the cipher for encryption, false for decryption mode
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
void rhx_initialize(rhx_state* state, rhx_keyparams* keyparams, bool encryption);

#endif

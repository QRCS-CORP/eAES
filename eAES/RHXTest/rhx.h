
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

/*!
* \mainpage <b>The RHX cipher</b>
* \section intro_sec Welcome
* <p>The RHX (Rijndael Hash-based eXtension) cipher, is a hybrid of Rijndael (AES) and a cryptographically strong pseudo-random generator function.
* The cryptographic KDF, is used to generate the round keys for the Rijndael rounds function, enabling the safe addition of increased mixing rounds, 
* and replacing the differentially-weak native Rijndael key-schedule expansion function. \n
* The cipher increases the number of mixing rounds from 14 used by AES-256, to 22 used by RHX-256, twice the best known classical computer attack.
* The cipher also has a 512-bit key configuration, which uses 30 rounds of mixing. 
* There are attacks now being proposed, that strongly indicate that larger key sizes will be necessary against future quantum-based attacks on symmetric ciphers.
* 
* <p>The default extension used by this cipher is the Keccak cSHAKE extended output function (XOF).
* The fallback generator is HKDF(HMAC(SHA2)) Expand.
* Both genertors are implemented in 256 and 512-bit forms of those functions, correlating to the input cipher-key size.
* The cipher code names are based on which generator is used; RHX for Rijndael HKDF eXtension, and RSX for Rijndael SHAKE eXtension, 
* with the ciphers formal name now being 'eAES', or extended AES.
* The cipher has four modes, AES128 and AES256, which are the standard AES configurations, and the two extended modes, RSX/RHX-256 and RSX/RHX-512.
* In extended mode, the key schedules round-key expansion function has been replaced by cSHAKE or HKDF, and can now can safely produce a larger round-key array,
* unlocking an increased number of mixing rounds, and preventing many serious forms of attack on the Rijndael cipher.
*
* <p>This is a 'tweakable cipher', the initialization parameters rhx_keyparams, include an info parameter.
* Internally, the info parameter is used to customize the SHAKE output, using the 'name' parameter to pre-initialize the cSHAKE state. 
* If using the HKDF extension, this parameter is used as the HKDF Expand 'info' parameter, added to the input key and internal counter, and processed by the HMAC pseudo-random function.
* The default value for this information parameter is the cipher name, the extension type H or S, the size of the extension generators security in bits, 
* and the size of the key in bits, as a 16-bit Little Endian integer, ex. RHX using the SHAKE extension, and a 256-bit key would be: RHXS25610.
* The info parameter can be tweaked, using a user defined string. This tweak can be used as a secondary 'domain key', 
* or to differentiate cipher-text output from other implementations.
* 
* \section HBA
* <p>The Hash Based Authentication mode (HBA), is an authenticated encryption with associated data (AEAD) cipher mode.
* It uses the extended forms of Rijndael (RHX/RSX), wrapped in a segmented integer counter mode (CTR).
* HBA uses the keyed hash-based MAC funtion; KMAC or HMAC, to generate the authentication code, 
* which is appended to the cipher-text output of an encryption call.
* In decryption mode, before decryption is performed, an internal mac code is calculated, and compared to the code embedded in the cipher-text.
* If authentication fails, the cipher-text is not decrypted, and the function returns a boolean false value.
* The AAD parameter can be used to add additional data to the MAC generators input, like packet data, or a custom code.
* The info parameter is a user-defined tweak array, and can be used as a secret secondary domain or group key.

* \section Implementation
* <p>The base cipher, Rijndael, and the extended form of the cipher, can operate using one of the four provided cipher modes of operation: \n
* Electronic Code Book mode (ECB), which can be used for testing or creating more complex algorithms.  \n
* The segmented integer counter mode (CTR). \n
* The Cipher Block Chaining mode (CBC). \n
* The authenticated block-cipher counter with Hash Based Authentication AEAD mode; HBA. \n
* This implementation has both a C reference, and an implementation that uses the AES-NI instructions that are used in the AES and RHX cipher variants. \n
* The AES-NI implementation can be enabled by adding the SYSTEM_AESNI_ENABLED constant to your preprocessor definitions. \n
* The implementation can be toggled from SHA3 to SHA2 operation mode by adding the RHX_HKDF_EXTENSION to the pre-processor definitions. \n
* The AES128 and AES256 implementations along with the ECB, CTR, and CBC modes are tested using vectors from NIST SP800-38a. \n
* The RHX-256, RHX-512, and HBA known answer vectors are taken from the CEX++ cryptographic library;
* <a href="https://github.com/Steppenwolfe65/CEX">The CEX++ Cryptographic Library</a>. \n
* See the documentation and the rhx_test.c tests for usage examples.
*
* \ section Links
* Towards post-quantum symmetric cryptography
* https://eprint.iacr.org/2019/553
* Towards Post-Quantum Secure Symmetric Cryptography: A Mathematical Perspective
* https://eprint.iacr.org/2019/1208
* 
*
* \author		John G. Underhill
* \version		1.0.0.1a
* \date			October 20, 2019
* \updated		December 05, 2020
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*/

/**
* \file rhx.h
* \brief <b>RHX header definition</b> \n
* Rijndael Hash Extended.
*
* \author John Underhill
* \date January 20, 2020
* \updated December 05, 2020
*
* <b>RHX-256 CTR short-form api example</b> \n
* \code
* // external message, key and custom-info arrays
* const size_t MSG_LEN = 200;
* const size_t CST_LEN = 20;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[RHX_RHX256_KEY_SIZE] = {...};
* uint8_t nonce[RHX_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* uint8_t output[MSG_LEN] = { 0 };
* rhx_hba_state state;
* rhx_keyparams kp = { key, RHX_RHX256_KEY_SIZE, nonce, cust, CST_LEN };
* 
* // initialize the state
* rhx_initialize(&state, &kp, true, RHX256);
* // encrypt the message
* rhx_ctr_transform(&state, output, msg, MSG_LEN)
* \endcode
*
* <b>HBA RHX-512 encryption example</b> \n
* \code
* // external message, key and custom-info arrays
* const size_t MSG_LEN = 200;
* const size_t CST_LEN = 20;
* const size_t AAD_LEN = 20;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[RHX_RHX256_KEY_SIZE] = {...};
* uint8_t nonce[RHX_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* uint8_t aad[CST_LEN] = {...};
* ...
*
* // mac-code will be appended to the cipher-text
* uint8_t cpt[MSG_LEN + RHX_HBA512_MAC_LENGTH] = { 0 };
* hba_keyparams kp = { key, RHX_RHX512_KEY_SIZE, nonce, cust, CST_LEN};
*
* // initialize the cipher state for encryption
* rhx_hba512_initialize(&state, &kp, true);
* // add the associated data
* rhx_hba_set_associated(&state, aad, sizeof(aad));
* // encrypt the message
* rhx_hba512_transform(&state, cpt, msg, MSG_LEN);
* \endcode
*
*
* <b>HBA RHX-512 decryption example</b> \n
* \code
* // external cipher-text, key and custom-info arrays
* const size_t CPT_LEN = 200;
* const size_t CUST_LEN = 20;
* const size_t AAD_LEN = 20;
* // the cipher-text containing the encrypted plain-text and the mac-code
* uint8_t cpt[CPT_LEN] = { hba_encrypt(k,p) }
* uint8_t key[RHX_RHX256_KEY_SIZE] = {...};
* uint8_t nonce[RHX_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* // subtract the mac-code length from the overall cipher-text length for the message size
* const size_t MSG_LEN = CPT_LEN - RHX_HBA512_MAC_LENGTH;
* uint8_t msg[MSG_LEN] = { 0 };
* hba_keyparams kp = { key, RHX_RHX512_KEY_SIZE, nonce, cust, CST_LEN, aad, AAD_LEN };
*
* // initialize the cipher state for decryption
* rhx_hba512_initialize(&state, &kp, false);
* // add the associated data
* rhx_hba_set_associated(&state, aad, sizeof(aad));
* // authenticate and decrypt the cipher-text
* if (rhx_hba512_transform(&state, msg, cpt, CPT_LEN - RHX_HBA512_MAC_LENGTH) == false)
* {
*	// authentication has failed, do something..
* }
* \endcode
*
*
* \remarks
* Toggle between the eAES cSHAKE (default) and the HKDF(SHA2) extensions by defining the RHX_SHAKE_EXTENSION definition in this file. \n
* The RHX cSHAKE extension is enabled by default, removing the RHX_SHAKE_EXTENSION reverts to the HKDF implementation of the key-schedule generator function. \n
* To enable the AES-NI implementation, uncomment the definition in this file or add SYSTEM_AESNI_ENABLED or add it to the compiler preprocessor definitions. \n
* To change the HBA authentication function from the KMAC Keccak-based to the HMAC(SHA2) authentication MAC protocol,
* add the RHX_HKDF_EXTENSION flag to the preprocessor definitions. \n
* AVX-512 instructions integrated throughout. Set the Enhanced Instruction Set to AVX512 for maximum performance.
*
* For usage examples, see rhx_test.h. \n
*/

#ifndef RHX_RHX_H
#define RHX_RHX_H

#include "common.h"
#include "hash.h"

/*! \enum rhx_cipher_mode
* The pre-defined cipher mode implementations
*/
RHX_EXPORT_API typedef enum
{
	AES128 = 1,	/*!< The AES-128 block cipher */
	AES256 = 2,	/*!< The AES-256 block cipher */
	RHX256 = 3,	/*!< The RHX-256 block cipher */
	RHX512 = 4,	/*!< The RHX-512 block cipher */
} rhx_cipher_type;

/*! \enum rhx_cipher_mode
* The pre-defined cipher mode implementations
*/
RHX_EXPORT_API typedef enum
{
	CBC = 1,	/*!< Cipher Block Chaining */
	CTR = 2,	/*!< segmented integer counter */
	ECB = 3,	/*!< Electronic CodeBook mode (insecure) */
	HBA = 4,	/*!< Hash Based Authentication block-cipher Counter Mode */
} rhx_cipher_mode;

/***********************************
*    USER CONFIGURABLE SETTINGS    *
***********************************/

/*!
\def SYSTEM_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the SYSTEM_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/
#if !defined(SYSTEM_AESNI_ENABLED)
#	if defined(SYSTEM_AVX_INTRINSICS)
#		define SYSTEM_AESNI_ENABLED
#	endif
#endif 

#if defined(SYSTEM_AESNI_ENABLED)
#	if defined(SYSTEM_COMPILER_MSC)
#		include <intrin.h>
#		include <immintrin.h>
#	elif defined(SYSTEM_COMPILER_GCC)
#		include <x86intrin.h>
#	endif
#endif

/*!
\def RHX_HKDF_EXTENSION
* Enables the HKDF extensions for the cipher (alternate mode of authentication).
* If not defined, the default cSHAKE extensions are used.
*/
#if !defined(RHX_HKDF_EXTENSION)
//#	define RHX_HKDF_EXTENSION
#endif

/*!
\def RHX_SHAKE_EXTENSION
* Enables the cSHAKE extensions for the cipher (default mode of operation).
* If not defined, the HKDF(SHA2) extensions are used.
* If the the RHX_HKDF_EXTENSION extension flag is defined, HBA reverts to HMAC(SHA2) authentication.
*/
#if !defined(RHX_SHAKE_EXTENSION)
#	if !defined(RHX_HKDF_EXTENSION)
#		define RHX_SHAKE_EXTENSION
#	endif
#endif

/***********************************
*     RHX CONSTANTS AND SIZES      *
***********************************/

/*!
\def RHX_HBA256_MAC_LENGTH
* The HBA-256 MAC code array length in bytes.
*/
#define RHX_HBA256_MAC_LENGTH 32

/*!
\def RHX_HBA512_MAC_LENGTH
* The HBA-512 MAC code array length in bytes.
*/
#define RHX_HBA512_MAC_LENGTH 64

/*!
\def RHX_HBA_KMAC_AUTH
* Use KMAC to authenticate HBA; removing this macro is enabled when running in SHAKE extension mode.
* If the RHX_SHAKE_EXTENSION is disabled, HMAC(SHA2) is the default authentication mode in HBA.
*/
#if defined(RHX_SHAKE_EXTENSION)
#	define RHX_HBA_KMAC_AUTH
#endif

/*!
\def RHX_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions.
*/
#define RHX_BLOCK_SIZE 16

/*!
\def RHX_AES128_KEY_SIZE
* The size in bytes of the AES-128 input cipher-key.
*/
#define RHX_AES128_KEY_SIZE 16

/*!
\def RHX_AES256_KEY_SIZE
* The size in bytes of the AES-256 input cipher-key.
*/
#define RHX_AES256_KEY_SIZE 32

/*!
\def RHX_RHX256_KEY_SIZE
* The size in bytes of the RHX-256 input cipher-key.
*/
#define RHX_RHX256_KEY_SIZE 32

/*!
\def RHX_RHX512_KEY_SIZE
* The size in bytes of the RHX-512 input cipher-key.
*/
#define RHX_RHX512_KEY_SIZE 64

/*!
\def RHX_HBA_MAXAAD_SIZE
* The maximum allowed AAD size.
*/
#define RHX_HBA_MAXAAD_SIZE 256

/*!
\def RHX_HBA_MAXINFO_SIZE
* The maximum allowed key info size.
*/
#define RHX_HBA_MAXINFO_SIZE 256

/*! \struct rhx_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the rhx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
RHX_EXPORT_API typedef struct
{
	const uint8_t* key;				/*!< The input cipher key */
	size_t keylen;					/*!< The length in bytes of the cipher key */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
	const uint8_t* info;			/*!< The information tweak */
	size_t infolen;					/*!< The length in bytes of the information tweak */
} rhx_keyparams;

/*! \struct rhx_state
* The internal state structure containing the round-key array.
*/
RHX_EXPORT_API typedef struct
{
#if defined(SYSTEM_AESNI_ENABLED)
	__m128i roundkeys[31];			/*!< The 128-bit intel integer round-key array */
#	if defined(SYSTEM_HAS_AVX512)
		__m512i roundkeysw[31];
#	endif
#else
	uint32_t roundkeys[124];		/*!< The round-keys 32-bit subkey array */
#endif
	size_t roundkeylen;				/*!< The round-key array length */
	size_t rounds;					/*!< The number of transformation rounds */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
} rhx_state;

/* common functions */

/**
* \brief Erase the round-key array and size
*/
RHX_EXPORT_API void rhx_dispose(rhx_state* state);

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
RHX_EXPORT_API void rhx_initialize(rhx_state* state, const rhx_keyparams* keyparams, bool encryption, rhx_cipher_type ctype);

/* cbc mode */

/**
* \brief Decrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the rhx_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text bytes
* \param inputlen: The number of input cipher-text bytes to decrypt
*/
RHX_EXPORT_API void rhx_cbc_decrypt(rhx_state* state, uint8_t* output, size_t *outputlen, const uint8_t* input, size_t inputlen);

/**
* \brief Encrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the rhx_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the encrypted plain-text
* \param input: [const] The input plain-text bytes
* \param inputlen: The number of input plain-text bytes to encrypt
*/
RHX_EXPORT_API void rhx_cbc_encrypt(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Decrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the rhx_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
RHX_EXPORT_API void rhx_cbc_decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the rhx_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
RHX_EXPORT_API void rhx_cbc_encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input);

/* pkcs7 */

/**
* \brief Add padding to a plaintext block pad before encryption.
*
* \param input: The block of input plaintext
* \param offset: The first byte in the block to pad
* \param length: The length of the plaintext block
*/
RHX_EXPORT_API void rhx_pkcs7_add_padding(uint8_t* input, size_t length);

/**
* \brief Get the number of padded bytes in a block of decrypted cipher-text.
*
* \param input: [const] The block of input plaintext
* \param offset: The first byte in the block to pad
* \param length: The length of the plaintext block
* 
* \return: The length of the block padding
*/
RHX_EXPORT_API size_t rhx_pkcs7_padding_length(const uint8_t* input);

/* ctr mode */

/**
* \brief Transform a length of data using a Big Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the rhx_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param inputlen: The number of input bytes to transform
*/
RHX_EXPORT_API void rhx_ctrbe_transform(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/**
* \brief Transform a length of data using a Little Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the rhx_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param inputlen: The number of input bytes to transform
*/
RHX_EXPORT_API void rhx_ctrle_transform(rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/* ecb mode */

/**
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
RHX_EXPORT_API void rhx_ecb_decrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
* 
* \param state: [struct] The initialized rhx_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
RHX_EXPORT_API void rhx_ecb_encrypt_block(rhx_state* state, uint8_t* output, const uint8_t* input);

/* HBA-256 */

/*! \struct rhx_hba256_state
* The HBA-256 state array; pointers for the cipher state, mack key and length, transformation mode, and the state counter.
* Used by the long-form of the HBA api, and initialized by the hba_initialize function.
*/
RHX_EXPORT_API typedef struct
{
#if defined(RHX_SHAKE_EXTENSION)
	keccak_state kstate;	/*!< the mac state */
#else
	hmac256_state kstate;
#endif
	rhx_state cstate;				/*!< the underlying block-ciphers state structure */
	uint64_t counter;					/*!< the processed bytes counter */
	uint8_t mkey[32];					/*!< the mac generators key array */
	uint8_t cust[RHX_HBA_MAXINFO_SIZE];	/*!< the ciphers custom key */
	size_t custlen;						/*!< the custom key array length */
	bool encrypt;						/*!< the transformation mode; true for encryption */
} rhx_hba256_state;

/**
* \brief Dispose of the HBA-256 cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays allocated on the heap,
* and must be called before the state goes out of scope.
*
* \param state: [struct] The HBA state structure; contains internal state information
*/
RHX_EXPORT_API void rhx_hba256_dispose(rhx_hba256_state* state);

/**
* \brief Initialize the cipher and load the keying material.
* Initializes the cipher state to an RHX-256 instance.
*
* \warning The initialize function must be called before either the associated data or transform functions are called.
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*/
RHX_EXPORT_API void rhx_hba256_initialize(rhx_hba256_state* state, const rhx_keyparams* keyparams, bool encrypt);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \param state: [struct] The HBA-256 state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
RHX_EXPORT_API void rhx_hba256_set_associated(rhx_hba256_state* state, const uint8_t* data, size_t datalen);

/**
* \brief Transform an array of bytes using an instance of RHX-256.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the ciphertext.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*
* \return: Returns true if the cipher has been initialized successfully, false on failure
*/
RHX_EXPORT_API bool rhx_hba256_transform(rhx_hba256_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/* HBA-512 */

/*! \struct rhx_hba_state
* The HBA state array; pointers for the cipher state, mack key and length, transformation mode, and the state counter.
* Used by the long-form of the HBA api, and initialized by the hba_initialize function.
*/
RHX_EXPORT_API typedef struct
{
#if defined(RHX_SHAKE_EXTENSION)
	keccak_state kstate;	/*!< the mac state */
#else
	hmac512_state kstate;
#endif
	rhx_state cstate;				/*!< the underlying block-ciphers state structure */
	uint64_t counter;					/*!< the processed bytes counter */
	uint8_t mkey[64];					/*!< the mac generators key array */
	uint8_t cust[RHX_HBA_MAXINFO_SIZE];	/*!< the ciphers custom key */
	size_t custlen;						/*!< the custom key array length */
	bool encrypt;						/*!< the transformation mode; true for encryption */
} rhx_hba512_state;

/**
* \brief Dispose of the HBA cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays allocated on the heap,
* and must be called before the state goes out of scope.
*
* \param state: [struct] The HBA state structure; contains internal state information
*/
RHX_EXPORT_API void rhx_hba512_dispose(rhx_hba512_state* state);

/**
* \brief Initialize the cipher and load the keying material.
* Initializes the cipher state to an RHX-512 instance.
*
* \warning The initialize function must be called before either the associated data or transform functions are called.
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*/
RHX_EXPORT_API void rhx_hba512_initialize(rhx_hba512_state* state, const rhx_keyparams* keyparams, bool encrypt);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \param state: [struct] The HBA-512 state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
RHX_EXPORT_API void rhx_hba512_set_associated(rhx_hba512_state* state, const uint8_t* data, size_t datalen);

/**
* \brief Transform an array of bytes using an instance of RHX-512.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the ciphertext.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
RHX_EXPORT_API bool rhx_hba512_transform(rhx_hba512_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

#endif

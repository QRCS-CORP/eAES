
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

#ifndef HASH_H
#define HASH_H

#include "common.h"

/* SHA3 Implementation */

/*!
* \def KECCAK_CSHAKE_DOMAIN_ID
* \brief The cSHAKE domain id
*/
#define KECCAK_CSHAKE_DOMAIN_ID 0x04

/*!
* \def KECCAK_KMAC_DOMAIN_ID
* \brief The KMAC domain id
*/
#define KECCAK_KMAC_DOMAIN_ID 0x04

/*!
* \def KECCAK_PERMUTATION_ROUNDS
* \brief The standard number of permutation rounds
*/
#define KECCAK_PERMUTATION_ROUNDS 24

/*!
* \def KECCAK_PERMUTATION_MAX_ROUNDS
* \brief The maximum number of permutation rounds
*/
#define KECCAK_PERMUTATION_MAX_ROUNDS 48

/*!
* \def KECCAK_PERMUTATION_MIN_ROUNDS
* \brief The minimum number of permutation rounds
*/
#define KECCAK_PERMUTATION_MIN_ROUNDS 12

/*!
* \def KECCAK_PERMUTATION_ROUNDS
* \brief The standard number of permutation rounds
*/
#define KECCAK_PERMUTATION_ROUNDS 24

/*!
* \def KECCAK_PERMUTATION_MAX_ROUNDS
* \brief The maximum number of permutation rounds
*/
#define KECCAK_PERMUTATION_MAX_ROUNDS 48

/*!
* \def KECCAK_PERMUTATION_MIN_ROUNDS
* \brief The minimum number of permutation rounds
*/
#define KECCAK_PERMUTATION_MIN_ROUNDS 12

/*!
* \def KECCAK_SHA3_DOMAIN_ID
* \brief The SHA3 domain id
*/
#define KECCAK_SHA3_DOMAIN_ID 0x06

/*!
* \def KECCAK_SHAKE_DOMAIN_ID
* \brief The SHAKE domain id
*/
#define KECCAK_SHAKE_DOMAIN_ID 0x1F

/*!
* \def KECCAK_STATE_BYTE_SIZE
* \brief The Keccak state array byte size
*/
#define KECCAK_STATE_BYTE_SIZE 200

/*!
* \def KECCAK_128_RATE
* \brief The KMAC-128 byte absorption rate
*/
#define KECCAK_128_RATE 168

/*!
* \def KECCAK_256_RATE
* \brief The KMAC-256 byte absorption rate
*/
#define KECCAK_256_RATE 136

/*!
* \def KECCAK_512_RATE
* \brief The KMAC-512 byte absorption rate
*/
#define KECCAK_512_RATE 72

/*!
* \def KECCAK_STATE_SIZE
* \brief The Keccak SHA3 uint64 state array size
*/
#define KECCAK_STATE_SIZE 25

/*!
* \def KECCAK_STATE_BYTE_SIZE
* \brief The Keccak SHA3 state size in bytes
*/
#define KECCAK_STATE_BYTE_SIZE 200

/*!
* \def KMAC_256_KEY_SIZE
* \brief The KMAC-256 key size in bytes
*/
#define KMAC_256_KEY_SIZE 32

/*!
* \def KMAC_512_KEY_SIZE
* \brief The KMAC-512 key size in bytes
*/
#define KMAC_512_KEY_SIZE 64

/*!
* \def SHAKE_256_KEY_SIZE
* \brief The SHAKE-256 key size in bytes
*/
#define SHAKE_256_KEY_SIZE 32

/*!
* \def SHAKE_512_KEY_SIZE
* \brief The SHAKE-512 key size in bytes
*/
#define SHAKE_512_KEY_SIZE 64

/*!
* \struct keccak_state
* \brief The Keccak state array; state array must be initialized by the caller
*/
RHX_EXPORT_API typedef struct
{
	uint64_t state[KECCAK_STATE_SIZE];			/*!< The SHA3 state  */
	uint8_t buffer[KECCAK_STATE_BYTE_SIZE];		/*!< The message buffer  */
	size_t position;								/*!< The buffer position  */
} keccak_state;

/*!
* \enum keccak_rate
* \brief The Keccak rate; determines which security strength is used by the function, 128, 256, or 512-bit
*/
typedef enum
{
	keccak_rate_128 = KECCAK_128_RATE,		/*!< The Keccak 128-bit rate  */
	keccak_rate_256 = KECCAK_256_RATE,		/*!< The Keccak 256-bit rate  */
	keccak_rate_512 = KECCAK_512_RATE,		/*!< The Keccak 512-bit rate  */
} keccak_rate;

/**
* \brief Absorb an input message into the Keccak state
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
* \param domain: The function domain id
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
RHX_EXPORT_API void keccak_absorb(keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen, uint8_t domain, size_t rounds);

/**
* \brief Absorb the custom, and name arrays into the Keccak state
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
RHX_EXPORT_API void keccak_absorb_custom(keccak_state* ctx, keccak_rate rate, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds);

/**
* \brief Absorb the custom, name, and key arrays into the Keccak state.
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
RHX_EXPORT_API void keccak_absorb_key_custom(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds);

/**
* \brief Dispose of the Keccak state.
*
* \warning The dispose function must be called when disposing of the function state.
* This function safely destroys the internal state.
*
* \param ctx: [struct] The Keccak state structure
*/
RHX_EXPORT_API void keccak_dispose(keccak_state* ctx);

/**
* \brief Finalize the Keccak state
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param domain: The function domain id
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
RHX_EXPORT_API void keccak_finalize(keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen, uint8_t domain, size_t rounds);

/**
* \brief Absorb bytes into state incrementally
*
* \param ctx: The function state
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message array
* \param msglen: The number of message bytes
*/
RHX_EXPORT_API void keccak_incremental_absorb(keccak_state* ctx, uint32_t rate, const uint8_t* message, size_t msglen);

/**
* \brief Finalize state added incrementally
*
* \param ctx: The function state
* \param rate: The rate of absorption in bytes
* \param domain: The function domain id
*/
RHX_EXPORT_API void keccak_incremental_finalize(keccak_state* ctx, uint32_t rate, uint8_t domain);

/**
* \brief Extract an array of bytes from the Keccak state
*
* \param ctx: The function state
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param rate: The rate of absorption in bytes
*/
RHX_EXPORT_API void keccak_incremental_squeeze(keccak_state* ctx, size_t rate, uint8_t* output, size_t outlen);

/**
* \brief The Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param ctx: [struct] The function state; must be initialized
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
RHX_EXPORT_API void keccak_permute(keccak_state* ctx, size_t rounds);

/**
* \brief The compact Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param state: The state array; must be initialized
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
RHX_EXPORT_API void keccak_permute_p1600c(uint64_t* state, size_t rounds);

/**
* \brief The unrolled Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param state: The state array; must be initialized
*/
RHX_EXPORT_API void keccak_permute_p1600u(uint64_t* state);

/**
* \brief The Keccak squeeze function.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
* \param rate: The rate of absorption in bytes
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
RHX_EXPORT_API void keccak_squeezeblocks(keccak_state* ctx, uint8_t* output, size_t nblocks, keccak_rate rate, size_t rounds);

/**
* \brief Initializes a Keccak state structure, must be called before message processing.
* Long form api: must be used in conjunction with the block-update and finalize functions.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
*/
RHX_EXPORT_API void keccak_initialize_state(keccak_state* ctx);

/**
* \brief Update Keccak state with message input.
*
* \warning The state must be initialized before calling
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
RHX_EXPORT_API void keccak_update(keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen, size_t rounds);

/* cSHAKE */

/**
* \brief Key a cSHAKE-128 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array..
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void cshake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a cSHAKE-256 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void cshake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a cSHAKE-512 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void cshake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief The SHAKE initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
RHX_EXPORT_API void shake_initialize(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen);

/**
* \brief The cSHAKE initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Initialize the name and customization strings into the state.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void cshake_initialize(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief The cSHAKE squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
RHX_EXPORT_API void cshake_squeezeblocks(keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks);

/**
* \brief The cSHAKE update function.
* Long form api: must be used in conjunction with the initialize and squeezeblocks functions.
* Finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
RHX_EXPORT_API void cshake_update(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen);

/* KMAC */

/**
* \brief Key a KMAC-128 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The MAC code byte array
* \param outlen: The number of MAC code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a KMAC-256 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The MAC code byte array
* \param outlen: The number of MAC code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a KMAC-512 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The MAC code byte array
* \param outlen: The number of MAC code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief The KMAC message update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* \warning The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
RHX_EXPORT_API void kmac_update(keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen);

/**
* \brief The KMAC finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param outlen: The number of bytes to extract
*/
RHX_EXPORT_API void kmac_finalize(keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen);

/**
* \brief Initialize a KMAC instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
RHX_EXPORT_API void kmac_initialize(keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/* SHA2 Implementation */

/*!
* \def HKDF_256_KEY_SIZE
* \brief The HKDF-256 key size in bytes
*/
#define HKDF_256_KEY_SIZE 32

/*!
* \def HKDF_512_KEY_SIZE
* \brief The HKDF-512 key size in bytes
*/
#define HKDF_512_KEY_SIZE 64

/*!
* \def HMAC_256_KEY_SIZE
* \brief The recommended HMAC(SHA2-256) key size, minimum is 32 bytes
*/
#define HMAC_256_KEY_SIZE 32

/*!
* \def HMAC_512_KEY_SIZE
* \brief The recommended HMAC(SHA2-512) key size minimum is 64 bytes
*/
#define HMAC_512_KEY_SIZE 64

/*!
* \def HMAC_256_MAC_SIZE
* \brief The HMAC-256 mac-code size in bytes
*/
#define HMAC_256_MAC_SIZE 32

/*!
* \def HMAC_512_MAC_SIZE
* \brief The HMAC-512 mac-code size in bytes
*/
#define HMAC_512_MAC_SIZE 64

/*!
* \def HMAC_256_RATE
* \brief The HMAC-256 input rate size in bytes
*/
#define HMAC_256_RATE 64

/*!
* \def HMAC_512_RATE
* \brief The HMAC-512 input rate size in bytes
*/
#define HMAC_512_RATE 128

/*!
* \def SHA2_256_HASH_SIZE
* \brief The SHA2-256 hash size in bytes
*/
#define SHA2_256_HASH_SIZE 32

/*!
* \def SHA2_512_HASH_SIZE
* \brief The SHA2-512 hash size in bytes
*/
#define SHA2_512_HASH_SIZE 64

/*!
* \def SHA2_256_RATE
* \brief The SHA-256 byte absorption rate
*/
#define SHA2_256_RATE 64

/*!
* \def SHA2_512_RATE
* \brief The SHA2-512 byte absorption rate
*/
#define SHA2_512_RATE 128

/*!
* \def SHA2_STATE_SIZE
* \brief The SHA2-256 state array size
*/
#define SHA2_STATE_SIZE 8

/*!
* \def SHA2_STATE_SIZE
* \brief The SHA2-256 state array size
*/
#define SHA2_STATE_SIZE 8

/* HMAC-256 */

/*!
* \struct sha256_state
* \brief The SHA2-256 digest state array
*/
RHX_EXPORT_API typedef struct
{
	uint32_t state[SHA2_STATE_SIZE];	/*!< The SHA2-256 state  */
	uint8_t buffer[HMAC_256_RATE];		/*!< The message buffer  */
	uint64_t t;							/*!< The message length  */
	size_t position;					/*!< The cache position  */
} sha256_state;

/**
* \brief Process a message with SHA2-256 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
RHX_EXPORT_API void sha256_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Dispose of the SHA2-256 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
RHX_EXPORT_API void sha256_dispose(sha256_state* ctx);

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 32-byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
RHX_EXPORT_API void sha256_finalize(sha256_state* ctx, uint8_t* output);

/**
* \brief Initializes a SHA2-256 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
RHX_EXPORT_API void sha256_initialize(sha256_state* ctx);

/**
* \brief The SHA2-256 permutation function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Absorbs a message and permutes the state array.
*
* \param output: The function output; must be initialized
* \param input: [const] The input message byte array
*/
RHX_EXPORT_API void sha256_permute(uint32_t* output, const uint8_t* input);

/**
* \brief Update SHA2-256 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of message input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
RHX_EXPORT_API void sha256_update(sha256_state* ctx, const uint8_t* message, size_t msglen);

/*!
* \struct hmac256_state
* \brief The HMAC(SHA2-256) state array
*/
RHX_EXPORT_API typedef struct
{
	sha256_state pstate;			/*!< The SHA2-256 state  */
	uint8_t ipad[HMAC_256_RATE];	/*!< The input pad array  */
	uint8_t opad[HMAC_256_RATE];	/*!< The output pad array  */
} hmac256_state;

/**
* \brief Process a message with HMAC(SHA2-256) and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
RHX_EXPORT_API void hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Dispose of the HMAC-256 state.
* This function destroys the internal state of the MAC.
*
* \param ctx: [struct] The cipher state structure
*/
RHX_EXPORT_API void hmac256_dispose(hmac256_state* ctx);

/**
* \brief Finalize the HMAC-256 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
RHX_EXPORT_API void hmac256_finalize(hmac256_state* ctx, uint8_t* output);

/**
* \brief Initializes an HMAC-256 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
RHX_EXPORT_API void hmac256_initialize(hmac256_state* ctx, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-256 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
RHX_EXPORT_API void hmac256_update(hmac256_state* ctx, const uint8_t* message, size_t msglen);

/* HMAC-512 */

/*!
* \struct sha512_state
* \brief The SHA2-512 digest state array
*/
RHX_EXPORT_API typedef struct
{
	uint64_t state[SHA2_STATE_SIZE];	/*!< The SHA2-512 state  */
	uint64_t t[2];							/*!< The message length  */
	uint8_t buffer[HMAC_512_RATE];		/*!< The message buffer  */
	size_t position;						/*!< The cache position  */
} sha512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
RHX_EXPORT_API void sha512_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Dispose of the SHA2-512 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
RHX_EXPORT_API void sha512_dispose(sha512_state* ctx);

/**
* \brief Finalize the message state and returns the SHA2-512 hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
RHX_EXPORT_API void sha512_finalize(sha512_state* ctx, uint8_t* output);

/**
* \brief Initializes a SHA2-512 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
RHX_EXPORT_API void sha512_initialize(sha512_state* ctx);

/**
* \brief The SHA2-512 permutation function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Absorbs a message and permutes the state array.
*
* \param output: The function output; must be initialized
* \param input: [const] The input message byte array
*/
RHX_EXPORT_API void sha512_permute(uint64_t* output, const uint8_t* input);

/**
* \brief Update SHA2-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
RHX_EXPORT_API void sha512_update(sha512_state* ctx, const uint8_t* message, size_t msglen);

/*!
* \struct hmac512_state
* \brief The HMAC(SHA2-512) state array
*/
RHX_EXPORT_API typedef struct
{
	sha512_state pstate;			/*!< The SHA2-512 state  */
	uint8_t ipad[HMAC_512_RATE];	/*!< The input pad array  */
	uint8_t opad[HMAC_512_RATE];	/*!< The output pad array  */
} hmac512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 128 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
RHX_EXPORT_API void hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Dispose of the HMAC-512 state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
RHX_EXPORT_API void hmac512_dispose(hmac512_state* ctx);

/**
* \brief Finalize the HMAC-512 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
RHX_EXPORT_API void hmac512_finalize(hmac512_state* ctx, uint8_t* output);

/**
* \brief Initializes an HMAC-512 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
RHX_EXPORT_API void hmac512_initialize(hmac512_state* ctx, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-512 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
RHX_EXPORT_API void hmac512_update(hmac512_state* ctx, const uint8_t* message, size_t msglen);

/* HKDF */

/**
* \brief Initialize an instance of HKDF(HMAC(SHA2-256)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
RHX_EXPORT_API void hkdf256_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-256).
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
RHX_EXPORT_API void hkdf256_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

/**
* \brief Initialize an instance of HKDF(HMAC(SHA2-512)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
RHX_EXPORT_API void hkdf512_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-512).
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
RHX_EXPORT_API void hkdf512_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

#endif
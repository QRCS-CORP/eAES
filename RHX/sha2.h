/**
* \file sha2.h
* \brief <b>SHA2 header definition</b> \n
* Contains the public api and documentation for SHA3 digest and SHAKE implementations.
*
* \author John Underhill
* \date May 23, 2019
* \remarks For usage examples, see sha3_kat.h
*/

#ifndef QCX_SHA2_H
#define QCX_SHA2_H

#include "common.h"

/*!
\def SHA2_256_ROUNDS
* the number of rounds in the compact SHA2-256 permutation
*/
#define SHA2_256_ROUNDS 64

/*!
\def SHA2_384_ROUNDS
* the number of rounds in the compact SHA2-384 permutation
*/
#define SHA2_384_ROUNDS 80

/*!
\def SHA2_512_ROUNDS
* the number of rounds in the compact SHA2-512 permutation
*/
#define SHA2_512_ROUNDS 80

/*!
\def SHA2_256_SIZE
* The SHA2-256 hash size in bytes
*/
#define SHA2_256_SIZE 32

/*!
\def SHA2_384_SIZE
* The SHA2-384 hash size in bytes
*/
#define SHA2_384_SIZE 48

/*!
\def SHA2_512_SIZE
* The SHA2-512 hash size in bytes
*/
#define SHA2_512_SIZE 64

/*!
\def SHA2_256_RATE
* The SHA-256 byte absorption rate
*/
#define SHA2_256_RATE 64

/*!
\def SHA2_384_RATE
* The SHA2-384 byte absorption rate
*/
#define SHA2_384_RATE 128

/*!
\def SHA2_512_RATE
* The SHA2-512 byte absorption rate
*/
#define SHA2_512_RATE 128

/*!
\def SHA2_256_STATESIZE
* The SHA2-256 state array size
*/
#define SHA2_STATESIZE 8

/* SHA2-256 */

typedef struct
{
	uint32_t state[8];
	uint64_t t;
} sha256_state;

/**
* \brief Process a message with SHA2-256 and returns the hash code in the output byte array.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
void sha256_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA2-256 with blocks of input.
* Absorbs a multiple of 64-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void sha256_blockupdate(sha256_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the hash value in output.
* Absorb the last block of message and creates the hash value. \n
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void sha256_finalize(sha256_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a SHA2-256 state structure, must be called before message processing.
*
* \param state: [struct] The function state
*/
void sha256_initialize(sha256_state* state);

/**
* \brief The SHA2-256 permution function.
* Permutes the state array.
*
* \param output: The function state; must be initialized
* \param input: [const] The input message byte array
*/
void sha256_permute(uint32_t* output, const uint8_t* input);

/* SHA2-384 */

typedef struct
{
	uint64_t state[8];
	uint64_t t[2];
} sha384_state;

/**
* \brief Process a message with SHA2-384 and returns the hash code in the output byte array.
*
* \warning The output array must be at least 48 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
void sha384_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA2-384 with blocks of input.
* Absorbs a multiple of 128-byte block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message:[const] The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
void sha384_blockupdate(sha384_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the SHA2-384 hash value in output.
* Absorb the last block of message and creates the hash value. \n
* Produces a 48 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void sha384_finalize(sha384_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a SHA2-384 state structure, must be called before message processing.
*
* \param state: [struct] The function state
*/
void sha384_initialize(sha384_state* state);

/**
* \brief The SHA2-384 permution function.
* Permutes the state array.
*
* \param state: The function state; must be initialized
* \param message: [const] The input message byte array
*/
void sha384_permute(uint64_t* output, const uint8_t* input);

/* SHA2-512 */

typedef struct
{
	uint64_t state[8];
	uint64_t t[2];
} sha512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
void sha512_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA2-512 with blocks of input.
* Absorbs a multiple of 128-byte block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message:[const] The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
void sha512_blockupdate(sha512_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the SHA2-512 hash value in output.
* Absorb the last block of message and creates the hash value. \n
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void sha512_finalize(sha512_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a SHA2-512 state structure, must be called before message processing.
*
* \param state: [struct] The function state
*/
void sha512_initialize(sha512_state* state);

/**
* \brief The SHA2-512 permution function.
* Permutes the state array.
*
* \param state: The function state; must be initialized
* \param message: [const] The input message byte array
*/
void sha512_permute(uint64_t* output, const uint8_t* input);

/* HMAC-256 */

typedef struct
{
	sha256_state pstate;
	uint8_t ipad[SHA2_256_RATE];
	uint8_t opad[SHA2_256_RATE];
} hmac256_state;

/**
* \brief Process a message with HMAC(SHA2-256) and returns the hash code in the output byte array.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-256 with blocks of input.
* Absorbs a multiple of 64-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void hmac256_blockupdate(hmac256_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the HMAC-256 message state and return the hash value in output.
* Absorb the last block of message and creates the hash value. \n
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void hmac256_finalize(hmac256_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a HMAC-256 state structure with a key, must be called before message processing.
*
* \param state: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac256_initialize(hmac256_state* state, const uint8_t* key, size_t keylen);

/* HMAC-512 */

typedef struct
{
	sha512_state pstate;
	uint8_t ipad[SHA2_512_RATE];
	uint8_t opad[SHA2_512_RATE];
} hmac512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
*
* \warning The output array must be at least 128 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-512 with blocks of input.
* Absorbs a multiple of 128-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void hmac512_blockupdate(hmac512_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the HMAC-512 message state and return the hash value in output.
* Absorb the last block of message and creates the hash value. \n
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void hmac512_finalize(hmac512_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a HMAC-512 state structure with a key, must be called before message processing.
*
* \param state: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac512_initialize(hmac512_state* state, const uint8_t* key, size_t keylen);

/* HKDF */

/**
* \brief Initialize and instance of HKDF(HMAC(SHA2-256)), and output an array of pseudo-random.
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
void hkdf256_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Initialize and instance of HKDF(HMAC(SHA2-512)), and output an array of pseudo-random.
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
void hkdf512_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

#endif


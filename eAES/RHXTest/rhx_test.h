
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

#ifndef QSCTEST_RHX_TEST_H
#define QSCTEST_RHX_TEST_H

/**
* \file rhx_test.h
* \brief <b>AESand RHX Known Answer Tests</b> \n
* Rijndael known answer comparison (KAT) tests. \n
* The AES test vectors are from the NIST standard tests contained in AES specification document, Appendix C. \n
* FIPS 197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard</a>. \n
* New vectors have been added for the extended modes RSX/RHX-256 and RSX/RHX-512, are from the CEX cryptographic library, reference: 
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptographic library</a>
* \author John Underhill
* \date October 12, 2020
* \updated December 05, 2020
*/

#include "common.h"
#include "rhx.h"

#if defined(SYSTEM_AESNI_ENABLED) 
#	if defined(SYSTEM_HAS_AVX512)
#		define RHX_WIDE_BLOCK_TESTS
#	endif
#endif

/**
* \brief Tests the CBC 128bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool qsctest_fips_aes128_cbc();

/**
* \brief Tests the CBC 256-bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool qsctest_fips_aes256_cbc();

/**
* \brief Tests the CTR 128bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool qsctest_fips_aes128_ctr();

/**
* \brief Tests the CTR 128bit key KAT vectors from NIST SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool qsctest_fips_aes256_ctr();

/**
* \brief Tests the ECB mode 128bit key KAT vectors from NIST FIPS197 and SP800-85a
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Fips197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard, Appendix C.1</a>
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool qsctest_fips_aes128_ecb();

/**
* \brief Tests the ECB 256-bit key KAT vectors from NIST FIPS197 and SP800-85a.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Fips197: <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">The Advanced Encryption Standard, Appendix C.3</a>
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>
*/
bool qsctest_fips_aes256_ecb();

/**
* \brief Tests the counter mode; CTR(RHX-256) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx256_ctr_stress();

/**
* \brief Tests the cipher block chaining mode; CBC(RHX-256) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx256_cbc_stress();

/**
* \brief Tests Tests the cipher block chaining mode; CBC(RHX-512) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx512_cbc_stress();

/**
* \brief Tests the counter mode; CTR(RHX-512) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx512_ctr_stress();

#if defined(RHX_WIDE_BLOCK_TESTS)

/**
* \brief Tests the AVX-512 big-endian counter mode; CTR(RHX-256) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx256_ctrbe_wide_equality();

/**
* \brief Tests the AVX-512 big-endian counter mode; CTR(RHX-512) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx512_ctrbe_wide_equality();

/**
* \brief Tests the AVX-512 little-endian counter mode; CTR(RHX-256) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx256_ctrle_wide_equality();

/**
* \brief Tests the AVX-512 little-endian counter mode; CTR(RHX-512) for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx512_ctrle_wide_equality();

#endif

/**
* \brief Tests the RSX/RHX 256-bit key KAT vectors from CEX.
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptrographic library</a>
* If RHX_SHAKE_EXTENSION is defined (default) the cSHAKE extension is tested, if it is not defined, reverts to the HKDF(SHA2) extension.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors generated by the CEX library implementation</a>
*/
bool qsctest_rhx256_ecb_kat();

/**
* \brief Tests the RSX/RHX 512-bit key KAT vectors from CEX.
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptrographic library</a>
* If RHX_SHAKE_EXTENSION is defined in rhx.h (default) the cSHAKE extension is tested, if it is not defined, reverts to the HKDF(SHA2) extension.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors generated by the CEX library implementation</a>
*/
bool qsctest_rhx512_ecb_kat();

/**
* \brief Tests the RSX/RHX 256-bit key Monte Carlo vectors from CEX.
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptrographic library</a>
* If RHX_SHAKE_EXTENSION is defined (default) the cSHAKE extension is tested, if it is not defined, reverts to the HKDF(SHA2) extension.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors generated by the CEX library implementation</a>
*/
bool qsctest_rhx256_monte_carlo();

/**
* \brief Tests the RSX/RHX 512-bit key Monte Carlo vectors from CEX.
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptrographic library</a>
* If RHX_SHAKE_EXTENSION is defined in rhx.h (default) the cSHAKE extension is tested, if it is not defined, reverts to the HKDF(SHA2) extension.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors generated by the CEX library implementation</a>
*/
bool qsctest_rhx512_monte_carlo();

/**
* \brief Tests the Hash Based Authentication (HBA-RSX/RHX) AEAD mode using 256-bit key KAT vectors from CEX.
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptrographic library</a>
* If RHX_SHAKE_EXTENSION is defined in rhx.h (default) the cSHAKE extension is tested, if it is not defined, reverts to the HKDF(SHA2) extension.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors generated by the CEX library implementation</a>
*/
bool qsctest_hba_rhx256_kat();

/**
* \brief Tests the Hash Based Authentication (HBA-RSX/RHX) AEAD mode using 512-bit key KAT vectors from CEX.
* The C++ <a href="https://github.com/Steppenwolfe65/CEX">CEX cryptrographic library</a>
* If RHX_SHAKE_EXTENSION is defined in rhx.h (default) the cSHAKE extension is tested, if it is not defined, reverts to the HKDF(SHA2) extension.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* The test uses use original (and authoritative) vectors generated by the CEX library implementation</a>
*/
bool qsctest_hba_rhx512_kat();

/**
* \brief Tests the HBA-RHX256 AEAD mode for correct operation.
*
* \return Returns true for success
*/
bool qsctest_hba_rhx256_stress();

/**
* \brief Tests the HBA-RHX512 AEAD mode for correct operation.
*
* \return Returns true for success
*/
bool qsctest_hba_rhx512_stress();

/**
* \brief Tests the padding functions for correct operation.
*
* \return Returns true for success
*/
bool qsctest_rhx_padding_test();

/**
* \brief Run the set of FIPS 197 AES tests
*/
void qsctest_aes_run();

/**
* \brief Run the set of extended AES (RHX) tests
*/
void qsctest_rhx_run();

#endif

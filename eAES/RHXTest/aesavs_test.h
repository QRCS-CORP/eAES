
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

#ifndef QSCTEST_AESAVS_TEST_H
#define QSCTEST_AESAVS_TEST_H

#include "common.h"
/**
* \file aesavs_test.h
* \brief AES Known Answer Tests \n
* Rijndael known answer comparison (KAT) tests. \n
* The AES AVS test vectors set. \n
* \author John Underhill
* \date October 12, 2020
* \updated December 05, 2020
*/

/**
* \brief Tests the CBC 128 and 256-bit key and text KAT vectors from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS KAT CBC 6.2</a>
*/
bool aesavs_cbc_kat(void);

/**
* \brief Tests the ECB 128 and 256-bit key and text KAT vectors from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS KAT ECB 6.2</a>
*/
bool aesavs_ecb_kat(void);

/**
* \brief Tests the CBC 128 and 256-bit key monte-carlo tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS MCT 6.4.2 CBC</a>
*/
bool aesavs_cbc_mct(void);

/**
* \brief Tests the ECB 128 and 256-bit key monte-carlo tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS 6.4.1 ECB</a>
*/
bool aesavs_ecb_mct(void);

/**
* \brief Tests the CBC 128 and 256-bit key multi-block message tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS 6.3 CBC</a>
*/
bool aesavs_cbc_mmt(void);

/**
* \brief Tests the ECB 128 and 256-bit key monte-carlo multi-block message tests from NIST AESAVS.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* NIST <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf">AESAVS 6.3 ECB</a>
*/
bool aesavs_ecb_mmt(void);

/**
* \brief Run the set of extended AESAVS test set
*/
void qsctest_aesavs_run(void);

#endif

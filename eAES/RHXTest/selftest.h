
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

#ifndef QSCTEST_SELFTEST_H
#define QSCTEST_SELFTEST_H

#include "common.h"

/**
* \brief Tests the RHX cipher, CTR, CBC, ECB and HBA modes for correct operation.
*
* \return Returns true for success
*/
RHX_EXPORT_API bool qsctest_rhx_test();

/**
* \brief Tests the SHA2 digests, HKDF and HMAC for correct operation.
*
* \return Returns true for success
*/
RHX_EXPORT_API bool qsctest_sha2_test();

/**
* \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
*
* \return Returns true for success
*/
RHX_EXPORT_API bool qsctest_sha3_test();

/**
* \brief Runs the library self tests.
*
* \return Returns true if all tests pass successfully
*/
RHX_EXPORT_API bool qsctest_selftest_run();

#endif
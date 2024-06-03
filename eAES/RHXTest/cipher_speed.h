
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

#ifndef QSCTEST_CIPHER_SPEED_H
#define QSCTEST_CIPHER_SPEED_H

/**
* \file cipher_speed.h
* \brief <b>AES and RHX performance benchmarking</b> \n
* Tests the CBC, CTR, AND HBA modes for timimng performance.
* \author John Underhill
* \date October 12, 2020
*/

#include "common.h"

/**
* \brief Tests the RHX implementations performance.
* Tests the AEX; CBC, CTR, and HBA modes for performance timing.
*/
void qsctest_aes_speed_run();

/**
* \brief Tests the RHX implementations performance.
* Tests the RHX; CBC, CTR, and HBA modes for performance timing.
*/
void qsctest_rhx_speed_run();

#endif
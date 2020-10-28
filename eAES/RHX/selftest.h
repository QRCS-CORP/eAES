#ifndef QSCTEST_SELFTEST_H
#define QSCTEST_SELFTEST_H

#include "common.h"

/**
* \brief Tests the RHX cipher, CTR, CBC, ECB and HBA modes for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_rhx_test();

/**
* \brief Tests the SHA2 digests, HKDF and HMAC for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_sha2_test();

/**
* \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_sha3_test();

/**
* \brief Runs the library self tests.
*
* \return Returns true if all tests pass successfully
*/
QSC_EXPORT_API bool qsctest_selftest_run();

#endif
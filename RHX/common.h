#ifndef QCC_COMMON_H
#define QCC_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*! \enum mqc_status
* Contains state and error return codes
*/
typedef enum
{
	QCX_STATUS_SUCCESS = 0,		/*!< signals operation success */
	QCX_STATUS_FAILURE = -1,	/*!< signals operation failure */
	QCX_STATUS_AUTHFAIL = -2,	/*!< seed authentication failure */
	QCX_STATUS_RANDFAIL = -3,	/*!< system random failure */
	QCX_ERROR_INVALID = -4,		/*!< invalid parameter input */
	QCX_ERROR_INTERNAL = -5,	/*!< anonymous internal failure  */
	QCX_ERROR_KEYGEN = -6		/*!< key generation failure  */
} mqc_status;

#endif

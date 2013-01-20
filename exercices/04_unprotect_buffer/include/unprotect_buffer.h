#ifndef _UNPROTECT_FILE_H
#define _UNPROTECT_FILE_H

 #include "../include/deriv_passwd.h"
 #include "../include/unprotect_buffer.h"
 #include "../include/polarssl/sha2.h"
 #include "../include/polarssl/aes.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

/**
 * @param [out] output        plain text buffer
 * @param [out] output_len    plain text buffer length in bytes
 * @param [in]  input         ciphered text buffer
 * @param [in]  input_len     ciphered text buffer length in bytes
 * @param [in]  passwd        user password
 * @param [in]  salt          salt
 * @param [in]  salt_len      salt length in bytes
 * @param [in]  iterations    number of iterations
 * @return      0 if OK, 1 else
 */

int unprotect_buffer(unsigned char **output, int *output_len,
		unsigned char *input, int input_len,
		char *password,
		unsigned char *salt, int salt_len,
		unsigned int iterations);

#endif

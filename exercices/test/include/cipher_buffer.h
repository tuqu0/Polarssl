#ifndef _CIPHER_BUFFER_
#define _CIPHER_BUFFER_

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include "polarssl/aes.h"
 #include "polarssl/havege.h"
 #include "polarssl/rsa.h"

 /**
   * @param [out] output	cipher text buffer
   * @param [out] output_len	cipher text buffer length in bytes
   * @param [in]  input		ciphered text buffer
   * @param [in]  input_len 	ciphered text buffer length in bytes
   * @param [in]  key		symetric key (16 bytes)
   * @return	  0 if OK, 1 else
   */
 int cipher_buffer(unsigned char **ouput, int *output_len,
		   unsigned char *input, int input_len,
	           char *pub_key_file, unsigned char *key);

#endif /* _CIPHER_BUFFER_ */

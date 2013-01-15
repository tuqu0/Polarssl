#ifndef _DECIPHER_BUFFER_
#define _DECIPHER_BUFFER_

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
   * @param [in]  pri_key_file	private parameters file
   * @return	  0 if OK, 1 else
   */
 int decipher_buffer(unsigned char **ouput, int *output_len,
     		     unsigned char *input, int input_len,
	             char *pri_key_file);

#endif /* _DECIPHER_BUFFER_ */

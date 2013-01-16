#ifndef _CIPHER_BUFFER_H_
#define _CIPHER_BUFFER_H_
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include "polarssl/aes.h"
 #include "polarssl/havege.h"
 #include "polarssl/rsa.h"

 int cipher_buffer(unsigned char **output, int *output_len,
                   unsigned char *input, int input_len,
                   char *public_key, unsigned char *key);
  
#endif /* _CIPHER_BUFFER_H_ */

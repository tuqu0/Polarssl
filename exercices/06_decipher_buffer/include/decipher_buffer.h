#ifndef _DECIPHER_BUFFER_H_
#define _DECIPHER_BUFFER_H_

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include "../include/polarssl/aes.h"
 #include "../include/polarssl/rsa.h"

 int decipher_buffer(unsigned char **output, int *output_len,
		     unsigned char *input, int input_len,
                     char *priv_key_file);

#endif /* _DECIPHER_BUFFER_H_ */

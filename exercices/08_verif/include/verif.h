#ifndef _SIGN_H_
#define _SIGN_H_
 
 #include "polarssl/rsa.h"
 #include "polarssl/sha2.h"
 #include "polarssl/havege.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

 int verif(unsigned char *sign, unsigned char *input, int input_len,
	   char *pub_key_file);

#endif /* _SIGN_H_ */

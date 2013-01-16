#ifndef _GEN_KEYRSA_
#define _GEN_KEY_RSA_

 #include <stdio.h>
 #include "polarssl/bignum.h"
 #include "polarssl/config.h"
 #include "polarssl/ctr_drbg.h"
 #include "polarssl/entropy.h"
 #include "polarssl/rsa.h"
 #include "polarssl/x509.h"

 #define KEY_LEN 1024
 #define EXPONENT 65537

 int gen_keyRSA(char *public_key, char *private_key);

#endif /* _GEN_KEY_RSA_ */

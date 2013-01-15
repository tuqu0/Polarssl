#ifndef _GEN_KEY_H
#define _GEN_KEY_H

 #include "polarssl/havege.h"
 #include <string.h>

 int gen_key(unsigned char *key, int key_length);

#endif

#include "../include/gen_key.h"
#include "../include/polarssl/havege.h"
#include <string.h>

int gen_key(unsigned char *key, int key_length)
{
	int ret;
	havege_state ctx;

	ret = 1; 

	/* *** check argument *** */
	if((key == NULL) || (key_length <= 0))
		goto cleanup;

	havege_init(&ctx);

	ret = havege_random(&ctx, key, key_length);
cleanup:
	memset(&ctx, 0x00, sizeof(havege_state));
	return ret;
}

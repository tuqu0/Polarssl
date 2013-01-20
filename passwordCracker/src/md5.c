#include "../include/md5.h"

char* crypt_md5(const char *pw, const char *salt, size_t rounds)
{
	md5_context ctx,ctx1;
	unsigned long l;
	int sl, pl, out_len;
	u_int i;
	u_char final[MD5_SIZE];
	const char *sp, *ep;
	char passwd[120], *p;
	const char *magic = "$1$";
	char *output;

	/* Refine the Salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	if(!strncmp(sp, magic, strlen(magic)))
		sp += strlen(magic);

	/* It stops at the first '$', max 8 chars */
	for(ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
		continue;

	/* get the length of the true salt */
	sl = ep - sp;
	md5_starts(&ctx);

	/* The password first, since that is what is most unknown */
	md5_update(&ctx, (unsigned char*)pw, strlen(pw));

	/* Then our magic string */
	md5_update(&ctx, (unsigned char*)magic, strlen(magic));

	/* Then the raw salt */
	md5_update(&ctx, (unsigned char*)sp, (u_int)sl);

	/* Then just as many characters of the MD5(pw,salt,pw) */
	md5_starts(&ctx1);
	md5_update(&ctx1, (unsigned char*)pw, strlen(pw));
	md5_update(&ctx1, (unsigned char*)sp, (u_int)sl);
	md5_update(&ctx1, (unsigned char*)pw, strlen(pw));
	md5_finish(&ctx1, final);
	for(pl = (int)strlen(pw); pl > 0; pl -= MD5_SIZE)
		md5_update(&ctx, (unsigned char*)final,
		    (u_int)(pl > MD5_SIZE ? MD5_SIZE : pl));

	/* Don't leave anything around in vm they could use. */
	memset(final, 0, sizeof(final));

	/* Then something really weird... */
	for (i = strlen(pw); i; i >>= 1)
		if(i & 1)
		    md5_update(&ctx, (unsigned char*)final, 1);
		else
		    md5_update(&ctx, (unsigned char*)pw, 1);

	/* Now make the output string */
	strcpy(passwd, magic);
	strncat(passwd, sp, (u_int)sl);
	strcat(passwd, "$");

	md5_finish(&ctx, final);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i = 0; i < rounds; i++) {
		md5_starts(&ctx1);
		if(i & 1)
			md5_update(&ctx1, (unsigned char*)pw, strlen(pw));
		else
			md5_update(&ctx1, (unsigned char*)final, MD5_SIZE);

		if(i % 3)
			md5_update(&ctx1, (unsigned char*)sp, (u_int)sl);

		if(i % 7)
			md5_update(&ctx1, (unsigned char*)pw, strlen(pw));

		if(i & 1)
			md5_update(&ctx1, (unsigned char*)final, MD5_SIZE);
		else
			md5_update(&ctx1, (unsigned char*)pw, strlen(pw));
		md5_finish(&ctx1, final);
	}

	p = passwd + strlen(passwd);

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12];
	_crypt_to64(p, l, 4); p += 4;
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13];
	_crypt_to64(p, l, 4); p += 4;
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14];
	_crypt_to64(p, l, 4); p += 4;
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15];
	_crypt_to64(p, l, 4); p += 4;
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5];
	_crypt_to64(p, l, 4); p += 4;
	l = final[11];
	_crypt_to64(p, l, 2); p += 2;
	*p = '\0';

	out_len = strlen(passwd) - sl - sizeof(magic);
	output = (char *) malloc(out_len + 1);
	if (output == NULL)
	{
		fprintf(stderr, "error : memory allocation failed\n");
		return NULL;		
	}
	strncpy(output, passwd + sizeof(magic) + sl, out_len);
	output[out_len] = '\0';

	return (output);
}

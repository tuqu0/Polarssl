#include "../include/crack.h"

bool crack(const char *shadow, MODE mode, const char *dico)
{
    int ret;
    FILE *f;

    /* *** Init *** */
    ret = 1;
    f = NULL;

    /* *** Check parameters *** */
    if (mode == DICO && dico == NULL)
        goto exit;
    if (shadow == NULL)
        goto exit;

    /* *** Read shadow file *** */
    f = fopen(shadow, "r");
    if (f == NULL)
    {
        fprintf(stderr, "error : unable to open %s\n", shadow);
        goto exit;
    }

exit:
    if (f != NULL)
        fclose(f);
    return ret;
}

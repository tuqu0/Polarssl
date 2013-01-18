#include "../include/main.h"

int main(int argc, char **argv)
{
    int opt;
    MODE mode;
    char *shadow, *dico;

    /* *** Init *** */
    shadow = NULL;
    dico = NULL;

    /* *** Options parser *** */
    while ((opt = getopt(argc, argv, "bd:f:")) != EOF)
    {
        switch (opt)
        {
            case 'b':
                mode = BRUTE_FORCE;
                break;                 
            case 'd':
                mode = DICO;
                dico = optarg;
                break;
            case 'f':
                shadow = optarg;
                break;
            case '?':
                mode = BRUTE_FORCE;
                break;
        }
    }

    /* *** Check parameters *** */
    if (argc < 3 || shadow == NULL) 
    {
        usage(argv[0]);
        goto exit;
    }

    /* *** Cracking *** */
    crack(shadow, mode, dico);

exit:
    return 0;
}

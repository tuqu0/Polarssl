#include "../include/main.h"

int main(int argc, char **argv)
{
    int opt;
    bool ret;
    MODE mode;
    char *shadow, *dico;
    
    /* *** Init *** */
    ret = false;
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
        ret = false;
        goto exit;
    }

    /* *** Cracking *** */
    ret = crack(shadow, mode, dico);

exit:
    return ret;
}

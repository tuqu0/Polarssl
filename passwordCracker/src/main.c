#include "../include/main.h"

int main(int argc, char **argv)
{
    int opt, bruteforce_len;
    MODE mode;
    char *shadow, *dico;

    /* *** Init *** */
    bruteforce_len = 0;
    shadow = NULL;
    dico = NULL;

    /* *** Options parser *** */
    while ((opt = getopt(argc, argv, "b:d:f:")) != EOF)
    {
        switch (opt)
        {
            case 'b':
                mode = BRUTE_FORCE;
                if ((bruteforce_len = atoi(optarg)) == 0)
                {
                    fprintf(stderr, "error : invalid length\n");
                    usage(argv[0]);
                    goto exit;
                }
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
        }
    }

    /* *** Check parameters *** */

    if (argc < 4 || shadow == NULL) 
    {
        usage(argv[0]);
        goto exit;
    }

    /* *** Cracking *** */
    crack(shadow, mode, dico, bruteforce_len);

exit:
    return 0;
}

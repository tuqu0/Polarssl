#include "../include/utils.h"

void usage(char *program)
{
    printf("usage : %s -f <shadow> [-b] [-f <dico>]\n", program);
    printf("-d <shadow>  fichier à cracker (/etc/shadow)\n");
    printf("-b           mode brute force (par défaut)\n");
    printf("-d <dico>    mode dictionnaire\n");
}

#include "../include/utils.h"

void usage(char *program)
{
    fprintf(stderr, "usage : %s -f <shadow> [-b] [-f <dico>]\n", program);
    fprintf(stderr, "-f <shadow>  fichier à cracker (/etc/shadow)\n");
    fprintf(stderr, "-b           mode brute force (par défaut)\n");
    fprintf(stderr, "-d <dico>    mode dictionnaire\n");
}

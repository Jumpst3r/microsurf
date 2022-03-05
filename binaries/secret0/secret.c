#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    int secret = atoi(argv[1]);
    int *T= malloc(2000 * sizeof(int));
    int val = T[secret];
    //printf("%c\n", val);
    return (int) val;
}
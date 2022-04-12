#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>
//https://stackoverflow.com/questions/523724/c-c-check-if-one-bit-is-set-in-i-e-int-variable
#define CHECK_BIT(var,pos) !!((var) & (1<<(pos)))

int main(int argc, char *argv[]) {
    uint64_t secret = strtoul(argv[1], NULL, 16);
    int *T= malloc(100 * sizeof(int));
    int nbits = sizeof(secret) * 8;
    int bval4 = CHECK_BIT(secret, 4);
    int bval5 = CHECK_BIT(secret, 5);
    int bval6 = CHECK_BIT(secret, 6);
    for(int i = 0; i < 1; i++){
        int val = T[i + (bval5 ^ bval4 ^ bval6)];
    }
    return 0;
}
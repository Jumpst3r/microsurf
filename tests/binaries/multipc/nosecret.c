#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    // even atoi causes a secret dep. mem access
    int secret = atoi(argv[1]);
    int i = 0;
    int val3 = 0;
    int *T= malloc(100 * sizeof(int));
    for (i; i < 10; i++){
        val3 = T[secret + i];
    }
    
    free(T);
    return val3;
}
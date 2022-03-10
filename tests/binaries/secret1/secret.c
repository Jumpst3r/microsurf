#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    int secret = atoi(argv[1]);
    int val = -1;
    int val2 = 0;
    int *T= malloc(10 * sizeof(int));
    int *M= malloc(800 * sizeof(int));

    int randomData = open("/dev/urandom", O_RDONLY);
   
    char myRandomData[50];
    char rndchar = 'x';
    read(randomData, myRandomData, sizeof myRandomData);

    // get the first printable character from rnd stream
    for (size_t i = 0; i < 50; i++){
        if(isprint(myRandomData[i])){
            rndchar = myRandomData[i];
        }
    }

    //secret dependent access:
    int branch = (int) rndchar;
    if (branch > 50){
        val = T[secret + (branch % 20)];
    }
    
    // random memory access
    val2 = M[branch];
    close(randomData);
    free(T);
    free(M);
    return val;
}
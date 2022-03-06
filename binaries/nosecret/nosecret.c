#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    // even atoi causes a secret dep. mem access
    //int secret = atoi(argv[1]);
    int myint = atoi("23");
    int val = -1;
    int val2 = 0;
    int *T= malloc(10 * sizeof(int));
    int *M= malloc(800 * sizeof(int));

    int randomData = open("/dev/urandom", O_RDONLY);
    char myRandomData[50];
    char rndchar = 'x';
    read(randomData, myRandomData, sizeof myRandomData);
    for (size_t i = 0; i < 50; i++){
        if(isprint(myRandomData[i])){
            rndchar = myRandomData[i];
        }
    }
    int b = (int) rndchar;

    // random memory access
    val2 = M[b];
    // some more random access
    for (size_t i = 0; i < 5; i++)
    {
        val2 += M[b + i];
    }

    if (b > 4){
        val2 += M[b % 10 ];
        if (b < 400){
            val2 += M[b % 200];
        }
    }
    
    free(T);
    free(M);
    return val2;
}
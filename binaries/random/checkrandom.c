#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

int main(int argc, char *argv[]) {

    int randomData = open("/dev/urandom", O_RDONLY);
    if (!randomData){
        printf("Failed to open /dev/urandom !");
        exit(1);
    }

    // read 10 integers, if we always get the same result - we (likely) succeeded in controlling randomness
    int res = 0;
    int prev = 0;
    for (int i = 0; i < 10; i++){
        char myRandomData[50];
        char rndchar = 'x';
        read(randomData, myRandomData, sizeof myRandomData);

        // get the first printable character from rnd stream
        for (size_t i = 0; i < 50; i++){
            if(isprint(myRandomData[i])){
                rndchar = myRandomData[i];
            }
        }
        // if randomness is fixed, this should always give 34
        int randint = (int) rndchar;
        if (randint == prev){
            res++;
        }
        prev = randint;
    }

    if (res < 5){
        printf("FAIL\n");
    }
    close(randomData);
    return 0;
}
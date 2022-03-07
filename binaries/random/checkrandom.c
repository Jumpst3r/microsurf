#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>

int main(int argc, char *argv[]) {
    int randomData = open("/dev/urandom", O_RDONLY);
    if (!randomData){
        printf("Failed to open /dev/urandom !");
        exit(1);
    }

    

    // read 10 integers, if we always get the same result - we (likely) succeeded in controlling randomness
    int res = 0;
    int res2 = 0;
    int res3 = 0;
    int prev = 0;
    int prev2 = 0;
    int prev3 = 0;
    for (int i = 0; i < 10; i++){
        char myRandomData[50];
        char rndchar = 'x';
        read(randomData, myRandomData, sizeof myRandomData);
        struct timespec start;
        clock_gettime(CLOCK_MONOTONIC, &start);
        // get the first printable character from rnd stream
        for (size_t i = 0; i < 50; i++){
            if(isprint(myRandomData[i])){
                rndchar = myRandomData[i];
            }
        }
        int randint = (int) rndchar;
        // if we don't intercept time syscalls, this should give a different
        // seed at each loop iteration, resulting in different random numbers
        srand(time(NULL));  
        int r = rand();
        if (start.tv_sec == prev3){
            res3++;
        }
        if (r == prev2){
            res2++;
        }
        if (randint == prev){
            res++;
        }
        prev = randint;
        prev2 = r;
        prev3 = start.tv_sec;
    }

    if (res < 5){
        printf("FAIL\n");
    }
    if (res2 < 5){
        printf("FAIL\n");
    }
    if (res3 < 5){
        printf("FAIL\n");
    }
    close(randomData);
    return 0;
}
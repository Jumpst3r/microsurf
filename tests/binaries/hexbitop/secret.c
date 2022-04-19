#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>
//https://stackoverflow.com/questions/523724/c-c-check-if-one-bit-is-set-in-i-e-int-variable
#define CHECK_BIT(var,pos) !!((var) & (1<<(pos)))


int someFunction(int value){
  for (int i = 0; i < 10; i++){
    value += 1;
  }
  return value;
}

int commonfct(int i){
  printf("some text\n");
  return 0;
}

int main(int argc, char *argv[]) {
    uint64_t secret = strtoul(argv[1], NULL, 16);
    int nbits = sizeof(secret) * 8;
    if (CHECK_BIT(secret, 4)){
        int someVal = 20;
        someFunction(someVal);
      }
    return commonfct(10);
}

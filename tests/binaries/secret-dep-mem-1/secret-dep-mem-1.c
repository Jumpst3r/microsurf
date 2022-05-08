#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>

int otherFct(int val){
  for (int i = 0; i < 4; i++){
    val += 3;
    if (val > 3) break;
  }
  return val+1;
}

int main(int argc, char **argv){
  int secret = strtoul(argv[1], NULL, 16);
  int* T = malloc(256 * sizeof(int));
  int val = 0;
  val += T[secret];
  return 0;
}
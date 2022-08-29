#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#define FLAGSIZE_MAX 64
char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}

void vuln(){
  char buf[16];
  gets(buf);
}

int main(int argc, char **argv){
  //open the flag.txt file
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }
  //Read from the file to flag
  fgets(flag,FLAGSIZE_MAX,f);
  //If there is a SIGSEGV run sigsegv_handler
  signal(SIGSEGV, sigsegv_handler);
  //gid settings
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  
  puts("Please enter your string: \n");
  vuln();
  printf("Thanks! Received: %s", argv[1]);
  return 0;
}
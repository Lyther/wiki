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

void vuln(char *input){
  char buf[16];
  strcpy(buf, input);
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
  
  //Need 1 argument to run the program
  if (argc > 1) {
  #run vuln with this argument
    vuln(argv[1]);
    printf("Thanks! Received: %s", argv[1]);
  }
  else
    printf("This program takes 1 argument.\n");
  return 0;
}
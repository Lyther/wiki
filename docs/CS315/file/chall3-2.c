#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void super_duper_secret_enroll_please_ret_to_me()
{
  char flag[0x100] = {0};
  FILE *fp = fopen("./flag.txt", "r");
  if (!fp)
  {
    puts("no flag!! contact a member of cs315");
    exit(-1);
  }
  fgets(flag, 0xff, fp);
  puts(flag);
  fclose(fp);
}

int main(void)
{
  char comments_and_concerns[32];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("alright, I heard some of u can't pick this course because too many students are coming to CS315");
  puts("my boss just told me this course isn't very easy and he wants me to design a challenge to examine those who want to be enrolled.");
  puts("xs, I don't know anything about security. I just walk around and serve coffee in lab.");
  puts("I'm going to put this function un-reachable and make sure nobody got enrolled.");
  puts("whatever u say, I'm not going to give u flag.");

  gets(comments_and_concerns);
}

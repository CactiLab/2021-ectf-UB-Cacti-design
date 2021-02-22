#include <stdio.h>




char * decrypt(char *passwd,int count)
​
{
  int j;
  int i = 0;
​
  while (i < count) {
    j = i & 3;
    if (i < 1) {
      j = -(-i & 3);
    }
    passwd[i] = ((string[j] ^ passwd[i]) + 0xe) % 0x5e + 0x21;
    i = i + 1;
  }
  printf("%s", passwd);
  return passwd;
}
​

int main(){

  char passwd[16] = {     0x12, 0x1c, 0x1c, 0x73,
                          0x4f, 0x03, 0x12, 0x35,
                          0x25, 0x1c, 0x6b, 0x03,
                          0x5c, 0x13, 0x10, 0x28};
  ​
  decrypt(passwd, 16);
}



​
char string[16] = {     0x65, 0x43, 0x54, 0x46,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00};
​

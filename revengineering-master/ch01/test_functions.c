#include <stdio.h>
#include <stdlib.h>

extern size_t _strlen(const char *s);
extern char * _strchr(const char *s, int c);
extern void * _memcpy(void *dest, const void *src, size_t n);
extern void * _memset(void *s, int c, size_t n);
extern int _strcmp(const char *s1, const char *s2);
extern char * _strset(const char *str, char c);

const char *string = "testtesttesttest";
const char *str1 = "hello";
const char *str2 = "hellooooo";
const char *str3 = "hell";
const char *str4 = "hallo";

int
main(int argc, char *argv[]){
  size_t size;
  int ch = 'p';
  char *ptr = NULL;
  
  size = _strlen(string);
  printf("%d\n",size);

  ptr = _strchr(string,ch);
  if (ptr)
    printf("%s\n",ptr);
  else
    printf("strchr null pointer\n");

  ptr = (char *)malloc(_strlen(string));
  _memcpy(ptr,string,_strlen(string));
  printf("%s\n",ptr);

  _memset(ptr,ch,_strlen(ptr));
  printf("%s\n",ptr);

  printf("%d\n",_strcmp(str1,str2));
  printf("%d\n",_strcmp(str1,str1));
  printf("%d\n",_strcmp(str1,str3));
  printf("%d\n",_strcmp(str1,str4));

  _strset(ptr,ch);
  printf("%s\n",ptr);
  
  exit(EXIT_SUCCESS);
}

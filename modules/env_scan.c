/*
30.03.2026
This module covers Environment Variables and Stores it in a key value pair
*/

/*
environ
   ↓                                      char** environ
+------------------+                        ↓
| pointer to "A=B" | ---> "A=B\0"        [ char* ] ----> "KEY=VALUE"
| pointer to "C=D" | ---> "C=D\0"        [ char* ] ----> "USER=arch"
| pointer to "E=F" | ---> "E=F\0"        [ char* ] ----> "HOME=/home/arch"
| NULL             |                     [  NULL ]
+------------------+

env        = environ
*env       = "KEY=VALUE"
**env      = 'K'
*/

#include <stdio.h>
#include <string.h>
#include "env_scan.h"

extern char **environ;

void printenv(const char *label, const char *value) {
  printf("E: %s\t-> V: %s\n", label, value);
}

void run_env_scan(){

  char **env = environ;

  while (*env) { 
    
    char *entry = *env;

    char *eq = strchr(entry, '=');

    if(eq){
      *eq = '\0';
      printenv(entry, eq+1);
    }

    env++;
  }  
}

int main(){
  run_env_scan();
  return 0;
}


/*
Pointers:

k = value
&k = address of k, used during declaration
int* x = &k // x stores address of k
x // address of k
*x // value of k (dereferenced)
*/

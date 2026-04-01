/*
30.03.2026
This module covers Environment Variables and Stores it in a key value pair
*/

#include <stdio.h>
#include <string.h>
#include "env_scan.h"

#define MAX_ENV 200

extern char **environ;

typedef struct {
  char *entry;
  int is_critical;
} EnvVar;

int is_critical_var(char *entry) {

    if (strncmp(entry, "PATH=", 5) == 0) return 2;
    if (strncmp(entry, "LD_", 3) == 0) return 2;
    if (strncmp(entry, "USER=", 5) == 0) return 2;
    if (strncmp(entry, "LOGNAME=", 8) == 0) return 2;
    if (strncmp(entry, "HOME=", 5) == 0) return 2;

    if (strncmp(entry, "XAUTHORITY=", 11) == 0) return 1;
    if (strncmp(entry, "DBUS_", 5) == 0) return 1;
    if (strncmp(entry, "XDG_RUNTIME_DIR=", 16) == 0) return 1;
    if (strncmp(entry, "DISPLAY=", 8) == 0) return 1;

    return 0;
}

void run_env_scan(){

  EnvVar list[MAX_ENV];
  int count = 0;
  char **env = environ;

  while (*env && count < MAX_ENV) { 
    list[count].entry = *env;
    list[count].is_critical = is_critical_var(*env);
    count ++;
    env++;
  }

  printf("\n[HIGH importance ENV VARS]\n");
  for(int i=0; i<count; i++){
    if (list[i].is_critical == 2){
      printf("%s\n", list[i].entry);
    }
  }

  printf("\n[Interesting ENV VARS]\n");
  for(int i=0; i<count; i++){
    if (list[i].is_critical == 1) {
      printf("%s\n", list[i].entry);
    }
  }
  
  printf("\n[LOW importance ENV VARS]\n");
  for(int i=0; i<count; i++){
    if (list[i].is_critical == 0) {
      printf("%s\n", list[i].entry);
    }
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


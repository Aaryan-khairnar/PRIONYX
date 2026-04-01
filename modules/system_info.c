/*
29.03.2026
Hostname, kernel version, OS, arch, UID, PID, GID, login name
This module covers all of it
*/

 
#include <stdio.h>

#include <sys/types.h> // That header defines many of the fundamental POSIX data types used across the system.
#include <sys/utsname.h> // This header gives access to kernel and architecture information through a structure called utsname.
#include <unistd.h> // This one contains POSIX system calls for interacting with the operating system.
#include <pwd.h> // retrieve information from password file
#include <grp.h> // retrieve information from grp file

#include "system_info.h"

void infoprintstr(const char *label, const char *value) {
  printf("[+] %s : %s\n", label, value);
}
void infoprintnum(const char *label, long value) {
  printf("[+] %s : %ld\n", label, value);
}

// ALL THE FOLLOWING CODE IS UNSAFE, ADD SAFETY CHECKS [1]

void run_system_info() {

  uid_t uid = getuid();
  infoprintnum("User ID", uid);
  // This is the numeric ID for this user. If this field has the value 0, then
  // this account has superuser privileges.

  struct passwd *pwd = getpwuid(uid);
  if (pwd != NULL) {
    infoprintstr("Username", pwd->pw_name);
    infoprintstr("Home Directory", pwd->pw_dir);
    infoprintstr("Shell", pwd->pw_shell);
  }
  // getpwuid(uid) returns a struct of pointers, these pointers point to the data loaded into memory
  // directly from /etc/passwd
  // This struct also points to char *gr_passwd; which is the Encrypted password, but in modern systems it just stores 'x', 
  // because all passwords are stored in /etc/shadow

  long hostid = gethostid();
  infoprintnum("Host ID", hostid);
  // Returns process group ID of calling process

  char hostname[100];
  if(gethostname(hostname, sizeof(hostname)) == 0){
      hostname[sizeof(hostname) - 1] = '\0';
      infoprintstr("Hostname", hostname);
  } else {
    infoprintstr("Hostname", "Unknown (gethostname failed)");
  }
  // Returns Hostname

  char loginname[100];
  if(getlogin_r(loginname, sizeof(loginname)) == 0){
      loginname[sizeof(loginname) - 1] = '\0';
      infoprintstr("Login name", loginname);
  } else {
    infoprintstr("Login name", "Unknown (getlogin_r failed)");
  }
  // Login Name: Also known as username, this is the unique name that user must
  // enter to log in Human readable identifier of numeric User ID

  pid_t pid = getpid();
  infoprintnum("Process ID", pid);
  // Current process ID

  pid_t pgrp = getpgrp();
  infoprintnum("Process Group ID", pgrp);
  // Returns process group ID of calling process, what groups have access to the process


  gid_t gid = getgid();
  infoprintnum("User Group ID", gid);
  // returns the group ID of the user who called/invoke the process
  
  gid_t groups[250];
  int n = getgroups(0, NULL);
  getgroups(n, groups);
  printf("Other Groups user is a part of:\n");
  for (int i = 0; i < n; i++) {
    gid_t gid = groups[i];
    infoprintnum("Group ID", gid);

    struct group *grp = getgrgid(gid);
    if (grp != NULL){
      infoprintstr("\t|-Name->", grp->gr_name);
    } else {
      infoprintstr("Name", "Unknown");
    }
  }
  // Returns all the groups in which the user belongs to

  uid_t euid = geteuid();
  infoprintnum("Effective User ID", euid);
  // Returns effective User ID

  gid_t egid = getegid();
  infoprintnum("Effective Group ID", egid);
  // Returns effective Host ID

  pid_t sid = getsid(pid);
  infoprintnum("Session leader process group ID", sid);
  // Session leader Process Group ID
  
  // for parents
  pid_t ppid = getppid();
  infoprintnum("Parent Process ID", ppid);
}

/*
int main(){
  run_system_info();
  return 0;
}
*/
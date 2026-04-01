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

#define MAX_GROUPS 250

struct systeminfo {
    uid_t uid;
    char pw_name[50];
    char pw_dir[100];
    char pw_shell[100];
    long hostid;
    char hostname[100];
    char loginname[100];
    pid_t pid;
    pid_t pgrp;
    gid_t gid;
    int group_count;
    gid_t groups[MAX_GROUPS];
    char group_names[MAX_GROUPS][50];
    uid_t euid;
    gid_t egid;
    pid_t sid;
    pid_t ppid;
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
} s;

void infoprintstr(const char *label, const char *value) {
  printf("[+] %s : %s\n", label, value);
}
void infoprintnum(const char *label, long value) {
  printf("[+] %s : %ld\n", label, value);
}

void run_system_info() {

  s.uid = getuid();
  infoprintnum("User ID", s.uid);
  // This is the numeric ID for this user. If this field has the value 0, then
  // this account has superuser privileges.

  struct passwd *pwd = getpwuid(s.uid);
  if (pwd != NULL) {
    snprintf(s.pw_name, sizeof(s.pw_name), "%s", pwd->pw_name);
    snprintf(s.pw_dir, sizeof(s.pw_dir), "%s", pwd->pw_dir);
    snprintf(s.pw_shell, sizeof(s.pw_shell), "%s", pwd->pw_shell);
    infoprintstr("Username", s.pw_name);
    infoprintstr("Home Directory", s.pw_dir);
    infoprintstr("Shell", s.pw_shell);
  }
  // getpwuid(uid) returns a struct of pointers, these pointers point to the data loaded into memory
  // directly from /etc/passwd
  // This struct also points to char *gr_passwd; which is the Encrypted password, but in modern systems it just stores 'x', 
  // because all passwords are stored in /etc/shadow

  s.hostid = gethostid();
  infoprintnum("Host ID", s.hostid);
  // Returns a host identifier (legacy, not reliable on modern systems)

  
  if(gethostname(s.hostname, sizeof(s.hostname)) == 0){
      s.hostname[sizeof(s.hostname) - 1] = '\0';
      infoprintstr("Hostname", s.hostname);
  } else {
    snprintf(s.hostname, sizeof(s.hostname), "%s", "Unknown");
    infoprintstr("Hostname", "Unknown (gethostname failed)");
  }
  // Returns Hostname


  if(getlogin_r(s.loginname, sizeof(s.loginname)) == 0){
      s.loginname[sizeof(s.loginname) - 1] = '\0';
      infoprintstr("Login name", s.loginname);
  } else {
    snprintf(s.loginname, sizeof(s.loginname), "%s", "Unknown");
    infoprintstr("Login name", "Unknown (getlogin_r failed)");
  }
  // Login Name: Also known as username, this is the unique name that user must
  // enter to log in Human readable identifier of numeric User ID

  s.pid = getpid();
  infoprintnum("Process ID", s.pid);
  // Current process ID

  s.pgrp = getpgrp();
  infoprintnum("Process Group ID", s.pgrp);
  // Returns process group ID of calling process, what groups have access to the process


  s.gid = getgid();
  infoprintnum("User Group ID", s.gid);
  // returns the group ID of the user who called/invoke the process
  
  
  int n = getgroups(0, NULL);  // returns number of groups
  if (n > MAX_GROUPS) n = MAX_GROUPS;  // limits n to MAX_GROUPS to make sure of no buffer overflow
  s.group_count = n;
  getgroups(n, s.groups); // Saves all the GID's in s.groups 
  printf("Other Groups user is a part of:\n"); 
  // Loop for storing group names and printing
  for(int i=0; i<s.group_count; i++){ 
    struct group *grp = getgrgid(s.groups[i]);  // get group struct
    if( grp != NULL){ // if not null
      snprintf(s.group_names[i], sizeof(s.group_names[i]), "%s", grp->gr_name); // store in the struct
      printf("%d. %d(%s)\n", i, s.groups[i], s.group_names[i]); // print it out
    } else{
      snprintf(s.group_names[i], sizeof(s.group_names[i]), "%s", "Unknown"); // store Unknown in the struct
      infoprintstr("Name", "Unknown"); // print unknown
    }
  }
  // Returns all the groups in which the user belongs to

  s.euid = geteuid();
  infoprintnum("Effective User ID", s.euid);
  // Returns effective User ID

  s.egid = getegid();
  infoprintnum("Effective Group ID", s.egid);
  // Returns effective Host ID

  s.sid = getsid(s.pid);
  infoprintnum("Session leader process group ID", s.sid);
  // Session leader Process Group ID
  
  // for parents
  s.ppid = getppid();
  infoprintnum("Parent Process ID", s.ppid);

  // system and kernel info
  struct utsname u;
  if (uname(&u) == 0) {
    snprintf(s.sysname, sizeof(s.sysname), "%s", u.sysname);
    snprintf(s.nodename, sizeof(s.nodename), "%s", u.nodename);
    snprintf(s.release, sizeof(s.release), "%s", u.release);
    snprintf(s.version, sizeof(s.version), "%s", u.version);
    snprintf(s.machine, sizeof(s.machine), "%s", u.machine);
    infoprintstr("System Name", s.sysname);
    infoprintstr("Node Name", s.nodename);
    infoprintstr("Kernel Release", s.release);
    infoprintstr("Kernel Version", s.version);
    infoprintstr("Architecture", s.machine);
  }
}
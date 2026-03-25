/*
24.03.2026
Hostname, kernel version, OS, arch, UID, PID, GID, login name
This module covers all of it
*/

#include <stdio.h>
#include <unistd.h>  // This one contains POSIX system calls for interacting with the operating system.
#include <sys/utsname.h>  // This header gives access to kernel and architecture information through a structure called utsname.
#include <sys/types.h> // That header defines many of the fundamental POSIX data types used across the system.
#include "system_info.h"  

void infoprintstr(const char *label, const char *value) {
    printf("[+] %s : %s\n", label, value);
}
void infoprintnum(const char *label, long value) {
    printf("[+] %s : %ld\n", label, value);
}

// ALL THE FOLLOWING CODE IS UNSAFE, ADD SAFETY CHECKS [1]

void run_system_info(){

    uid_t uid = getuid(); 
    pid_t pid = getpid();
    pid_t pgrp = getpgrp();
    
    long hostid = gethostid();

    infoprintnum("User ID", uid);
    infoprintnum("Process ID", pid);
    infoprintnum("Process Group ID", pgrp);
    infoprintnum("Host ID", hostid);
    
    char hostname[100];
    gethostname(hostname, sizeof(hostname));
    infoprintstr("Hostname", hostname);
    // THIS ^ HERE IS UNSAFE YOU NEED TO CHANGE IT

    gid_t egid = getegid();
    infoprintnum("Effective Group ID", egid);

    uid_t euid = geteuid();
    infoprintnum("Effective User ID", euid);

    gid_t gid = getgid();
    infoprintnum("Group ID", gid);

    gid_t groups[250];
    int n = getgroups(0, NULL);
    getgroups(n, groups);
    printf("Groups IDs:\n");
    for(int i=0; i<n; i++){
        infoprintnum("->", groups[i]);
    }

    pid_t sid = getsid(pid);
    infoprintnum("Session leader process group ID", sid);

    char loginname[250];
    getlogin_r(loginname, sizeof(loginname));
    infoprintstr("Login name", loginname);
    
    // for parents
    pid_t ppid = getppid();
    infoprintnum("Parent Process ID", ppid);
}



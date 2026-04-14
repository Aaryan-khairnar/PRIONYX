/*
13.04.2025
This module scans the proc filesystem and lists out suspiscious processes
Walk /proc for all PIDs, read status/cmdline/environ per process, show UID/PID/name
opendir, atoi (check numeric dir names), fopen per PID, NULL handling
/proc/[pid]/status, /proc/[pid]/cmdline, /proc/[pid]/environ

Linux programming interface pg 267
*/

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "process_scan.h"

#define MAX_PROC 70000

struct process{
    char name[512];
    int pid;
    int ppid;
    char state;
    int threads;
    char binpath[1024];
    char cwd[1024]; //current working directory
    int no_of_fd;
} result[MAX_PROC];
int processcount = 0;

void visit_proc_dir(){

    DIR *dirpointer = opendir("/proc");

    struct dirent *entry;

    while((entry = readdir(dirpointer)) != NULL){

        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
            continue;
        }

        int is_process = 0; //assume it is not a process
        for(int i = 0; entry->d_name[i]; i++){
            if (entry->d_name[i] < '0' || entry->d_name[i] > '9') {
                is_process = 0;
                break;
            }
            else{
                is_process = 1;
            }
        }

        if(is_process){
            struct process p;
            p.pid = atoi(entry->d_name);
            
            store_res();

            if (processcount < MAX_PROC) {
                    result[processcount++] = p;
            } else {
                printf("The Processes count limit of %d reached, please change it in the source code\n", MAX_PROC);
            }
        }
    }
    closedir(dirpointer);
}

void store_res(){
    
}

void process_scan(){

    visit_proc_dir();
    printf("\nNo of processes in the system: %d\n", processcount);

    for(int i =0; i< processcount; i++){
        printf("%d\n", result[i].pid);
    }
}

int main(){
    process_scan();
}

/*
1. /proc/[pid]/status → your main goldmine
From this file, extract:
Name
Uid
PPid (parent PID)
State
Threads
Why it matters:

Parent-child relationships expose weird spawning
UID tells privilege level
Too many threads = possible abuse

2. /proc/[pid]/cmdline
Empty cmdline → big red flag
Weird arguments → suspicious behavior
Example:
Normal: /usr/bin/bash
Suspicious: empty or binary gibberish

3. /proc/[pid]/exe (VERY important)
This is a symlink → actual binary path.
Use:
readlink("/proc/[pid]/exe", ...)
Why this is powerful:
If binary runs from:
/tmp
/dev/shm
unknown location
→ huge red flag

4. /proc/[pid]/cwd

Current working directory.

If a process is running from:

/tmp
deleted directory
→ suspicious

5. /proc/[pid]/fd/ (file descriptors)

Count how many files/sockets it has open.

Too many FDs → possible:
scanning
network abuse
leaks

You don’t need deep inspection yet — just count is enough.

6. /proc/[pid]/stat or statm
Basic resource usage:
CPU time
memory
Useful later for:
detecting heavy abnormal usage


Now the interesting part — how to flag suspicious
Here’s a simple scoring model you can actually implement right now:
Example scoring logic
Start with score = 0
Add points:
UID = 0 (root process) → +1
cmdline is empty → +3
exe path in /tmp, /dev/shm → +4
parent PID = 1 but not a known service → +2
too many FDs (>100 for now) → +2
name mismatch with exe → +3
zombie state → +1
Then classify:
score >= 6 → High risk
3–5 → Medium
1–2 → Low

*/
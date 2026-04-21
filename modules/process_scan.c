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
    int pid;
    char name[1024];
    char cmdline[2048];
    int uid; //Which user runs process 
    int ppid;  //Parent process Id
    char state; //Sleeping or Active
    int threads; // No of threads?
    char binpath[1024]; //Binary path
    char cwd[1024]; //current working directory
    int no_of_fd;
    int score;
    char issues[256];
} resultprocess[MAX_PROC];
static int processcount = 0;
static int skipcount = 0;

void store_res_proc(struct process *p);
void read_status_fields(struct process *p);
void read_exe_symlink(struct process *p);
void read_cwd_symlink(struct process *p);
void count_fd(struct process *p);
void read_commandline(struct process *p);
int is_presult_interesting(struct process *p);
int compare_scores(const void *a, const void *b);
void print_result();

void visit_proc_dir(){

    DIR *dirpointer = opendir("/proc");
    if(dirpointer == NULL) { return; }

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
            memset(&p, 0, sizeof(struct process));
            p.pid = atoi(entry->d_name);
            
            store_res_proc(&p);
            if(is_presult_interesting(&p)){
                if (processcount < MAX_PROC) { 
                    resultprocess[processcount++] = p;
                } else {printf("\nNo of processes in the system: %d\n", processcount);
                    printf("The Processes count limit of %d reached, please increase it in the source code\n", MAX_PROC);
                }
            }
            else{
                skipcount++;
                continue;
            }
            
        }
    }
    closedir(dirpointer);
}

void store_res_proc(struct process *p){
    read_status_fields(p);
    read_exe_symlink(p);
    read_cwd_symlink(p);
    count_fd(p);
    read_commandline(p);
}

int is_presult_interesting(struct process *p){
    int score = 0;

    // Optional: Filter out Kernel Threads (highly recommended so your scan isn't flooded with kworkers)
    if (p->pid == 2 || p->ppid == 2) {
        return 0; 
    }

    if (p->uid == 0) {
        score += 1;
        strcat(p->issues, "UID_ROOT ");
    }
    if (strlen(p->cmdline) == 0) {
        score += 3;
        strcat(p->issues, "HIDDEN_CMDLINE ");
    }
    if (strncmp(p->binpath, "/tmp", 4) == 0 || strncmp(p->binpath, "/dev/shm", 8) == 0) {
        score += 4;
        strcat(p->issues, "TMP_EXEC ");
    }
    if (p->ppid == 1) {
        score += 2;
        strcat(p->issues, "ORPHAN_ROOT ");
    }
    if (p->no_of_fd > 100) {
        score += 2;
        strcat(p->issues, "HIGH_FD ");
    }

    // Catch processes running entirely in memory (memfd)
    if (strncmp(p->binpath, "/memfd:", 7) == 0) {
        score += 5;
        strcat(p->issues, "MEMFD_EXEC ");
    }
    
    // Catch binaries that were executed and immediately deleted from disk to hide
    if (strstr(p->binpath, "(deleted)") != NULL) {
        score += 4;
        strcat(p->issues, "EXEC_DELETED ");
    }

    // Check for name mismatch
    if (strlen(p->name) > 0 && strcmp(p->binpath, "[unreadable]") != 0) {
        if (strstr(p->binpath, p->name) == NULL) {
            score += 3;
            strcat(p->issues, "NAME_MISMATCH ");
        }
    }

    // If the cmdline isn't empty, check it for common attacker flags
    if (strlen(p->cmdline) > 0) {
        if (strstr(p->cmdline, "base64 -d") != NULL || strstr(p->cmdline, "base64 --decode") != NULL) {
            score += 4;
            strcat(p->issues, "BASE64_DECODE ");
        }
        if (strstr(p->cmdline, "/dev/tcp/") != NULL || strstr(p->cmdline, "/dev/udp/") != NULL) {
            score += 5;
            strcat(p->issues, "DEV_TCP_SHELL ");
        }
    }

    p->score = score;
    return (score >= 1);
}

void read_status_fields(struct process *p){
    if(!p) return;

    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/status", p->pid);
    FILE *fp = fopen(path, "r");

    if(fp == NULL){ return; }

    char line[1024];
    while(fgets(line, sizeof(line), fp)){
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:\t%511s", p->name);
        }

        else if (strncmp(line, "PPid:", 5) == 0) {
        sscanf(line, "PPid:\t%d", &p->ppid);
        }

        else if (strncmp(line, "Uid:", 4) == 0) {
        sscanf(line, "Uid:\t%d", &p->uid);
        }

        else if (strncmp(line, "State:", 6) == 0) {
        sscanf(line, "State:\t%c", &p->state);
        }

        else if (strncmp(line, "Threads:", 8) == 0) {
        sscanf(line, "Threads:\t%d", &p->threads);
        }
    }
    fclose(fp);
}

void read_exe_symlink(struct process *p){
    if(!p) return;

    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/exe", p->pid);

    ssize_t len = readlink(path, p->binpath, sizeof(p->binpath) - 1);
    if (len != -1) {
        p->binpath[len] = '\0'; // Null-terminate the string
    } else {
        strcpy(p->binpath, "[unreadable]");
    }
}

void read_cwd_symlink(struct process *p){
    if(!p) return;

    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/cwd", p->pid);

    ssize_t len = readlink(path, p->cwd, sizeof(p->cwd) - 1);
    if (len != -1) {
        p->cwd[len] = '\0'; // Null-terminate the string
    } else {
        strcpy(p->cwd, "[unreadable]");
    }
}

void count_fd(struct process *p){
    if(!p) return;

    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/fd", p->pid);
    
    DIR *dirpointer = opendir(path);
    if(dirpointer == NULL) { return; }

    if(dirpointer){
        int count = 0;

        struct dirent *entry;
        while((entry = readdir(dirpointer)) != NULL){
            if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
                continue;
            }
            count++;
        }
        p->no_of_fd = count;
        closedir(dirpointer);
    }
}

void read_commandline(struct process *p){
    if(!p) return;

    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", p->pid);
    FILE *fp = fopen(path, "r");
    
    if(fp == NULL){ 
        p->cmdline[0] = '\0';
        return; 
    }

    size_t bytes_read = fread(p->cmdline, 1, sizeof(p->cmdline) - 1, fp);
    p->cmdline[bytes_read] = '\0';

    fclose(fp);
}

// Compare function for qsort (sorts descending by threat score)
int compare_scores(const void *a, const void *b){
    struct process *p1 = (struct process *)a;
    struct process *p2 = (struct process *)b;
    return p2->score - p1->score; 
}

void print_result(){

    // 1. Sort the results array by severity
    qsort(resultprocess, processcount, sizeof(struct process), compare_scores);

    // 2. Tally the severities
    int high = 0, med = 0, low = 0;
    for(int i = 0; i < processcount; i++){
        if(resultprocess[i].score >= 6) high++;
        else if(resultprocess[i].score >= 3) med++;
        else low++;
    }

    // 3. Print Header & Legend

    printf("========== ISSUE INDEX ==========\n");
    printf("UID_ROOT        -> Runs with root privileges (high impact if exploited)\n");
    printf("HIDDEN_CMDLINE  -> Process is masking its arguments (CRITICAL)\n");
    printf("TMP_EXEC        -> Executing from /tmp or /dev/shm\n");
    printf("ORPHAN_ROOT     -> Parent PID is 1 (potential daemon or pivot)\n");
    printf("HIGH_FD         -> Process has >100 open files/sockets\n");
    printf("NAME_MISMATCH   -> Process name does not match the executed binary\n");
    printf("MEMFD_EXEC      -> Executing directly from memory (Fileless Malware)\n");
    printf("EXEC_DELETED    -> Binary was deleted from disk after execution\n");
    printf("BASE64_DECODE   -> Command line contains base64 decoding patterns\n");
    printf("DEV_TCP_SHELL   -> Command line contains reverse shell network piping\n");
    printf("=================================\n\n");

    // 4. Print Summary
    printf("========== SCAN SUMMARY ==========\n");
    printf("Total interesting processes : %d\n", processcount);
    printf("High Risk   (>=6)           : %d\n", high);
    printf("Medium Risk (3-5)           : %d\n", med);
    printf("Low Risk    (1-2)           : %d\n", low);
    printf("==================================\n\n");

    // 5. Print the formatted table
    printf("========== FINDINGS (sorted by severity) ==========\n\n");
    
    // Table Header
    printf("%-5s %-20s | %-45s | %-30s | %-10s | %s\n", "SCORE", "NAME", "BINPATH", "ISSUES", "UID:PPID", "FDs");
    
    for(int i = 0; i < processcount; i++){
        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%d:%d", resultprocess[i].uid, resultprocess[i].ppid);
        
        // Removed the strict .XX truncation limits so data doesn't get cut
        printf("[%d]   %-20s | %-45s | %-30s | %-10s | %d\n", 
            resultprocess[i].score, 
            resultprocess[i].name, 
            resultprocess[i].binpath, 
            resultprocess[i].issues,   
            id_str, 
            resultprocess[i].no_of_fd);
    }
    printf("\n");
}

void run_process_scan(){

    visit_proc_dir();
    
    if(skipcount > 0){
        printf("A few Processes were skipped because of permission issues (run program with sudo if possible)\n");
    }

    print_result();
}
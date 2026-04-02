/*
01.04.2025
This module Walks key directories, finds all SUID/SGID binaries using stat()
/usr/bin, /bin, /sbin, /usr/sbin, /opt
opendir/readdir, stat(), S_ISUID/S_ISGID macros, recursion or iteration
*/

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include "file_perm_enum.h"

#define MAX_FILES 10000
#define MAX_DIRS 5000

ino_t visited_inodes[MAX_DIRS];
dev_t visited_devs[MAX_DIRS];
int visited_count = 0;

struct FileMetadata {
    char path[512];
    uid_t uid;
    gid_t gid;
    mode_t mode;
    off_t size;
    int is_suid;
    int is_sgid;
    int is_world_writable;
    int is_group_writable;
    int is_readable;
    int is_executable;
} results[MAX_FILES];
int file_count = 0;

char dir_list[MAX_DIRS][512];
int dir_count = 0;

void get_perm_string(mode_t mode, char *perm) {
    perm[0] = (mode & S_IRUSR) ? 'r' : '-';
    perm[1] = (mode & S_IWUSR) ? 'w' : '-';
    perm[2] = (mode & S_IXUSR) ? 'x' : '-';

    perm[3] = (mode & S_IRGRP) ? 'r' : '-';
    perm[4] = (mode & S_IWGRP) ? 'w' : '-';
    perm[5] = (mode & S_IXGRP) ? 'x' : '-';

    perm[6] = (mode & S_IROTH) ? 'r' : '-';
    perm[7] = (mode & S_IWOTH) ? 'w' : '-';
    perm[8] = (mode & S_IXOTH) ? 'x' : '-';

    perm[9] = '\0';
}

void add_dir_to_list(char* path){

    if (dir_count >= MAX_DIRS) return;

    // skip very big / useless dirs
    if (
        strncmp(path, "/proc", 5) == 0 ||
        strncmp(path, "/boot", 5) == 0 ||
        strncmp(path, "/sys", 4) == 0 ||
        strncmp(path, "/dev", 4) == 0 ||
        strncmp(path, "/var/cache", 10) == 0 ||
        strncmp(path, "/var/lib", 8) == 0 ||
        strncmp(path, "/usr/share", 10) == 0
    ) return;

    struct stat st;
    if (stat(path, &st) != 0) return;

    // check if already visited (inode + device)
    for (int i = 0; i < visited_count; i++) {
        if (visited_inodes[i] == st.st_ino &&
            visited_devs[i] == st.st_dev) {
            return; // already scanned this directory
        }
    }

    // mark as visited
    if (visited_count < MAX_DIRS) {
        visited_inodes[visited_count] = st.st_ino;
        visited_devs[visited_count] = st.st_dev;
        visited_count++;
    }

    // optional: avoid duplicate string paths (not strictly needed now)
    for (int i = 0; i < dir_count; i++) {
        if (strcmp(dir_list[i], path) == 0) return;
    }

    // add to list
    snprintf(dir_list[dir_count], sizeof(dir_list[dir_count]), "%s", path);
    dir_count++;

    if (dir_count >= MAX_DIRS) {
        printf("[!] Directory limit reached\n");
        return;
    }
}


void read_dir_metadata(char *dirinput){

        DIR *dir = opendir(dirinput); //makes a pointer of DIR datatype, points it to the directory path
        if (dir == NULL) return;      //checks if directory path exists or not

        struct dirent *entry; //make a pointer for dirent struct
        // This structure gives you the d_name field which is the directory name 
        // (Concatinated to path to make absolute path)

        int added = 0;

        // entry = readdir(dir) -> Give me the next entry to read
        // if there is no next directory, it will 
        while ((entry = readdir(dir)) != NULL) {  

            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){ continue; }
            //if directory name is . or .. then we skip

            // define struct and store results in that struct
            char path[512]; // reserve space for path
            snprintf(path, sizeof(path), "%s/%s", dirinput, entry->d_name); 
            // Put full path of the file /dirinput/d_name -> in path
        
            struct stat st; //Get file attributes for FILE and put them in BUF.
            if (lstat(path, &st) != 0) continue; 

            if (S_ISLNK(st.st_mode)) continue;

            if (!S_ISREG(st.st_mode)) continue;

            if (S_ISDIR(st.st_mode)) {
                if (strlen(path) >= sizeof(path) - 1) continue;
            // limit expansion per dir
                if (added < 20) {
                    add_dir_to_list(path);
                    added++;
                }
                continue;
            }

            // process regular file
            struct FileMetadata f;
            snprintf(f.path, sizeof(f.path), "%s", path);
            f.uid = st.st_uid;
            f.gid = st.st_gid;
            f.mode = st.st_mode;
            f.size = st.st_size;
            f.is_suid = (st.st_mode & S_ISUID) ? 1 : 0;
            f.is_sgid = (st.st_mode & S_ISGID) ? 1 : 0;
            f.is_world_writable = (st.st_mode & S_IWOTH) ? 1 : 0;
            f.is_group_writable = (st.st_mode & S_IWGRP) ? 1 : 0;
            f.is_readable = (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) ? 1 : 0;
            f.is_executable = (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) ? 1 : 0;

            if (file_count < MAX_FILES) {
                results[file_count++] = f;
            }
        }
    closedir(dir);
}


int compare_risk(const void *a, const void *b) {
    struct FileMetadata *fa = (struct FileMetadata *)a;
    struct FileMetadata *fb = (struct FileMetadata *)b;

    int score_a = 0, score_b = 0;

    // recompute score (same logic as below)
    if (fa->is_suid && fa->uid == 0) score_a += 3;
    if (fa->is_suid && fa->uid != 0) score_a += 3;
    if (fa->is_sgid) score_a += 2;
    if (fa->is_world_writable) score_a += 3;
    if (fa->is_executable && fa->is_world_writable) score_a += 2;
    if (fa->is_suid && (fa->is_world_writable || fa->is_group_writable)) score_a += 3;

    if (fb->is_suid && fb->uid == 0) score_b += 3;
    if (fb->is_suid && fb->uid != 0) score_b += 3;
    if (fb->is_sgid) score_b += 2;
    if (fb->is_world_writable) score_b += 3;
    if (fb->is_executable && fb->is_world_writable) score_b += 2;
    if (fb->is_suid && (fb->is_world_writable || fb->is_group_writable)) score_b += 3;

    return score_b - score_a; // descending
}

void analyse_results(){

    // sort results by risk first
    qsort(results, file_count, sizeof(struct FileMetadata), compare_risk);

    printf("\n==== FILE METADATA ANALYSIS ====\n\n");
    printf("%-40s | %-25s | %-10s | %s\n", 
           "PATH", "ISSUE", "PERMS", "RISK SCORE");

    for (int i = 0; i < file_count; i++) {

        struct FileMetadata f = results[i];
        char issue[128] = "";
        char perm[10];
        get_perm_string(f.mode, perm);

        int score = 0;

        // --- PRIORITY CLASSIFICATION ---
        if (f.is_suid && (f.is_world_writable || f.is_group_writable)) {
            strcpy(issue, "SUID+WRITABLE");
            score += 6;
        }
        else if (f.is_suid && f.uid != 0) {
            strcpy(issue, "SUID_NONROOT");
            score += 5;
        }
        else if (f.is_world_writable && f.is_executable) {
            strcpy(issue, "EXEC+WORLD_WRITE");
            score += 5;
        }
        else if (f.is_world_writable) {
            strcpy(issue, "WORLD_WRITABLE");
            score += 3;
        }
        else if (f.is_suid && f.uid == 0) {
            strcpy(issue, "SUID_ROOT");
            score += 3;
        }
        else if (f.is_sgid) {
            strcpy(issue, "SGID");
            score += 2;
        }

        // --- CONTEXT TAGS (append, not replace) ---
        if (strstr(f.path, "/tmp") ||
            strstr(f.path, "/dev/shm") ||
            strstr(f.path, "/var/tmp")) {

            strcat(issue, " TMP");
            score += 1;
        }

        if (f.is_suid && f.size < 10000) {
            strcat(issue, " SMALL");
            score += 1;
        }

        // skip clean files
        if (strlen(issue) == 0) continue;

        printf("%-40s | %-25s | %-10s | %d\n",
               f.path, issue, perm, score);
    }
}


void file_perm_enum_scan(){

    printf("\n====== FILE PERMISSION ENUMERATION ======\n");

    add_dir_to_list("/bin");
    add_dir_to_list("/usr/bin");
    add_dir_to_list("/usr/sbin");
    add_dir_to_list("/sbin");

    add_dir_to_list("/usr/local/bin");
    add_dir_to_list("/usr/local/sbin");

    add_dir_to_list("/opt");

    add_dir_to_list("/home");
    add_dir_to_list("/root");

    add_dir_to_list("/tmp");
    add_dir_to_list("/var/tmp");
    add_dir_to_list("/dev/shm");

    add_dir_to_list("/etc");
    add_dir_to_list("/etc/cron.d");
    add_dir_to_list("/etc/cron.daily");
    add_dir_to_list("/etc/cron.hourly");
    add_dir_to_list("/etc/cron.weekly");

    add_dir_to_list("/var");
    add_dir_to_list("/var/log");
    add_dir_to_list("/var/spool/cron");

    printf("[Scanning files with dangerous permissions]...\n");

    printf(
        "SUID_ROOT       → Runs as root (privilege escalation boundary)\n"
        "SUID_NONROOT    → Runs as another user (can still be abused)\n"
        "SGID            → Runs with group privileges\n"
        "WORLD_WRITABLE  → Anyone can modify the file (attacker control)\n"
        "EXEC+WORLD_WRITE→ Executable AND writable (very dangerous combo)\n"
        "SUID+WRITABLE   → Privileged + modifiable (CRITICAL)\n"
        "ROOT_WRITE      → Root-owned but writable (system integrity risk)\n"
        "READ_WRITE      → File can be read and modified (data exposure + tampering)\n"
        "TMP             → Located in /tmp, /var/tmp, /dev/shm (untrusted location)\n"
        "SMALL           → Very small binary (possible custom/backdoor)\n"
    );

    for (int i = 0; i < dir_count; i++) {
        read_dir_metadata(dir_list[i]);
    }
    analyse_results();
}

int main(){
    file_perm_enum_scan();
}
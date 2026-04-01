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
#include "file_perm_enum.h"

struct FileMetadata {
    char path[512];
    uid_t owner;
    gid_t group;
    int is_suid;
    int is_sgid;
    int is_world_writable;
    int is_executable;
} f;

const char *dir_targets[] = {
    "/bin",
    "/usr/bin",
    "/sbin",
    "/usr/sbin",
    "/opt",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
    "/root"
};

const char *file_targets[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/id_rsa"
};

int check_suid(){}

int check_writable(){}

int check_readable(){}

check_dangerous_combo(){}



void file_perm_enum_scan(){

    // Your ahh gotta learn this code

    DIR *dir = opendir("/usr/bin");  
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {

    if (strcmp(entry->d_name, ".") == 0 ||
        strcmp(entry->d_name, "..") == 0)
        continue;

    char path[512];
    snprintf(path, sizeof(path), "/usr/bin/%s", entry->d_name);

    struct stat st;
    if (stat(path, &st) == 0) {

        if (st.st_mode & S_ISUID) {
            printf("[SUID] %s\n", path);
        }

        if (st.st_mode & S_ISGID) {
            printf("[SGID] %s\n", path);
        }
    }
}

closedir(dir);


}






/*
(A) Directory traversal
How do I find files?
(B) File metadata
How do I inspect permissions and ownership?
(C) Privilege semantics
What does SUID/SGID actually mean?
*/

/*
For each SUID binary, collect:
🔹 Basic info
path
owner (uid → username)
group
permissions
🔹 Privilege relevance

This is where it becomes interesting:

is it owned by root?
is it writable?
is it in PATH?
is it uncommon (not standard binaries)?
*/


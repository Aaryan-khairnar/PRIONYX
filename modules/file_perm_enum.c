/*
11.04.2025
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
#include <errno.h>
#include "file_perm_enum.h"

#define MAX_FILES 10000

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
    char issue[512];
    int score;
    ino_t inode;
    dev_t device;
} result[MAX_FILES];
int filecount = 0;
int skipcount = 0;

/******FUNCTIONS DECLARATION*******/
void store_res(struct stat st, char* path);
int is_result_interesting(struct FileMetadata *f);
void print_results(struct FileMetadata* result);
void add_issue(struct FileMetadata *f, const char *tag);
int is_duplicate(struct FileMetadata *f);
/**********************************/

void visit_directory(char* dirpath){
    DIR *dp; //Make a DIR datatype pointer called dp
    dp = opendir(dirpath); //Point dp to actual location of our file
    
    if(dp == NULL) {
        skipcount++;
        //printf("Error in opening directory: %s, %s\n", strerror(errno), dirpath);
        return;
    }
    struct dirent *entry; //Dirent struct is returned by readdir(dp), takes a pointer returns a struct
   
    //We parse through each and every directory inside the given directory until we reach NULL/end
    while((entry = readdir(dp)) != NULL){ 
        
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
            continue;
        }
        
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);  //print file path

        struct stat st;

        if(lstat(path, &st) != 0) {  // lstat gets the metadata of the file
            printf("Error in lstat function: %s\n", strerror(errno));
            continue;
        }

        if(S_ISLNK(st.st_mode)){  // skip if anything is a symbolic link
            continue;
        } 

        if(S_ISDIR(st.st_mode)){  // recursion if anything is a directory
            visit_directory(path);
            continue;
        }

        if (!S_ISREG(st.st_mode)){  // skip if anything is not a regular directory
            continue;
        }

        store_res(st, path); //Store result of the file
    }

    closedir(dp); //Close directory
}


void store_res(struct stat st, char* path){
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
        f.inode = st.st_ino;
        f.device = st.st_dev;

        // store all metadata in int or binary including path in char[]

        if(is_result_interesting(&f)){
            if(!is_duplicate(&f)){
                if (filecount < MAX_FILES) {
                    result[filecount++] = f;
                } else {
                printf("The filecount limit of %d reached, please change it in the source code\n", MAX_FILES);
                }
            } 
        } 
        return;
}


int is_result_interesting(struct FileMetadata *f){
    f->score = 0;
    f->issue[0] = '\0';  // Initialise both so we don't have any 

    if (f->is_suid && (f->is_world_writable || f->is_group_writable)) {
    add_issue(f, "SUID_WRITABLE");
    f->score += 6;
    }
    if (f->is_suid && f->uid != 0) {
        add_issue(f, "SUID_OTHER_USER");
        f->score += 5;
    }
    if (f->is_world_writable && f->is_executable) {
        add_issue(f, "EXEC_WRITABLE");
        f->score += 5;
    }
    if (f->is_world_writable) {
        add_issue(f, "WORLD_WRITABLE");
        f->score += 3;
    }
    if (f->is_suid && f->uid == 0) {
        add_issue(f, "SUID_ROOT");
        f->score += 3;
    }
    if (f->is_sgid) {
        add_issue(f, "SGID");
        f->score += 2;
    }
    if(f->score > 0){
        return 1;  // Yes the result is interesting, store it
    } else {
        return 0;  // No the result is not interesting, skip it
    }
}

int compare_files(const void *a, const void *b) {
    struct FileMetadata *f1 = (struct FileMetadata *)a;
    struct FileMetadata *f2 = (struct FileMetadata *)b;

    return f2->score - f1->score; // descending order
}

void add_issue(struct FileMetadata *f, const char *tag) {
    if(strlen(f->issue) > 0) {
        strncat(f->issue, " | ", sizeof(f->issue) - strlen(f->issue) - 1);
    }
    strncat(f->issue, tag, sizeof(f->issue) - strlen(f->issue) - 1);
}

int is_duplicate(struct FileMetadata *f){
    for(int i = 0; i < filecount; i++){
        if(result[i].inode == f->inode &&
           result[i].device == f->device){
            return 1;
        }
    }
    return 0;
}

void print_results(struct FileMetadata* result){

    qsort(result, filecount, sizeof(struct FileMetadata), compare_files);

    int high = 0, medium = 0, low = 0;

    for(int i = 0; i < filecount; i++){
        if(result[i].score >= 6) high++;
        else if(result[i].score >= 3) medium++;
        else low++;
    }

    printf("\n========== ISSUE INDEX ==========\n");

    printf(
    "SUID_ROOT       → Runs with root privileges (high impact if exploited)\n"
    "SUID_OTHER_USER → Runs as another user (possible privilege pivot)\n"
    "SGID            → Executes with group privileges\n"
    "WORLD_WRITABLE  → Any user can modify this file\n"
    "EXEC_WRITABLE   → Executable + writable → direct code execution risk\n"
    "SUID_WRITABLE   → Privileged binary that can be modified (CRITICAL)\n"
    );

    printf("=================================\n");

    // ===== SUMMARY FIRST =====
    printf("\n========== SCAN SUMMARY ==========\n");
    printf("Total interesting files : %d\n", filecount);
    printf("High Risk   (>=6)       : %d\n", high);
    printf("Medium Risk (3-5)       : %d\n", medium);
    printf("Low Risk    (1-2)       : %d\n", low);
    printf("Skipped files(Bad perm) : %d\n", low);
    printf("==================================\n\n");

    // ===== FINDINGS (ONE LINE PER FILE) =====
    printf("========== FINDINGS (sorted by severity) ==========\n\n");
    printf("%-4s %-43s | %-30s | %-11s | %8s\n",
       "RISK", "PATH", "ISSUES", "UID:GID", "SIZE");

    for(int i = 0; i < filecount; i++){

    int len = strlen(result[i].path);
    int chunk = 44;   // width of PATH column
    int printed = 0;

    // First line (with full row info)
    printf("[%d] ", result[i].score);

    if(len <= chunk){
        printf("%-44s | %-30s | %5d:%-5d | %8ldB\n",
            result[i].path,
            result[i].issue,
            result[i].uid,
            result[i].gid,
            result[i].size
        );
    } else {
        // print first chunk
        printf("%-44.*s | %-30s | %5d:%-5d | %8ldB\n",
            chunk, result[i].path,
            result[i].issue,
            result[i].uid,
            result[i].gid,
            result[i].size
        );

        printed += chunk;

        // remaining chunks (only path, rest empty)
        while(printed < len){
            printf("     %-44.*s | %-30s | %-11s | %8s\n",
                chunk,
                result[i].path + printed,
                "", "", ""
            );
            printed += chunk;
        }
    }
}
}

void file_perm_enum_scan(){

    visit_directory("/bin");
    visit_directory("/sbin");
    visit_directory("/usr");
    visit_directory("/etc");
    visit_directory("/var");
    visit_directory("/tmp");
    visit_directory("/home");
    visit_directory("/root");
    visit_directory("/opt");
    visit_directory("/boot");
    visit_directory("/srv");

    if(skipcount > 0){
        printf("A few directories were skipped because of permission issues (run program with sudo if possible)");
    }
    
    print_results(result);
}
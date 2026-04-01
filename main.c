#include <stdio.h>
#include "modules/system_info.h"
#include "modules/env_scan.h"
//#include "modules/file_perm_enum.h"
//#include "modules/process_scan.h"

int main() {
    printf("====== Defender Enumeration Tool v0.1 ======\n");

    printf("\n====[SYSTEM INFORMATION SCAN]====\n");

    run_system_info();

    printf("\n====[ENVIRONMENT VARIABLES SCAN]====\n");

    run_env_scan();
    

    //run_file_perm_enum();
    //printf("\n");

    //run_process_scan();
    //printf("\n");

    return 0;
}
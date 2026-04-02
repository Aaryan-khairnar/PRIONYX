#include <stdio.h>
#include "modules/system_info.h"
#include "modules/env_scan.h"
#include "modules/file_perm_enum.h"
//#include "modules/process_scan.h"

int main() {
    printf("====== PRIONYX Defender Enumeration Tool v0.1 ======\n");

    printf("\n====[SYSTEM INFORMATION SCAN]====\n\n");

    run_system_info();

    printf("\n====[ENVIRONMENT VARIABLES SCAN]====\n");

    run_env_scan();
    
    printf("\n======[FILE PERMISSION ENUMERATION]======\n\n");
    file_perm_enum_scan();
    printf("\n");

    //run_process_scan();
    //printf("\n");

    return 0;
}
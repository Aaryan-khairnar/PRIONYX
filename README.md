# PRIONYX - Defender Enumeration Tool (C Edition)

PRIONYX is a dependency-free, statically compiled Linux enumeration and incident response tool written in pure C. Designed for defenders, DFIR analysts, and sysadmins who need a single binary that runs on any Linux system — including stripped containers, embedded devices, and potentially compromised hosts — without relying on interpreters, package managers, or shell utilities.

Unlike typical offensive enumeration scripts, this tool focuses on **system awareness and safe inspection**, providing insights into the system’s configuration, permissions, and processes without relying on external shell utilities. Its modular design makes it easy to expand with additional scanning capabilities.

## Features

- **System Information:** Hostname, OS, kernel version, architecture  
- **Environment Variables:** Lists and highlights relevant variables  
- **SUID Binary Enumeration:** Detects all SUID binaries across key directories  
- **Process Inspection:** Lists running processes with PID and UID information  
- **Modular Design:** Easily extendable with new modules in C

## Installation

Compile the project with all modules:

```bash
gcc main.c modules/*.c -o PRIONYX_enum
````

## Usage

Run the tool:

```bash
./PRIONYX_enum
```

Example output:

```
=== PRIONYX Defender Enumeration Tool v0.1 ===

[SYSTEM INFO]
Hostname: arch
OS: Linux 6.8.2
Architecture: x86_64

[ENVIRONMENT VARIABLES]
PATH=/usr/local/bin:/usr/bin:/bin
HOME=/home/arch

[SUID BINARIES]
/usr/bin/passwd
/bin/su

[PROCESS ENUMERATION]
Name: bash
Uid: 1000    1000    1000    1000
```

## Modules

* `system_info` – Basic system information
* `env_scan` – Environment variable analysis
* `suid_scan` – SUID binary detection
* `process_scan` – Process enumeration via `/proc`

## Structure

```
PRIONYX/
├─ main.c
└─ modules/
    ├─ system_info.c
    ├─ system_info.h
    ├─ env_scan.c
    ├─ env_scan.h
    ├─ suid_scan.c
    ├─ suid_scan.h
    ├─ process_scan.c
    ├─ process_scan.h
```

## License

This project is open-source and free to use for educational purposes, under MIT License.

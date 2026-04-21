# PRIONYX - Linux Triage and Incident Response Enumeration Tool
---

PRIONYX is a lightweight Linux triage and system inspection tool written in C. It is designed to assist defenders, incident responders, and forensic analysts in rapidly assessing the state of a system during the early stages of an investigation.

The tool operates as a single, dependency-free binary and avoids reliance on external shell utilities. This makes it suitable for use in constrained or untrusted environments such as minimal installations, containers, embedded systems, or potentially compromised hosts where standard tooling may not be available or reliable.

PRIONYX focuses on structured system visibility rather than exploitation. It collects and organizes critical host information, highlights permission-related risks, and surfaces process-level indicators that may warrant further investigation. Its primary objective is to support rapid triage by providing a clear and consolidated view of the system’s current state.

---

## Objectives

The primary goals of PRIONYX are:

* To enable fast and reliable system triage during incident response
* To provide a consolidated snapshot of host-level information
* To identify potentially risky configurations and artifacts
* To assist analysts in prioritizing areas for deeper investigation
* To function in environments with limited tooling or restricted access

PRIONYX is not intended to replace full forensic workflows. Instead, it serves as an initial assessment layer that helps guide subsequent analysis.

---

## Key Features

### System Information Collection

Retrieves essential host context including user identity, effective privileges, group memberships, hostname, kernel details, architecture, and process identifiers. This establishes a baseline understanding of the execution environment.

### Environment Variable Analysis

Enumerates environment variables and classifies them based on relevance. This helps highlight variables related to execution paths, privilege transitions, and user/session context.

### File Permission Enumeration

Scans selected directories to identify files with security-relevant permission configurations, including SUID, SGID, and writable executables. Findings are categorized and scored to assist prioritization.

### Process Inspection

Enumerates running processes using the `/proc` filesystem. Extracts metadata such as process name, binary path, UID, PPID, and file descriptor usage, along with heuristic indicators that may suggest unusual behavior.

### Extended Module Support

Includes additional modules for reviewing capabilities, scheduled tasks, login history, and network-related information.

### Modular Architecture

The codebase is organized into independent modules, enabling straightforward extension and maintenance.

### Single Binary Execution

Compiles into a standalone binary with no external dependencies, ensuring consistent execution across diverse Linux environments.

---

## Modules

* `system_info` — System and user context collection
* `env_scan` — Environment variable enumeration and classification
* `file_perm_enum` — Permission-based file analysis
* `process_scan` — Process enumeration and inspection
* `capability_scan` — File capability inspection
* `cron_scan` — Scheduled task enumeration
* `login_history` — Login activity inspection
* `network_scan` — Network and interface enumeration

---

## Installation

Compile all modules into a single executable:

```bash
gcc main.c modules/*.c -o prionyx
```

---

## Usage

Execute the binary:

```bash
./prionyx
```

For comprehensive coverage, execution with elevated privileges is recommended:

```bash
sudo ./prionyx
```

Running as root reduces permission-related limitations and improves visibility across system components.

---

## Example Output

```C
====== PRIONYX Defender Enumeration Tool v0.1 ======

====[SYSTEM INFORMATION SCAN]====

[+] User ID : 0
[+] Username : root
[+] Home Directory : /root
[+] Shell : /usr/bin/bash
[+] Hostname : arch
[+] Process ID : 16656
[+] Parent Process ID : 16655
[+] System Name : Linux
[+] Kernel Release : 6.19.11-arch1-1
[+] Architecture : x86_64
[!] Running as root — extended checks enabled


====[ENVIRONMENT VARIABLES SCAN]====

[HIGH importance ENV VARS]
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
LOGNAME=root
USER=root
HOME=/root

[Interesting ENV VARS]
XAUTHORITY=/run/user/1000/xauth_...
DISPLAY=:0


======[FILE PERMISSION ENUMERATION]======

========== SCAN SUMMARY ==========
Total interesting files : 87
High Risk   (>=6)       : 0
Medium Risk (3-5)       : 67
Low Risk    (1-2)       : 20
==================================

[5] /bin/mount.cifs                            | SUID_ROOT | SGID
[3] /bin/sudo                                  | SUID_ROOT
[3] /bin/passwd                                | SUID_ROOT
[3] /home/arch/.config/ticktick/config.json    | WORLD_WRITABLE


======[SUSPICIOUS PROCESS ENUMERATION]======

========== SCAN SUMMARY ==========
Total interesting processes : 56
High Risk   (>=6)           : 1
Medium Risk (3-5)           : 40
Low Risk    (1-2)           : 15
==================================

[6] systemd-udevd   | /usr/bin/udevadm                   | UID_ROOT ORPHAN_ROOT NAME_MISMATCH
[3] dockerd         | /usr/bin/dockerd                   | UID_ROOT ORPHAN_ROOT
[3] python3         | /usr/bin/python3.14                | UID_ROOT ORPHAN_ROOT
```

---

## Project Structure

```text
PRIONYX/
├── LICENSE
├── README.md
├── main.c
├── prionyx
└── modules/
    ├── capability_scan.c /.h
    ├── cron_scan.c /.h
    ├── env_scan.c /.h
    ├── file_perm_enum.c /.h
    ├── login_history.c /.h
    ├── network_scan.c /.h
    ├── process_scan.c /.h
    └── system_info.c /.h
```

---

## Future Work

Planned enhancements focus on improving integration with incident response workflows through structured data output and automated reporting.

A key planned feature is **native JSON output generation** from the PRIONYX binary. This will allow scan results to be captured in a structured, machine-readable format rather than only displayed in the terminal.

This will enable the following workflow:

1. PRIONYX performs system triage and generates structured JSON output
2. A separate Python-based reporting tool consumes the JSON data
3. The reporting tool generates a formatted PDF report summarizing the system state

The reporting layer is expected to include categorized findings such as system overview, process analysis, file permission risks, persistence mechanisms, and notable anomalies. This separation of responsibilities ensures that the C binary remains lightweight and focused on data collection, while higher-level reporting and presentation are handled externally.

---

## License

This project is released under the MIT License and is intended for educational, research, and defensive security use.
# TA1 Report - Prionyx

There are four things a triage system needs to do: 
1. detect malicious processes/files
2. identify what they are
3. reconstruct how they got there
4. build a timeline

opencode -s ses_f4612b69bffex30JFFPLjpHPMR

### Sources

1. [NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf)
2. [SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)
3. [Linux Matrix - MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/linux/)
4. [CAPA Project](https://mandiant.github.io/capa/)


### List of tags, so I can prioritize and rank/score them based on severity 

| Tag              | Observation                                           | Evidence source | Why interesting?                  | Legitimate cases                      | Context needed                | Initial priority |
| ---------------- | ----------------------------------------------------- | --------------- | --------------------------------- | ------------------------------------- | ----------------------------- | ---------------- |
| `SUID_ROOT`      | SUID root executable                                  | `stat()`        | Can execute with elevated UID     | Legitimate system binaries            | path, package owner, domain   | TBD              |
| `WORLD_WRITABLE` | World-writable executable/file                        | `stat()`        | Other users may modify it         | `/tmp`, application data, shared dirs | path, file type, domain       | TBD              |
| `MEMFD_EXEC`     | Executable mapped from memfd                          | `/proc/PID/exe` | Fileless execution                | rare legitimate uses                  | process, parent, network      | TBD              |
| `EXEC_DELETED`   | Running executable deleted from disk                  | `/proc/PID/exe` | Can indicate deleted malware      | upgrades/restarts                     | process age, package, parent  | TBD              |
| `NAME_MISMATCH`  | Process identity differs from executable              | `/proc`         | Possible masquerading             | legitimate renamed processes          | ancestry, cmdline, executable | TBD              |
| `ORPHAN_ROOT`    | Root process with unusual parent relationship         | `/proc`         | Could indicate detached execution | daemons/services                      | ancestry, service manager     | TBD              |
| `TMP_EXEC`       | Process executable originates from temporary location | `/proc/PID/exe` | Common execution staging area     | installers, legitimate temp programs  | signer/package/path/domain    | TBD              |

### False Positives that I usually encounter

| Signal                | Potential false positive   | How to distinguish                   |
| --------------------- | -------------------------- | ------------------------------------ |
| SUID                  | `/usr/bin/sudo`            | known system/package-owned binary    |
| SUID                  | Flatpak/container          | trust domain                         |
| deleted executable    | normal package upgrade     | process age + package ownership      |
| process name mismatch | legitimate daemon behavior | ancestry + executable                |
| `/tmp` execution      | installer                  | process ancestry + command line      |
| root process          | normal daemon              | parent/service relationship          |
| network listener      | legitimate service         | executable + port + service identity |
| cron                  | legitimate maintenance job | command ownership + path + user      |

## Notes

#### What to prioritize when collecting data?
- Develop a plan to acquire data
- Multiple potential data sources
- Analyst should create a plan based on prioritization
- Priority HIGH VALUE DATA > HIGHLY VOLATILE DATA > EASILY ACQUIREABLE DATA

### File Modification, Access, and Creation Times
- MAC(modification, access and creation) time collection is very important 
- If an analyst needs to establish an accurate timeline of events, then the file times should be preserved.
- The computerís clock does not have the correct time. For example, the clock may not have been
synchronized regularly with an authoritative time source.
- The time may not be recorded with the expected level of detail, such omitting the seconds or
minutes.
- An attacker may have altered the recorded file times.

### Other recommendations
- Analysts should examine copies of files, not the original files.
- Analysts should preserve and verify file integrity. 
- Analysts should rely on file headers, not file extensions, to identify file content types.

### What data can be collected from the OS?

#### Non Volatile Data
- Configuration Files - both OS configuration + application configuration
- Users and Groups
- Password Files
- Scheduled Jobs
- System Event logs
- Audit Records
- Application Events
- Command History
- Recently accessed Files
- Swap File
- Dump File - For errors in OS
- Hibernation File
- Temporary Files
- Network Shares

#### Volatile Data
- Memory Slack Space
- Free Space
- Network Configurations
- Network Connections
- Running Processes
- Open Files
- Login Sessions
- Operating System Time - Important for correlating events

-> In priority Order
1. Network connections
2. Login sessions
3. Contents of memory
4. Running processes
5. Open files
6. Network configuration
7. Operating system time
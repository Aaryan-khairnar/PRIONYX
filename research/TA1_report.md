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


### Tag prioritization 

| Tag              | Observation                                           | Evidence source | Why interesting?                  | Legitimate cases                      | Context needed                | Initial priority |
| ---------------- | ----------------------------------------------------- | --------------- | --------------------------------- | ------------------------------------- | ----------------------------- | ---------------- |
| `SUID_ROOT`      | SUID root executable                                  | `stat()`        | Can execute with elevated UID     | Legitimate system binaries            | path, package owner, domain   | TBD              |
| `WORLD_WRITABLE` | World-writable executable/file                        | `stat()`        | Other users may modify it         | `/tmp`, application data, shared dirs | path, file type, domain       | TBD              |
| `MEMFD_EXEC`     | Executable mapped from memfd                          | `/proc/PID/exe` | Fileless execution                | rare legitimate uses                  | process, parent, network      | TBD              |
| `EXEC_DELETED`   | Running executable deleted from disk                  | `/proc/PID/exe` | Can indicate deleted malware      | upgrades/restarts                     | process age, package, parent  | TBD              |
| `NAME_MISMATCH`  | Process identity differs from executable              | `/proc`         | Possible masquerading             | legitimate renamed processes          | ancestry, cmdline, executable | TBD              |
| `ORPHAN_ROOT`    | Root process with unusual parent relationship         | `/proc`         | Could indicate detached execution | daemons/services                      | ancestry, service manager     | TBD              |
| `TMP_EXEC`       | Process executable originates from temporary location | `/proc/PID/exe` | Common execution staging area     | installers, legitimate temp programs  | signer/package/path/domain    | TBD              |

### False Positives

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

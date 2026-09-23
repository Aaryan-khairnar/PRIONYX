# PRIONYX — Progress Report & Literature Review (Plain-English Edition)

> This version explains everything in simple words, like you're learning it for the first time — because you are, and that's completely normal three years into a five-year degree. Nobody starts out knowing how to design a data pipeline. You already wrote four working C modules that talk to the Linux kernel directly — that's genuinely not a small thing. What's missing is *structure*, not skill. This document walks through exactly what structure to add, one small idea at a time.

---

## 1. What Is PRIONYX, In One Paragraph

PRIONYX looks at a running Linux computer and asks two questions: "which files on this disk look dangerous?" and "which running programs look dangerous?" Right now it answers both questions by printing a big list to the screen. The list is *correct* — the facts in it are real — but it's not *useful* yet, because it doesn't tell you which of those facts actually matter together. Your job for the next phase is not to detect more things. It's to make the tool smarter about the things it already detects.

## 2. Why Are We Even Doing This In C?

This is a fair question to stop and ask, so let's actually answer it instead of assuming.

**What C gives you that a "normal" language (Python, Go, Rust) would make harder:**
- **Direct access, no middleman.** Everything PRIONYX does — reading `/proc/1234/status`, calling `stat()` on a file, reading raw bytes of an ELF header — is C talking straight to the Linux kernel through the exact same interface the kernel itself was written against. There's no interpreter, no garbage collector, no runtime sitting between your code and the operating system.
- **One tiny file, no install step.** A C program compiles into a single binary. You can copy that one file onto a server that has nothing else installed — no Python, no pip, no internet access — and it still runs. For a *security* tool, this matters a lot: if a machine is compromised, you often can't (and shouldn't) trust it to have a working package manager or network access to fetch dependencies.
- **This is genuinely how real tools in this space are built.** `chkrootkit`, `rkhunter`, and large parts of `auditd` are C or C-adjacent, for exactly the reason above. You're not choosing an unusual path — you're choosing the normal path for this specific kind of tool.

**What C makes harder (being honest about the cost):**
- No built-in "smart" data structures. Python has dictionaries and lists built in; C makes you build a hash map by hand if you want one (we'll do this, and it's simpler than it sounds — see Section 6.2).
- No built-in JSON. You either write a tiny JSON *writer* yourself (very doable, ~60 lines, see Section 5) or add a dependency (which fights your "single static binary" goal).
- Manual memory management means one wrong pointer can crash the whole scan. This is real, but it's also exactly the kind of bug-finding practice that's valuable for someone going into security work — you'll be *much* better at spotting real vulnerabilities in other people's C code after doing this.

**Bottom line:** C is the right choice for what PRIONYX is trying to be (a dependency-free host-triage binary). The extra manual work (building your own tiny data structures instead of importing them) is not wasted effort — it's the actual skill this project is meant to build.

## 3. What You Have Right Now — An Honest Read of Your Four Files

You called these "badly written." Having actually read them: they're not. They're **working, correct, single-purpose collectors** — every one of them successfully asks the kernel a real question and gets a real answer. What they're missing is not code quality, it's a *shared shape*. Let's go file by file.

### 3.1 `system_info.c` — verdict: fine as-is
This one just introduces the tool to the machine it's running on: who am I, what's the hostname, what kernel is this. It doesn't detect anything, so it doesn't need scoring or a `finding_t` — it's context, not evidence. Leave it structurally alone. Later, its output becomes the "header" of your JSON report (Section 5) rather than the first thing printed to the screen.

### 3.2 `env_scan.c` — verdict: good bucket system, one missing connection
You already built exactly the right idea here: a function (`is_critical_var`) that looks at each environment variable and puts it in a bucket (high/interesting/low). That *is* a tiny rule engine — you've already done this once without calling it that.

The one gap: you detect `LD_` variables (which includes `LD_PRELOAD`, a real library-injection technique — see Section 9) but nothing currently *uses* that fact. Later, the correlator (Section 6.2) should be able to ask "was `LD_PRELOAD` set for this process?" That means `env_scan` needs to save its finding somewhere another module can read it, not just print it to the screen and forget it.

### 3.3 `file_perm_enum.c` — verdict: solid detection logic, needs restructuring
Look at what `is_result_interesting()` actually does: it checks real permission bits (`S_ISUID`, `S_IWOTH`, etc.) using the actual, correct kernel-level way to check them. That part is right. The problems are all *structural*, not logical:

1. **Everything is one global array, sized by guess.** `struct FileMetadata result[MAX_FILES]` with `MAX_FILES 10000` — if a scan ever finds more than 10,000 interesting files, it silently stops storing new ones (you already print a warning for this, which is good practice, but it's still a ceiling that shouldn't exist).
2. **You throw away timestamps you already have.** `struct stat st` — the variable you're already calling `stat()` on — contains `st.st_mtime` (last modified) and `st.st_ctime` (last metadata change) for free. You call `stat()`, get these fields handed to you, and then never copy them into `struct FileMetadata`. This is the single easiest, highest-value line to add, because it's the raw material for your entire Timeline feature (Section 6.4) and it costs you nothing — the data is already sitting in memory.
3. **Scoring and printing are welded together.** `print_results()` does formatting *and* is the only place the sorted, scored data exists. If you want to output JSON instead of a console table, right now you'd have to rewrite this whole function instead of just adding a second, separate "write as JSON" function that reads the same array.
4. **No concept of "where" a file lives, beyond its raw path string.** This is the false-positive problem from your first scan — a SUID binary inside a Flatpak sandbox gets treated identically to a real SUID binary in `/usr/bin`, because nothing in the struct records the difference.

None of these are "bad code." They're the normal first version of a tool, before you know what the second version needs. Now you know.

### 3.4 `process_scan.c` — verdict: honestly, better than average — keep this logic
This is the strongest of your four files. Look at what you already check: `MEMFD_EXEC`, `EXEC_DELETED`, `HIDDEN_CMDLINE`, `TMP_EXEC`, `NAME_MISMATCH`, `BASE64_DECODE`, `DEV_TCP_SHELL`. Every one of these is a real, deterministic, "proof not signature" indicator — several of these are the *exact* techniques described in the research papers in Section 9 (memfd fileless execution, deleted-binary execution, name masquerading). You independently arrived at real forensic techniques. That's a genuinely good sign for where this project is headed.

Three concrete, fixable issues:
1. **You never read `/proc/<pid>/stat`.** You read `status`, `cmdline`, `exe`, `cwd`, and count `fd` entries — but `stat` (a *different* file from `status`, confusingly named by Linux, not by you) is where field 22 (`starttime`) lives — the process's start time, needed for the Timeline. Right now there's no way to know *when* a suspicious process started.
2. **`strcat(p->issues, "UID_ROOT ")` has no bounds checking.** `p->issues` is `char[256]`. Right now you have at most ~10 possible tags and they fit, so nothing breaks today — but `strcat` doesn't know where the end of the buffer is, so if you add a couple more checks later without noticing, you get a buffer overflow. In a security tool, a memory-safety bug in the *detector itself* is exactly the kind of thing an examiner will point out. Simple fix later: switch to `strncat(p->issues, "UID_ROOT ", sizeof(p->issues) - strlen(p->issues) - 1)`, the same pattern you already use correctly in `file_perm_enum.c`'s `add_issue()`. You've already written the safe version once — just copy that habit over.
3. **Detection and storage are one function.** Same issue as `file_perm_enum.c` — `is_presult_interesting()` decides *and* scores *and* writes strings, all at once. This is fine for a first pass, but it's why adding a JSON output means touching this function instead of adding beside it.

## 4. The Big Idea: One Common "Form" Every Module Fills Out

Here's the core problem in one sentence: **`file_perm_enum.c` and `process_scan.c` each invented their own private way of describing "something suspicious," so nothing can compare them to each other.**

Think of it like this: imagine two security guards at a building, each keeping notes in their own personal notebook, in their own handwriting, using their own shorthand. At the end of the day, nobody can quickly check "did guard A and guard B both notice something about the same door?" — because their notes aren't in a shared format. The fix isn't to make either guard write *more* — it's to give both guards the same standard incident report form.

That form, in PRIONYX, is a single C `struct` — let's call it `finding_t` — that both `file_perm_enum.c` and `process_scan.c` fill out instead of printing straight to the screen.

```c
typedef struct {
    char   subject[512];       // what this finding is about: a file path, or "pid:1234"
    char   subject_type[16];   // "file" or "process" — which kind of thing is this?
    char   tags[8][32];        // the short labels, e.g. "SUID_ROOT", "MEMFD_EXEC"
    int    tag_count;          // how many of the 8 slots above are actually filled in
    int    trust_domain;       // a number meaning "host", "container", "flatpak", etc. (Section 6.1)
    long   evidence_time;      // a timestamp — when did this happen? (Section 6.4)
    int    score;              // the number you already compute today
} finding_t;
```

That's it. That's the whole idea. Every field on this form already exists somewhere in your current code — you're not inventing new detection logic, you're just agreeing on one shape for the answer.

**Here's exactly how your existing fields map onto it:**

| Your field today | Which file | Goes into `finding_t` as |
|---|---|---|
| `f.path` | `file_perm_enum.c` | `subject` |
| `f.issue` (a string like `"SUID_ROOT \| SGID"`) | `file_perm_enum.c` | split apart into `tags[]` — one tag per slot instead of one long string |
| `f.score` | `file_perm_enum.c` | `score` |
| `st.st_mtime` / `st.st_ctime` (available now, not yet saved) | `file_perm_enum.c` | `evidence_time` — **this is the field you need to add** |
| `p->binpath` or `"pid:%d"` from `p->pid` | `process_scan.c` | `subject` |
| `p->issues` (a string like `"UID_ROOT ORPHAN_ROOT "`) | `process_scan.c` | split apart into `tags[]` |
| `p->score` | `process_scan.c` | `score` |
| *(doesn't exist yet — needs `/proc/<pid>/stat` field 22)* | `process_scan.c` | `evidence_time` — **needs new code** |

Once both files fill the *same* struct, you can put every file-finding and every process-finding into one array and sort, filter, and compare them the exact same way, with the exact same code.

## 5. Why JSON, And What It Actually Is

If you've never really used JSON before: it's just plain text, written so both humans and programs can read it, that stores information as `"label": value` pairs, nested inside `{ }` and `[ ]`. Nothing more mysterious than that. Your `finding_t` struct above, written as JSON, looks like this:

```json
{
  "subject": "/bin/sudo",
  "subject_type": "file",
  "tags": ["SUID_ROOT"],
  "trust_domain": 0,
  "evidence_time": 1758099600,
  "score": 3
}
```

Why bother, if you already have the struct? Because a struct only exists *inside your running C program* — the moment the program ends, it's gone. Writing it as JSON to a file (or printing it) means: (1) you have a permanent record you can look at later, and (2) if you ever wanted a different program (even a simple Python script, for a demo or a graph) to read PRIONYX's results, JSON is a format basically everything can read.

**You do not need a JSON *library*.** Since every field in `finding_t` is a fixed, known shape (a string, a number, a small fixed list), you can write it out yourself with plain `fprintf`, one field at a time:

```c
void print_finding_as_json(finding_t *f, FILE *out) {
    fprintf(out, "{\"subject\":\"%s\",\"score\":%d,\"tags\":[", f->subject, f->score);
    for (int i = 0; i < f->tag_count; i++) {
        fprintf(out, "%s\"%s\"", i > 0 ? "," : "", f->tags[i]);
    }
    fprintf(out, "]}\n");
}
```

That's genuinely the whole trick. One line per finding, in a file — this format is called **NDJSON** (Newline-Delimited JSON), and it's exactly the format `docker logs`, many security tools, and log pipelines use, because you can write one line at a time as you go instead of building one giant JSON blob in memory.

**One decision to make and not worry about further:** you don't need to *read* JSON back into C (JSON parsing in C is the genuinely fiddly part, not writing it). Keep passing `finding_t` structs directly between your own functions in memory — only turn them into JSON right at the very end, as the final report. This avoids the hard part of JSON entirely while still giving you the shareable-format benefit.

## 6. The Four New Pieces You Need To Build

You asked specifically what to feed into "the comparer" — this section is that answer, piece by piece, in plain English first, with the mechanics after.

### 6.1 The Trust-Domain Classifier — "which neighborhood is this file in?"

Plain-English version: before you decide a file is scary, first figure out *where* it actually lives. A knife on a kitchen counter and a knife on a doorstep mean different things, even though it's the "same fact" (a knife exists here). Your `/var/lib/flatpak/.../spotify` false positive from before is a knife-on-the-kitchen-counter problem — a file that's dangerous-looking but is actually sitting inside a sandbox where it can't do the thing the flag implies.

The simplest version: check the start of the path string.
```c
if (strncmp(path, "/var/lib/flatpak/", 18) == 0) domain = FLATPAK;
else if (strstr(path, "/.local/share/containers/") != NULL) domain = CONTAINER_OVERLAY;
else domain = HOST;
```
That's genuinely enough to fix most of your current false positives, and it's simple enough to build in an afternoon.

The stronger, "real proof" version (optional, do it later if time allows): instead of trusting the *path string* (which could theoretically be tricked with a symlink), ask the Linux kernel directly what filesystem a path is actually sitting on, using `statfs()`:
```c
#include <sys/vfs.h>
struct statfs sfs;
statfs(path, &sfs);
// sfs.f_type tells you the REAL filesystem type as a number, e.g.:
// 0x794c7630 means "this is a container overlay filesystem" — a hard fact, not a guess from the path spelling
```
Think of the difference like this: reading the path string is like reading the label on a box. Calling `statfs()` is like actually opening the box and checking what's inside. Both usually agree, but the second one can't be fooled by a mislabeled box.

### 6.2 The Correlator ("the comparer") — this is your direct question, answered fully

**What exactly goes in?** Every `finding_t` you produced in Section 4, from *every* module — files, processes, and (once you build them) cron entries, network sockets, and environment-variable flags. The correlator doesn't care which module a finding came from. It only cares about two fields: `subject` (for files/paths) and, for processes, the `pid`.

**How it actually works, in plain English:** imagine a phone book, but instead of names, the "index" is a file path or a process ID, and instead of a phone number, each entry has a list of "which findings mention this same thing." That's it — that's a hash map. In practice:

1. Make one big list (a table) where the key is a path or a pid, and the value is a list of finding indexes that mention it.
2. Walk through every finding you collected. For each one, add it to the table under its `subject`.
3. Afterward, walk through the table. Any key with **more than one finding attached to it** is interesting — it means two different modules independently noticed something about the *same* file or process.

**A concrete example using data you already produce:** say `process_scan.c` flags pid 4821 with tag `TMP_EXEC` because its binary runs from `/tmp/x`. Separately, `file_perm_enum.c` flags `/tmp/x` itself with tag `WORLD_WRITABLE`. Right now, these are two disconnected facts in two disconnected lists. In the correlator, both findings share the same `subject` string (`/tmp/x`), so they land in the same phone-book entry. That tells you: *this isn't just a process running from a weird place — the file it's running from is also writable by anyone.* Those two facts together are much scarier than either alone, and the correlator is the only place that can notice this, because neither individual module has any way to see what the other module found.

**What data specifically to feed it — the exact field list:**
- From `file_perm_enum.c`: `subject` = file path, plus every tag currently in `f.issue`.
- From `process_scan.c`: `subject` = the process's resolved binary path (`p->binpath`) **and separately** `"pid:" + p->pid` as a second subject, since a process can be matched either by what binary it's running (compare to file findings and cron findings) or by its pid (compare to network and capability findings).
- From `cron_scan` (once built the same way): `subject` = whatever command path the cron entry runs — this is what lets you connect a running process back to a persistence mechanism.
- From `network_scan` (once built the same way): `subject` = `"pid:" + owning_pid` of the socket, so it lines up with a process finding.
- From `capability_scan` (once built the same way): same — `"pid:" + pid`.
- From `env_scan.c`: doesn't need a `subject` in the same sense, but should expose a simple yes/no fact like "was `LD_PRELOAD` set" that the correlator can attach to whichever process is currently running (since env vars belong to a process, via `/proc/<pid>/environ`).

That's genuinely everything. You don't need more fields than "what is this about" (`subject`) and "what did we notice" (`tags`) for a correlator to already provide real value.

### 6.3 The Rule Engine — turning "if this AND this, then flag" into actual code

Plain-English version: you already do this by hand inside `is_result_interesting()` and `is_presult_interesting()` — each `if` statement *is* a rule. The only change is moving these rules out of the detection function and into a plain list, so adding a new rule later doesn't mean editing C logic, just adding one line to a table.

Using tags you already produce, here's what a rule table looks like, in the simplest form — just a list of "if you see these tags together, add this much score":

| If a finding has these tags... | ...and it's NOT in this trust domain... | Add this score | Because |
|---|---|---|---|
| `SUID_ROOT` | Container / Flatpak | +5 | Real host SUID binary — the classic privilege-escalation surface |
| `WORLD_WRITABLE` | (any) | +5 | Anyone can rewrite this file |
| `TMP_EXEC` + the process's binary is also flagged `WORLD_WRITABLE` (from the correlator, Section 6.2) | (any) | +10 | Not just running from `/tmp` — running from a file anyone could have swapped out |
| `MEMFD_EXEC` | (any) | +8 | Fileless execution — no file on disk means nothing to scan later |
| A process's binary path also matches a `cron_scan` entry (a correlator match) | (any) | +6 | This isn't just a weird process — it's set up to survive a reboot |

In code, this is just an array of small structs, checked one at a time — no "engine" in the scary sense, just a loop:
```c
typedef struct {
    const char *needs_tag;      // must have this tag
    int         exclude_domain; // skip this rule if the finding is in this trust domain (-1 = no exclusion)
    int         add_score;
} rule_t;

rule_t rules[] = {
    { "SUID_ROOT", CONTAINER_OVERLAY, 5 },
    { "WORLD_WRITABLE", -1, 5 },
    { "MEMFD_EXEC", -1, 8 },
};

// then, for each finding:
for (int r = 0; r < num_rules; r++) {
    if (finding_has_tag(f, rules[r].needs_tag) && f->trust_domain != rules[r].exclude_domain) {
        f->score += rules[r].add_score;
    }
}
```
Start with 5–8 rules covering tags you already have. You can grow the table forever without ever touching `file_perm_enum.c` or `process_scan.c` again — that separation is the entire point.

### 6.4 The Timeline — "what happened first?"

Plain-English version: once every finding has an `evidence_time` (Section 4's struct), the timeline is just: put every finding in one list, and sort that list by time instead of by score. That's genuinely the whole feature at its simplest.

The one tricky bit is that process start time isn't stored as a normal date — it's stored as "clock ticks since the computer booted," a detail of how Linux happens to record it. To turn it into a real date, you need two extra pieces of information: how many ticks happen per second (`sysconf(_SC_CLK_TCK)`, almost always 100), and how long the computer has been on (read from `/proc/uptime`). Then:
```
computer's boot time  = right now - how long it's been on
process's real start time = boot time + (ticks the process started at ÷ ticks per second)
```
This is worth its own small helper function, tested once against a process you know the actual start time of, because a units mistake here (mixing "ticks" and "seconds") gives you a timeline that's silently wrong instead of obviously broken.

## 7. Full Data Dictionary — Every Field, What You Have, What's Missing

This is the direct, complete answer to "what data should I input into the comparer, cover everything."

**File findings** (from `file_perm_enum.c`):

| Field | Status | Notes |
|---|---|---|
| Path | ✅ have (`f.path`) | |
| UID / GID | ✅ have | |
| Permission bits (SUID/SGID/writable/etc.) | ✅ have | This is your existing, correct logic |
| Score | ✅ have | |
| Inode + device (for dedup) | ✅ have | Keep this — it's a smart detail you already got right |
| **Modification/change time** | ❌ missing, but data already exists in `st.st_mtime`/`st.st_ctime` | One-line fix — needed for Section 6.4 |
| **Trust domain** | ❌ missing, needs new code | Section 6.1 |
| Package-manager ownership (optional, later) | ❌ missing, optional | Run `dpkg -S <path>` and check if it succeeds |

**Process findings** (from `process_scan.c`):

| Field | Status | Notes |
|---|---|---|
| PID, PPID, UID | ✅ have | |
| Resolved binary path (`exe`) | ✅ have | Correctly detects `(deleted)` and `memfd:` already |
| Command line | ✅ have | |
| Name vs. binary mismatch | ✅ have | |
| File descriptor count | ✅ have | |
| Score, issue tags | ✅ have | |
| **Process start time** | ❌ missing, needs `/proc/<pid>/stat` field 22 | Section 6.4 |
| Memory region permissions (RWX check) | ❌ missing, needs `/proc/<pid>/maps` | Good next-module addition, catches injected/unpacked code |
| Effective capabilities | Partially — separate module `capability_scan.c` exists but isn't linked to this pid yet | Needs to be joined via the correlator (Section 6.2), not rebuilt |
| Whether `LD_PRELOAD` was set for this process | Partially — `env_scan.c` can see this for *your own* environment, but not per-process yet | Needs reading `/proc/<pid>/environ`, matched by pid |

**Cross-cutting context** (from `system_info.c` and `env_scan.c`): these don't need scores of their own. Their job is to give the correlator *baseline facts* to compare against — e.g., "the current user's UID is 1000" lets a rule flag a root-owned (`UID_ROOT`) process as more unusual on a system where the logged-in user is normally unprivileged.

## 8. Literature Review

Organized around the four things a triage system needs to do: **detect** malicious processes/files, **identify** what they are, **reconstruct** how they got there, and **build a timeline**.

### 8.1 Existing Linux IR / triage tools (prior art for architecture)
*In plain terms: other people's tools that do pieces of what you're building — good to compare against, not to copy code from.*
- **UAC** (Unix-like Artifacts Collector) — native-binary-only live-response collector across Linux/BSD/AIX/Solaris/ESXi; architecturally closest to PRIONYX, but purely a raw-artifact dumper with no scoring or correlation layer — the gap PRIONYX aims to close. https://github.com/tclahr/uac
- **GRR Rapid Response** — Google's remote live-forensics framework for fleet-wide triage. https://grr-doc.readthedocs.io/
- **Cyber Triage** — commercial platform; reference for a correlation model (heuristics + hash reputation + YARA/Sigma feeding a scoring engine that promotes "suspicious" items once related events appear).
- **Sandfly Security** — Linux-only agentless EDR built specifically around anti-forensic techniques (memfd, masquerading, deleted binaries); their blog is a strong primary source for concrete detection commands. https://sandflysecurity.com/blog/
- **log2timeline / Plaso** — the reference "super-timeline" engine: normalizes many artifact types into one merged chronological record. Direct model for PRIONYX's planned timeline assembler. https://github.com/log2timeline/plaso
- **SANS FOR577** — course syllabus is a good checklist for what a rapid Linux triage pass should cover. https://www.sans.org/cyber-security-courses/linux-threat-hunting-incident-response

### 8.2 Runtime/kernel-level detection (eBPF)
*In plain terms: newer tools that watch the kernel live, instead of checking files after the fact.*
- **Falco** (CNCF) — rules engine over kernel syscall events; explicit rules for memfd fileless execution and shell-in-container. https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/
- **Tetragon** (Cilium) — same model with in-kernel enforcement (can block, not just alert).
- **Tracee** (Aqua Security) — built-in signatures for LD_PRELOAD/dlopen injection, kernel module loads, ptrace/mmap/mprotect memory-injection patterns.
- **Adversarial angle**: kernel rootkits that hook the functions eBPF tooling depends on, blinding detection from inside the kernel — relevant to any claim PRIONYX makes about "how the incident happened." https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion

### 8.3 Attack reconstruction / timeline construction (provenance graphs)
*In plain terms: academic work on automatically drawing "who did what to whom" diagrams from log data.*
- **BackTracker**, **PrioTracker** — backward/forward causality tracing to find intrusion entry points.
- **SLEUTH** (USENIX Security 2017) — real-time reconstruction from ordinary auditd-style logs (no custom instrumentation needed).
- **HOLMES**, **UNICORN**, **ProvDetector** — high-level abstraction, unsupervised streaming anomaly detection, and rare-path embedding approaches respectively.
- Recent (2024–2025): **ANUBIS** (supervised causality matching), **RT-APT** (graph kernels for real-time scaling), **MGDA** (self-supervised graph representation + ATT&CK-stage matching), **TPPR** (99.9% graph simplification while retaining 91% of true attack nodes — directly relevant if PRIONYX's timeline output needs to stay human-readable).

### 8.4 Linux/ELF malware family classification
*In plain terms: research on figuring out which malware "family" a suspicious file belongs to.*
- Most public research targets IoT-class ELF botnets (Mirai, Gafgyt, Tsunami, XorDDoS) due to labeled VirusTotal corpora, but feature-extraction methodology transfers to general Linux malware: ELF header + opcode n-gram ML frameworks, entropy-based cross-architecture classifiers (F1 = 0.97 across Gafgyt/Mirai/Tsunami), and raw-byte-sequence models.
- **Mandiant `capa`** — rule-based (not ML) capability matching over static features (imports, strings, control flow); ELF-supported since v3. The declarative rule format (feature + logic tree) is the direct model for PRIONYX's planned rule engine (Section 6.3). https://github.com/mandiant/capa-rules

### 8.5 Fileless / anti-forensic technique detection
*In plain terms: how attackers hide, and how to notice anyway. You already implement several of these.*
- **`memfd_create()` fileless execution** — malware executes from an anonymous fd; detectable via `/proc/<pid>/exe` resolving to `memfd:<name> (deleted)`. Your `MEMFD_EXEC` check already does this. https://sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics
- **Kernel-thread masquerading** — a process named like a kernel thread (`[kworkerd]`) but with a populated `/proc/<pid>/maps` is not a real kernel thread.
- **argv[] overwrite masquerading** and **LD_PRELOAD/dlopen injection** — both directly checkable from `/proc` without kernel instrumentation.

### 8.6 Threat landscape context (2026)
- SANS's 2026 writeup on a real supply-chain incident (1,500+ poisoned AUR packages, Rust infostealer, eBPF rootkit hiding kernel-level traces) frames Linux binary triage as two questions: *how did this get here* and *what does it do* — maps directly onto PRIONYX's root-cause vs. identification split. https://www.sans.org/blog/investigating-ai-tools-modern-linux-intrusions

### 8.7 Non-signature, "structural proof" classification — where the Section 9 parameters come from
- **GTFOBins** (https://gtfobins.github.io/) — a community-maintained list of exactly which standard Linux commands can be abused for privilege escalation if they have SUID rights or certain permissions. In plain terms: it turns a bare "this file has the SUID bit" fact into "and here's specifically how that could be abused" — very useful for turning your `SUID_ROOT` tag into something more specific.
- **Cross-view diff-based rootkit detection** — the classic trick of asking the same question two different ways and seeing if you get two different answers (e.g., "how many processes exist according to `/proc`?" vs. "how many according to another kernel interface?"). If the two disagree, something is hiding one of the answers from you — that disagreement *is* the proof, no signature needed.
- **MITRE ATT&CK for Linux** (https://attack.mitre.org/matrices/enterprise/linux/) — the standard naming system security people use for attack techniques. Tagging your rules with these IDs (Section 6.3) makes your report look and read like professional security tooling.
- **MITRE Detection Strategy DET0164** — https://attack.mitre.org/detectionstrategies/DET0164 — the official write-up of the exact "cmdline vs. binary vs. ancestry" logic behind your `NAME_MISMATCH` check.

## 9. Concrete Parameter Reference — Every "Real Proof" Signal, In One Place

The rule for this whole table: every row is something you can check with a plain system call or file read — nothing here is a guess, a hash lookup, or a machine-learning score.

### 9.1 Process parameters

| Parameter | How you get it | What it tells you | Do you have this? |
|---|---|---|---|
| `/proc/<pid>/exe` target | `readlink()` | Fileless execution (`memfd:`) or self-deleted binary (`(deleted)`) | ✅ yes |
| Name vs. binary path mismatch | Compare `comm` to `exe` | Possible masquerading | ✅ yes |
| Parent process chain to PID 1 | Follow `ppid` repeatedly | Orphaned/detached process | ✅ have `ppid`, could extend to full chain |
| Parent's identity vs. expected role | Compare parent's name to a small table (e.g. web server shouldn't parent a shell) | Classic web-shell pattern | ❌ not yet — needs a small lookup table |
| Effective UID vs. expected | `/proc/<pid>/status` → `Uid` | Privilege escalation | ✅ yes |
| Capabilities held | `/proc/<pid>/status` → `CapEff` | Process with more power than it should have | Partially — separate module, needs joining |
| Memory region permissions | `/proc/<pid>/maps` | Injected/unpacked code (regions that are both writable and executable) | ❌ not yet |
| Command line vs. ancestry | `/proc/<pid>/cmdline` | argv rewrite masquerading | ✅ partially (you check for content, not full ancestry match) |
| `LD_PRELOAD` set | `/proc/<pid>/environ` | Library-injection persistence | Partially — `env_scan.c` checks your own env, not per-process yet |
| File descriptor targets | `readlink()` each `/proc/<pid>/fd/*` | Descriptors to memfd/deleted/`/dev/shm` targets | ❌ you count fds but don't inspect what they point to |
| Persistence tie-back | Compare binary path to cron/systemd entries | Ties a process to a survive-reboot mechanism | ❌ needs correlator (Section 6.2) |
| Start time | `/proc/<pid>/stat` field 22, converted (Section 6.4) | Timeline placement | ❌ not yet |

### 9.2 File parameters

| Parameter | How you get it | What it tells you | Do you have this? |
|---|---|---|---|
| SUID/SGID/world-writable bits | `stat()` mode bits | Direct privilege/tampering risk | ✅ yes |
| Modification/change time | `st.st_mtime` / `st.st_ctime` | Timeline placement | Data exists, not saved yet |
| Trust domain | Path prefix, or `statfs()` (Section 6.1) | Real host file vs. container/sandbox noise | ❌ not yet — biggest immediate win |
| GTFOBins match | Look up the filename in a small hardcoded list | Whether a SUID bit is a *known* privilege-escalation vector | ❌ optional, later |
| Package ownership | `dpkg -S <path>` (optional shell-out) | A file not owned by any package is riskier than one that is | ❌ optional, later |
| ELF header sanity (architecture, entry point) | Parse the raw ELF header bytes | Cross-architecture droppers, packed/obfuscated binaries | ❌ future module, not urgent for this deadline |

## 10. Rewrite Plan, File By File

**`file_perm_enum.c`** — smallest, highest-value change set:
1. In `store_res()`, copy `st.st_mtime` and `st.st_ctime` into `FileMetadata` (two new fields, two new lines).
2. Write one new function, `int classify_trust_domain(const char *path)`, that returns a number based on path prefixes (Section 6.1). Call it once per file, store the result.
3. Leave `is_result_interesting()` exactly as it is — your scoring logic doesn't need to change yet, just gains two more fields to carry.
4. Add one new function, `void export_findings_json(FILE *out)`, that loops over `result[]` and prints each as one JSON line (Section 5). Keep `print_results()` working exactly as it does today — you're adding a second output, not replacing the first.

**`process_scan.c`**:
1. Add a new function `void read_stat_starttime(struct process *p)` that opens `/proc/<pid>/stat`, reads field 22, and converts it using the formula in Section 6.4.
2. Swap the unbounded `strcat()` calls in `is_presult_interesting()` for `strncat()`, matching the safe pattern you already use in `file_perm_enum.c`'s `add_issue()`.
3. Add the same kind of `export_findings_json()` function as above.

**`env_scan.c`**: no urgent changes — it already works. When you build the correlator, add one small function `int env_has_ld_preload(int pid)` that reads `/proc/<pid>/environ` for a *specific* process (not just your own environment) — this is new code, not a rewrite of what's there.

**`system_info.c`**: no changes needed. Its output becomes the header of your final JSON report.

**New files to add** (don't touch the four above for these):
- `trust_domain.c` — the classifier from Section 6.1.
- `correlator.c` — the phone-book/hash-map logic from Section 6.2.
- `rules.c` — the rule table and evaluator from Section 6.3.
- `timeline.c` — the sort-by-time output from Section 6.4.

Keeping these as separate new files, rather than folding the logic into your existing four modules, means your working code stays working the entire time you're building this — you can test each new piece independently before wiring it in.

## 11. Three-Day Weekend Plan

**Day 1 — the two easiest, highest-payoff edits**
- [ ] Add `mtime`/`ctime` fields to `file_perm_enum.c`'s struct and copy them in `store_res()`.
- [ ] Write `classify_trust_domain()` (path-prefix version first) and call it from `file_perm_enum.c`.
- [ ] Rerun your scan, manually check: does the Flatpak/container noise now get tagged differently from real host SUID files? (You don't need scoring changes yet — just confirm the classification itself is correct before building on it.)

**Day 2 — bring `process_scan.c` up to the same standard**
- [ ] Add `read_stat_starttime()` and convert to wall-clock time.
- [ ] Fix the `strcat` → `strncat` safety issue.
- [ ] Add `export_findings_json()` to both `file_perm_enum.c` and `process_scan.c`, and run both, confirming you get valid-looking JSON lines out.

**Day 3 — build the correlator and one small rule table**
- [ ] Write `correlator.c`: read both JSON files (or, simpler, keep both `finding_t` arrays in memory in one combined `main.c` run) and build the path/pid lookup table from Section 6.2.
- [ ] Write 5–8 rules in `rules.c` using tags you already produce (Section 6.3's table is a ready-made starting list).
- [ ] Run the whole pipeline once, top to bottom, and write up what changed for your report — the Day 1 before/after is your strongest piece of evidence that the redesign actually works, not just that it exists on paper.

**If you get through all of that with time left:** add the `/proc/<pid>/maps` RWX check (Section 9.1) — it's a genuinely new detection, not a restructuring task, so it's good bonus material for the report if Days 1–3 go smoothly.

## 12. Open Questions / Discussion Points for the Report
- Why rule-based scoring over ML classification, given the pure-C, no-dependency goal (Section 2's cost/benefit reasoning applies directly here too).
- How PRIONYX's planned trust-domain + correlation layers differ from UAC's "collect everything, judge nothing" model.
- What the smallest useful version of a "provenance graph" looks like for a semester-scope tool (the phone-book/hash-map in Section 6.2, not the full academic graph-ML machinery in Section 8.3).
- Why timestamps were missing in v0.1 despite the data already being available (`st.st_mtime`) — a good, honest paragraph for a "lessons learned" section.

## 13. Reference List
- https://github.com/tclahr/uac
- https://grr-doc.readthedocs.io/
- https://www.cybertriage.com/blog/best-incident-response-tools-2026/
- https://sandflysecurity.com/blog/
- https://remnux.org/
- https://github.com/log2timeline/plaso
- https://www.sans.org/cyber-security-courses/linux-threat-hunting-incident-response
- https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/
- https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion
- https://arxiv.org/pdf/2112.11032 (ANUBIS)
- https://www.sciencedirect.com/science/article/abs/pii/S1084804524002133 (RT-APT)
- https://www.sciencedirect.com/science/article/pii/S1389128625007728 (MGDA)
- https://arxiv.org/pdf/2510.22191 (TPPR)
- https://github.com/mandiant/capa
- https://github.com/mandiant/capa-rules
- https://sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics
- https://blog.apnic.net/2020/04/27/detecting-linux-kernel-process-masquerading-with-command-line-forensics
- https://attack.mitre.org/detectionstrategies/DET0164
- https://attack.mitre.org/matrices/enterprise/linux/
- https://www.sans.org/blog/investigating-ai-tools-modern-linux-intrusions
- https://gtfobins.github.io/

---

## How to combine the whole thing together

Good — that instinct (module → own struct, correlator → merges via a shared key) is exactly right. Let's make it mechanical, because right now it probably feels like magic and it isn't.

**The one rule that makes multi-file C possible**

A `.c` file is private by default. Nothing in `file_perm_enum.c` is visible to `main.c` or `process_scan.c` unless you explicitly say so — and you say so through the `.h` header file. The header is a *promise*: "somewhere, there's a function/struct with exactly this shape." The `.c` file is the *actual implementation* of that promise. When everything compiles and links together, the linker matches up every promise with its implementation.

Here's the smallest possible example of this, ignoring your project entirely, just to see the mechanic:

```c
// counter.h  — the promise
int get_count(void);

// counter.c  — the implementation
static int secret_count = 42;   // "static" = truly private, only this file can touch it
int get_count(void) {
    return secret_count;        // this is the ONLY way outside code can see it
}

// main.c  — the user
#include "counter.h"
#include <stdio.h>
int main(void) {
    printf("%d\n", get_count());  // works, even though main.c never sees secret_count itself
}
```

That's the whole trick. Your `result[MAX_FILES]` array in `file_perm_enum.c` is currently like `secret_count` — totally invisible outside that file, which is exactly why `main.c` can't hand it to a correlator right now.

**Step 1 — give each module a "handout" function**

In `file_perm_enum.h`, add one line:
```c
int get_file_results(struct FileMetadata **out);
```
In `file_perm_enum.c`, add the matching function:
```c
int get_file_results(struct FileMetadata **out) {
    *out = result;      // hand out the address of your existing array
    return filecount;   // and how many entries are actually filled in
}
```
Do the exact same thing in `process_scan.c` / `process_scan.h` for `resultprocess`. Now `main.c` can do:
```c
#include "file_perm_enum.h"
#include "process_scan.h"

struct FileMetadata *files;
int file_count = get_file_results(&files);

struct process *procs;
int proc_count = get_process_results(&procs);
```
`main.c` now has real access to both arrays, without either module needing to know the other exists. This is step one, and you can do it today, it's maybe 10 minutes of typing.

**Step 2 — teach each module to write JSON, without touching what it already does**

Add one new function per module. Don't remove `print_results()` — just add beside it:
```c
// in file_perm_enum.c
void export_file_findings_json(FILE *out) {
    for (int i = 0; i < filecount; i++) {
        fprintf(out,
            "{\"module\":\"file\",\"subject\":\"%s\",\"score\":%d,\"issues\":\"%s\",\"uid\":%d}\n",
            result[i].path, result[i].score, result[i].issue, result[i].uid);
    }
}
```
Same pattern in `process_scan.c`, just with `p.binpath`, `p.pid`, `p.score`, `p.issues` instead. The `"module":"file"` / `"module":"process"` field is what lets one shared output file (or a Python script reading it later) tell the two kinds of records apart.

**Step 3 — wire it all together in `main.c`**

This is the orchestration, and it's genuinely just calling things in order:
```c
int main(void) {
    file_perm_enum_scan();      // fills result[] like it does now
    run_process_scan();         // fills resultprocess[] like it does now

    FILE *out = fopen("findings.json", "w");
    export_file_findings_json(out);
    export_process_findings_json(out);
    fclose(out);

    // correlator gets its data directly from memory, no JSON parsing needed:
    struct FileMetadata *files; int fc = get_file_results(&files);
    struct process *procs;      int pc = get_process_results(&procs);
    run_correlator(files, fc, procs, pc);
}
```
Notice: the JSON file is written **for humans and for your future Python script** — the correlator itself never reads that file back in. It works straight off the live arrays, still in memory, in the same run. That's the piece that avoids needing a JSON *parser* in C, which we agreed to skip.

**Where `correlator.c` fits**

It's a brand new file, with its own `.h`/`.c` pair, that takes the arrays as arguments (like `run_correlator(files, fc, procs, pc)` above) and does the matching we talked about — build a table keyed by path/pid, find entries that appear in more than one array, and build the merged `case_t` records. It doesn't touch `file_perm_enum.c` or `process_scan.c` at all, and they don't know it exists. That's the whole reason Step 1's "handout function" pattern matters — it's what lets a completely separate file reach in and use their data safely.

Apply this exact same 3-step recipe (handout function → JSON export function → call both from `main.c`) to `cron_scan.c`, `network_scan.c`, `capability_scan.c`, and `login_history.c` as you build them out — it's the same three steps every time, just different field names.


---

### QUESTION - Triage vs Antivirus
Nah, i want to ask you, what are the actual parameters that these modern world triage system projects parse? like what? should I just stick to file permissions and processes for now? what else? what do i parse from a file? to know the context? network connections? How is that a triage system and not an antivirus? what research papers do i refer to? 

Good question — this is the one that actually decides what your tool is. Let me give it straight.
Triage vs. Antivirus — the one-sentence difference
- Antivirus asks: "Is THIS object in my bad-list?" — it needs a known-bad list (hashes, signatures) and answers yes/no per file. It inspects content.
  
- Triage asks: "Of everything on this box, what deserves a human's eyes first, and what's it connected to?" — it has no bad-list. It collects facts, ranks them, and links them into a story a human investigates.
  
> Your own doc says it perfectly: 

UAC (a real tool) collects everything but judges nothing — that's the difference between a dumper and a triage system. You're already building triage; the score field and the is_presult_interesting() checks are a mini-triage engine. An antivirus inspects bytes; a triage tool inspects relationships and context.

> What modern triage systems actually parse?

Six buckets. Everything in the real tools (Plaso, UAC, Sandfly) falls into these:

1. Processes (running state). name, pid, parent/ancestry chain, who owns it (uid + Linux capabilities), the binary it runs (real file? (deleted)? memfd:?), its command line, its open file descriptors, its memory maps (any rwx region?), when it started, and does anything relaunch it (cron/systemd tie-back).
2. Files (on-disk state). permissions (suid/sgid/world-writable), owner, timestamps, where it lives, and light structure checks (is it even an ELF? what architecture?). Not "is it malicious."
3. Network (connection state). listening sockets + established connections, and which pid owns them. This is where you learn a weird process is actually talking to the internet.
4. Persistence (survival state). cron entries, systemd units, rc scripts, shell profiles — "if I reboot, does it come back?" MITRE calls these T1053/T1547.
5. Identity/change state. recent logins, new users, recently-modified files, auth anomalies — "what changed, and who was here?"
6. Baseline (context state). hostname, kernel, uptime, boot time, current user. Alone it detects nothing, but every other check becomes interpretable against it (your docs call this "cross-cutting context"). Without it, "root-owned process" is meaningless.

> What do you parse from a file to know its context?  

The context is the file's surroundings, not its contents. In priority order:

- Metadata (one stat() call): path, size, uid/gid, suid/sgid/writable bits, mtime/ctime, inode.

- Where it lives (statfs()): host vs. container-overlay vs. flatpak vs. /tmp. This kills your false positives — it's the context that matters most.

- Who owns it: is it from the package manager (dpkg -S), or a loose file dropped outside packages?

- What kind of thing it is: read the first ~4 bytes — ELF? script? data? (You already check S_ISREG.)
  
- Light ELF structure (cheap, later): header architecture mismatch (MIPS binary on x86_64 = dropper smell), stripped sections / high entropy (packed), which library functions it imports (does it even call networking?). This is capa's whole model — it tells you what a binary can do, not whether it's evil.
  
- When it changed: timestamps vs. surrounding files (timestomping tell, and timeline material).
  
That's "context." Taste the metadata, don't read the soup.

> Stick to perms + processes?

Yes — those two are ~70% of the value. But add exactly two cheap things before you call it done, because they make the correlator actually sing:

- Network connections (/proc/net/tcp + match socket inodes to pids): a flagged process that also owns a listening socket is a much bigger deal than one that doesn't — and this is the #1 missing link for a "triage" claim.
  
- Cron/persistence: just parsing /var/spool/cron, /etc/cron*, systemd unit files. It's boring and easy, and it answers "does this survive reboot" — which is the persistence tie-back every triage system does.
  
> Skip for now: deep ELF parsing, login history, eBPF, any ML. Those are report "future work" material, not this semester's build.
Research you actually need to cite (plain-English, and only these)

Your linux-incident-triage-literature-review.md already has the full list. The ones that matter for convincing a grader:

- SLEUTH (USENIX Security 2017) — proves you can reconstruct an attack from plain logs, no custom instrumentation. This is your strongest single citation for "the correlator/timeline idea."
  
- BackTracker / PrioTracker — the original "walk the causal graph" papers; the intellectual ancestor of your correlator. Cite for design, don't build it.
  
- MITRE DET0164 — the exact detection logic behind your NAME_MISMATCH check. Worst-case, this one citation alone proves "my process checks come from the standard definition, not my head."
  
- MITRE ATT&CK for Linux — the naming system for your report; tag your findings with T-numbers and it instantly looks like professional tooling.
  
- Sandfly's memfd post — primary source for your MEMFD_EXEC check. Concrete, citable, matches code you already wrote.
  
- capa (Mandiant) — the model for your rule engine: "declarative rules that say what a binary can do, not whether it's bad." Direct justification for why you went rule-based not ML.
  
- Plaso/log2timeline — the model for your timeline feature.
  
- UAC — the "collect everything, judge nothing" contrast case; your architecture section is literally "UAC plus a judgment layer."
  
- The 2024-2025 papers (ANUBIS, RT-APT, MGDA, TPPR) are graph-ML provenance research — name-drop them in "related work/future work," don't read them in depth; they're not what you'll build.

>If your report has to answer one thing clearly, it's this: 
"PRIONYX is not an antivirus because it never says 'this is malware.'

>VIt says 'here's what deserves a look, here's the order, and here's how the suspicious things connect.'" That single sentence separates your project from every tool that just dumps data.

---

### LONG TERM PLAN

Here's your long-term plan, in the real order to do it — each step small enough to finish in a sitting, and each one leaves the tool compiling and working. The golden habit stays: compile + run + git commit after every step.\

>Phase 1 — Decide your rules on paper (what's SUS, what isn't)

1. Open linux-incident-triage-literature-review.md and PRIONYX_PROGRESS.md side by side. Make a one-page table: one row per tag your code already produces (SUID_ROOT, WORLD_WRITABLE, MEMFD_EXEC, ORPHAN_ROOT, NAME_MISMATCH...) with columns: what it means, how you get it, when is it a false positive, what score weight it deserves. This table IS your spec — every rule you write later comes from it.

2. Decide your false-positive list on paper first: Flatpak paths, container-overlay paths, /proc, kernel threads. Write the exact path prefixes that define "noise." You've already diagnosed these in the research docs — now make it a checklist.

3. Decide your scoring philosophy in one sentence, e.g.: "Files in HOST domain score by tag; same tags in CONTAINER/FLATPAK domains are deprioritized; combinations of tags score higher than single tags." Write it down. This is your answer for the report and it stops you from inventing scores as you go.

>Phase 2 — Give every module one shared shape + JSON out

1. Create include/finding.h: the finding_t struct (from plan §4). Nothing else changes.

2. Create findings.c + findings.h: one global array, add_finding(), get_findings(). This is the single sink every module pours into.

3. Convert file_perm_enum.c: keep its logic, but instead of printf, push a finding_t into the bucket. Add evidence_time = st.st_mtime (data you already fetch but throw away).

4. Convert process_scan.c the same way: subject = binpath or pid:<n>. Also, in this sitting: fix the 10 strcat(p->issues,...) calls to strncat (real overflow risk, plan §3.3). And add read_stat_starttime() from /proc/<pid>/stat field 22 (ticks→wall-clock via sysconf(_SC_CLK_TCK) + /proc/uptime) so processes also get an evidence_time.

5. In main.c: after all scans, write findings.json (one NDJSON line per finding — plan §5, ~10 lines of fprintf). Keep a minimal console print so output still shows. Take a before/after screenshot now — your strongest report evidence already.

6. Leave env_scan.c and system_info.c symmetric: nothing to add, their output becomes the JSON header later.

>Phase 3 — Trust domain (kills your false positives)

1.  Write trust_domain.c: classify_trust_domain(path) with a path-prefix table first (Flatpak, container overlay, /tmp, /dev/shm, HOST).

2.  Add trust_domain to your findings output. Rerun and confirm the Spotify/container noise ranks below /bin/sudo. Screenshot again. This is the whole point of your report's §3 → measured fix.

3.  Later/optional: upgrade to statfs() magic numbers so the classification is kernel-proof, not path-string-proof.

>Phase 4 — Correlator (the "comparer" you asked about)

1.  Write correlator.c: build a small hash map keyed by subject, walk your findings, and any subject with findings from ≥2 categories gets a synthetic tag (CORR_FILE, CORR_PROC...). Plan §6.2 — the phone-book idea.

2.  Wire the first edge: process → file — a process whose binary path is also flagged (e.g. WORLD_WRITABLE). This is the single most defensible "triage" feature you can demo.

3.  Add the network collector (network_scan.c — parse /proc/net/tcp+udp, match socket inodes to pids). Then the second edge: process → network (a flagged process that owns a socket = highly interesting).

>Phase 5 — Rule engine (moving scores out of the code)

1.  Build rules.c: a static array of {needs_tag, exclude_domain, add_score} and one loop (plan §6.3). Move your scores from is_presult_interesting()/is_result_interesting() into it, 5–8 rules to start.

2.  Tag rules with MITRE ATT&CK IDs (T1053, T1548, T1574...) — one-line change per rule, big credibility win.

>Phase 6 — Timeline

1.  Write timeline.c: sort all findings by evidence_time, print chronologically. Works the day after steps 6–7 complete. Answers "what changed first?"

>Phase 7 — Bonus collectors (only if time)

1.  Per-process LD_PRELOAD check (read /proc/<pid>/environ) and the /proc/<pid>/maps rwx check — both new detections, good report stretch material.

2.  cron_scan.c (parse /var/spool/cron, /etc/cron*, systemd units) — gives you the third correlator edge: process persistence tie-back.

>Phase 8 — Report & hardening

1.  Write the TA1 report from the evidence log: research docs are already citations; your before/after screenshots + the false-positive kill prove the architecture works.

2.  Harden: compile with gcc -Wall -Wextra clean, run under valgrind for leaks, test as non-root and with sudo, write a demo.sh that runs a full scan and shows before/after, and keep committing.

### Tags

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

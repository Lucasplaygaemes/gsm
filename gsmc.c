/*
 * gsm user space daemon (gsmc)
 * 
 * features:
 * - interactive menu with whitelist support
 * - real-time monitoring with "stealth mode" (only shows threats)
 * - virus list and whitelist management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <time.h>
#include <sys/xattr.h>
#include <errno.h>
#include <yara.h>
#include <dirent.h>
// ── Deep Scanner additions ─────────────────────────────────────────────────
#include <sys/fanotify.h>   // on-access file scanning (FAN_CLOSE_WRITE)
#include <elf.h>            // ELF format structures (section parsing)
#include <math.h>           // log2() for Shannon entropy
#include <limits.h>         // PATH_MAX
// ──────────────────────────────────────────────────────────────────────────
#include "gsm_shared.h"

#define DEVICE_PATH "/dev/gsm"
#define CONFIG_DIR "/hashes"
#define CONFIG_FILE "/hashes/gsm_hashes.conf"
#define WHITELIST_FILE "/hashes/gsm_whitelist.conf"
#define BLOCKED_FILE "/hashes/gsm_blocked.conf"
#define BUFFER_SIZE 4096
#define MAX_HASHES 256
#define MAX_WHITELIST 128

typedef struct {
    char hash[65];
    int threat_level;
    int action;
    char name[256];
    char desc[512];
} hash_entry_t;

static hash_entry_t hash_database[MAX_HASHES];
static char whitelist[MAX_WHITELIST][256];
static int hash_db_size = 0;
static int whitelist_size = 0;
static int monitoring_active = 0;
static int verbose_mode = 0;

// variables for yara
static YR_RULES *yara_rules = NULL;
static YR_COMPILER *yara_compiler = NULL;

#define YARA_RULES_DIR    "./YARA"
#define QUARANTINE_DIR    "./quarentena"

// ── Deep Scanner: Threat Scoring Thresholds ──────────────────────────────────
#define THREAT_SCORE_MALICIOUS  80   // >= this → quarantine automatically
#define THREAT_SCORE_SUSPECT    40   // >= this → tag as suspect, monitor
#define MAX_SCAN_SIZE  (4 * 1024 * 1024)  // 4MB cap for string/entropy scan
#define ENTROPY_HIGH        7.0      // > this → packed/obfuscated → +20 pts
#define ENTROPY_VERY_HIGH   7.5      // > this → likely encrypted payload → +40 pts

// ── Deep Scanner: Suspicious String Signatures ───────────────────────────────
// Each entry has a string pattern, a threat score contribution, and a description.
// Scores accumulate. Total >= THREAT_SCORE_MALICIOUS → quarantine.
typedef struct { const char *pattern; int score; const char *desc; } str_sig_t;

static const str_sig_t string_sigs[] = {
    // Reverse shell / execution
    {"/bin/sh",          25, "direct shell reference"},
    {"bash -i",          40, "interactive bash (reverse shell pattern)"},
    {"nc -e",            55, "netcat with exec (classic reverse shell)"},
    {"ncat -e",          55, "ncat with exec (reverse shell)"},
    {"/dev/tcp/",        60, "bash TCP redirect (reverse shell)"},
    {"python -c",        30, "inline Python execution"},
    {"perl -e",          30, "inline Perl execution"},
    {"ruby -e",          30, "inline Ruby execution"},
    // Privilege escalation
    {"chmod 777",        35, "world-writable permission change"},
    {"chmod +s",         45, "setuid/setgid bit set"},
    {"chown root",       40, "ownership change to root"},
    // Persistence
    {"/etc/crontab",     35, "crontab modification"},
    {"cron.d/",          30, "cron directory access"},
    {".bashrc",          25, "bashrc persistence"},
    {".bash_profile",    25, "bash_profile persistence"},
    {"systemctl enable", 30, "systemd service enable"},
    {"rc.local",         25, "rc.local startup persistence"},
    // Credential theft
    {"/etc/shadow",      55, "shadow file (credential theft)"},
    {"/etc/passwd",      30, "passwd file access"},
    {"id_rsa",           45, "SSH private key reference"},
    {".ssh/",            30, "SSH directory"},
    {"authorized_keys",  40, "SSH authorized keys modification"},
    // Downloader / dropper
    {"wget ",            20, "wget downloader"},
    {"curl ",            20, "curl downloader"},
    // Obfuscation
    {"base64 -d",        35, "base64 decode (obfuscation)"},
    {"base64 --decode",  35, "base64 decode (obfuscation)"},
    {"xxd -r",           30, "hex-to-binary (obfuscation)"},
    {"eval ",            25, "eval() style execution"},
    // Injection / memory manipulation
    {"ptrace",           35, "ptrace (process injection)"},
    {"/proc/mem",        50, "direct memory access via /proc"},
    {"LD_PRELOAD",       45, "LD_PRELOAD injection"},
    {"LD_LIBRARY_PATH",  35, "library path manipulation"},
    // Network
    {"SOCK_RAW",         30, "raw socket creation"},
    {"/etc/resolv.conf", 20, "DNS config access"},
    {NULL, 0, NULL}  // sentinel
};

// fanotify file descriptor (set up in setup_fanotify, used in run_monitoring)
static int fanotify_fd = -1;
// ─────────────────────────────────────────────────────────────────────────────

// helper function to copy files if rename fails (cross-device move)
int copy_file(const char *src, const char *dst) {
    FILE *fsrc = fopen(src, "rb");
    FILE *fdst = fopen(dst, "wb");
    if (!fsrc || !fdst) {
        if (fsrc) fclose(fsrc);
        if (fdst) fclose(fdst);
        return -1;
    }
    char buf[BUFFER_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fsrc)) > 0) {
        fwrite(buf, 1, n, fdst);
    }
    fclose(fsrc);
    fclose(fdst);
    return 0;
}

// forward declarations
void signal_handler(int sig);
void kill_process_via_kernel(int dev_fd, int pid);
void handle_event(gsm_event_t *event, int dev_fd);
int calculate_file_sha256(const char *filepath, char *output_hex);
int check_hash_in_database(const char *hash, hash_entry_t **entry);
int load_hash_database(const char *config_file);
int load_whitelist();
int save_whitelist();
void apply_malicious_tag(const char *path);
void run_monitoring(int dev_fd);
void manage_virus_list();
void manage_whitelist();
void manage_blocked_list();
// deep scanner
double calculate_entropy(const uint8_t *data, size_t len);
double calculate_file_entropy(const char *filepath);
int    scan_suspicious_strings(const char *filepath, int *out_score);
int    calculate_elf_text_sha256(const char *filepath, char *output_hex);
int    scan_file_deep(const char *filepath);
int    setup_fanotify(void);
void   handle_fanotify_event(int fan_fd);

void signal_handler(int sig) {
    if (monitoring_active) {
        printf("\n[gsmc] stopping monitoring... returning to menu.\n");
        monitoring_active = 0;
    } else {
        printf("\n[gsmc] exiting...\n");
        exit(0);
    }
}

int load_whitelist() {
    FILE *fp = fopen(WHITELIST_FILE, "r");
    whitelist_size = 0;
    
    // 1. hardcoded critical paths (always protected)
    const char *critical_paths[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", 
        "/lib", "/lib64", "/usr/lib", "/usr/local/lib",
        "/etc", "/boot", "/proc", "/sys", "/dev", "/var/lib"
    };
    for (int i = 0; i < sizeof(critical_paths)/sizeof(char*); i++) {
        if (whitelist_size < MAX_WHITELIST)
            strncpy(whitelist[whitelist_size++], critical_paths[i], 255);
    }

    if (!fp) {
        save_whitelist(); 
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) && whitelist_size < MAX_WHITELIST) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0 && line[0] != '#') {
            int exists = 0;
            for(int j=0; j<whitelist_size; j++) {
                if(strcmp(whitelist[j], line) == 0) { exists = 1; break; }
            }
            if(!exists) strncpy(whitelist[whitelist_size++], line, 255);
        }
    }
    fclose(fp);
    return 0;
}

int save_whitelist() {
    FILE *fp = fopen(WHITELIST_FILE, "w");
    if (!fp) return -1;
    for (int i = 0; i < whitelist_size; i++) {
        fprintf(fp, "%s\n", whitelist[i]);
    }
    fclose(fp);
    return 0;
}

int load_hash_database(const char *config_file) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) return -1;
    hash_db_size = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && hash_db_size < MAX_HASHES) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\n")] = 0;
        int parsed = sscanf(line, "%64[^|]|%d|%d|%255[^|]|%511s",
                           hash_database[hash_db_size].hash, 
                           &hash_database[hash_db_size].threat_level,
                           &hash_database[hash_db_size].action,
                           hash_database[hash_db_size].name,
                           hash_database[hash_db_size].desc);
        if (parsed >= 4) hash_db_size++;
    }
    fclose(fp);
    return 0;
}

int calculate_file_sha256(const char *filepath, char *output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    unsigned char buffer[BUFFER_SIZE];
    int fd, bytes_read;
    fd = open(filepath, O_RDONLY);
    if (fd < 0) return -1;
    SHA256_Init(&sha256);
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) SHA256_Update(&sha256, buffer, bytes_read);
    SHA256_Final(hash, &sha256);
    close(fd);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(output_hex + (i * 2), "%02x", hash[i]);
    output_hex[64] = '\0';
    return 0;
}

void move_to_quarantine(const char *path) {
    char new_path[512];
    char *filename = strrchr(path, '/');
    if (!filename) filename = (char*)path;
    else filename++;

    // ensure the folder exists
    mkdir(QUARANTINE_DIR, 0700);
    snprintf(new_path, sizeof(new_path), "%s/%s", QUARANTINE_DIR, filename);

    // try to move
    if (rename(path, new_path) == 0) {
        setxattr(new_path, GSM_QUARANTINE_TAG, "1", 1, 0);
        printf("[gsmc] success: %s moved to quarantine folder '%s'\n", filename, QUARANTINE_DIR);
    } else {
        // plan b: if rename fails (e.g. cross-partition), copy and delete
        if (copy_file(path, new_path) == 0) {
            unlink(path); // delete original
            setxattr(new_path, GSM_QUARANTINE_TAG, "1", 1, 0);
            printf("[gsmc] success: %s copied to quarantine folder '%s'\n", filename, QUARANTINE_DIR);
        } else {
            fprintf(stderr, "[gsmc] error: could not quarantine %s: %s\n", filename, strerror(errno));
        }
    }
}

int yar_callback(YR_SCAN_CONTEXT * context, int message, void *message_data, void *user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        char* path = (char*)user_data;
        int is_suspect = 0;

        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (strcmp(meta->identifier, "level") == 0 && 
                meta->type == META_TYPE_STRING && 
                strcmp(meta->string, "suspect") == 0) {
                is_suspect = 1;
            }
        }

        if (is_suspect) {
            printf("\n[yara] ??? suspicious match: [%s] in file: %s ???\n", rule->identifier, path);
            setxattr(path, GSM_SUSPECT_TAG, "1", 1, 0);
        } else {
            printf("\n[yara] !!! malicious match: [%s] in file: %s !!!\n", rule->identifier, path);
            setxattr(path, GSM_MALICIOUS_TAG, "1", 1, 0);
            move_to_quarantine(path);
        }
    }
    return CALLBACK_CONTINUE;
}

void handle_event(gsm_event_t *event, int dev_fd) {
    char hash[65];
    hash_entry_t *db_entry = NULL;
    time_t now;
    char timestamp[32];
    char val[16];

    // 1. master security: check if path is in whitelist
    int is_whitelisted = 0;
    for (int i = 0; i < whitelist_size; i++) {
        if (strncmp(event->target_path, whitelist[i], strlen(whitelist[i])) == 0) {
            is_whitelisted = 1;
            break;
        }
    }

    // if it's a system path, ignore aggressive actions (yara/move)
    if (is_whitelisted && strstr(event->target_path, "/quarentena/") == NULL) {
        // allow only visual log in verbose mode
        if (verbose_mode && event->action_taken != 3) {
            time(&now); strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now));
            printf("[%s] system path accessed (safe): %s\n", timestamp, event->target_path);
        }
        return; 
    }

    // ignore rule paths
    if (strstr(event->target_path, "/YARA/") != NULL) return;

    time(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now));

    // 2. check if file already has danger tags
    if (getxattr(event->target_path, GSM_MALICIOUS_TAG, val, sizeof(val)) > 0) {
        printf("[%s] [!] detected malicious tag: %s. moving to quarantine...\n", timestamp, event->target_path);
        move_to_quarantine(event->target_path);
        return;
    } 
    
    if (getxattr(event->target_path, GSM_QUARANTINE_TAG, val, sizeof(val)) > 0) {
        if (verbose_mode) printf("[%s] [q] file already in quarantine: %s\n", timestamp, event->target_path);
        return;
    }

    if (getxattr(event->target_path, GSM_SUSPECT_TAG, val, sizeof(val)) > 0) {
        if (verbose_mode) printf("[%s] [?] monitoring suspect file: %s\n", timestamp, event->target_path);
    }

    // 3. check if kernel blocked execution
    if (event->action_taken == 2) {
        printf("\n[%s] [!!!] kernel blocked execution: %s\n", timestamp, event->target_path);
        return;
    }

    // 4. suspect behavior (edr)
    if (event->action_taken == 3) {
        char exe_link[64], exe_path[256];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", event->pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path)-1);
        
        if (len != -1) {
            exe_path[len] = '\0';
            
            // critical security: check if killer process is whitelisted
            int is_proc_whitelisted = 0;
            for (int i = 0; i < whitelist_size; i++) {
                if (strncmp(exe_path, whitelist[i], strlen(whitelist[i])) == 0) {
                    is_proc_whitelisted = 1;
                    break;
                }
            }

            if (is_proc_whitelisted) {
                if (verbose_mode) printf("[gsmc] ignoring suspect action from whitelisted binary: %s\n", exe_path);
                // optional: remove suspect tag to stop false alarms
                removexattr(exe_path, GSM_SUSPECT_TAG);
                return;
            }

            printf("\n[%s] [!!! suspicious activity !!!] pid %d (%s) target: %s\n", timestamp, event->pid, event->process_name, event->target_path);
            printf("[gsmc] action: terminating process and quarantining...\n");

            // kill process immediately
            char pidstr[16];
            int slen = snprintf(pidstr, sizeof(pidstr), "%d", event->pid);
            write(dev_fd, pidstr, slen);
            usleep(50000); 

            if (strstr(exe_path, "/bin/bash") || strstr(exe_path, "/bin/sh") || strstr(exe_path, "/usr/bin/python")) {
                printf("[gsmc] suspect script terminated (pid %d).\n", event->pid);
            } else {
                printf("[gsmc] suspect binary %s killed and moved to quarantine.\n", exe_path);
                move_to_quarantine(exe_path);
            }
        }
        return;
    }

    // 5. network block (edr — reverse shell / C2 prevention)
    if (event->action_taken == 4) {
        char exe_link[64], exe_path[256];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", event->pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (len > 0) exe_path[len] = '\0';
        else strncpy(exe_path, event->target_path, sizeof(exe_path) - 1);

        printf("\n[%s] \033[1;31m[!!! NETWORK BLOCK !!!]\033[0m pid %d (%s)\n",
               timestamp, event->pid, event->process_name);
        printf("  connection attempt: %s\n", event->target_path);
        printf("  binary:             %s\n", exe_path);
        printf("[gsmc] action: killing process and quarantining binary...\n");

        // kill the suspect process immediately via kernel
        char pidstr[16];
        int slen = snprintf(pidstr, sizeof(pidstr), "%d", event->pid);
        write(dev_fd, pidstr, slen);
        usleep(50000);

        // quarantine the binary (unless it's a shell/interpreter)
        if (strstr(exe_path, "/bin/bash") || strstr(exe_path, "/bin/sh") ||
            strstr(exe_path, "/usr/bin/python") || strstr(exe_path, "/usr/bin/perl")) {
            printf("[gsmc] suspect script killed (pid %d) — skipping quarantine of interpreter.\n", event->pid);
        } else {
            move_to_quarantine(exe_path);
            printf("[gsmc] binary quarantined: %s\n", exe_path);
        }
        return;
    }

    // 5–9. Unified deep scan (entropy + strings + ELF .text hash + YARA + SHA-256)
    {
        int score = scan_file_deep(event->target_path);
        if (score >= THREAT_SCORE_MALICIOUS) {
            printf("\n[%s] \033[1;31m[!!! THREAT !!!]\033[0m %s (score: %d) → quarantine\n",
                   timestamp, event->target_path, score);
            setxattr(event->target_path, GSM_MALICIOUS_TAG, "1", 1, 0);
            move_to_quarantine(event->target_path);
        } else if (score >= THREAT_SCORE_SUSPECT) {
            printf("\n[%s] \033[1;33m[? SUSPECT ?]\033[0m %s (score: %d) → monitoring\n",
                   timestamp, event->target_path, score);
            setxattr(event->target_path, GSM_SUSPECT_TAG, "1", 1, 0);
        } else if (verbose_mode) {
            printf("[%s] clean: %s\n", timestamp, event->target_path);
        }
    }
}


// ══════════════════════════════════════════════════════════════════════════════
// DEEP SCANNER — Anti-Virus Engine
// ══════════════════════════════════════════════════════════════════════════════

// Calculate Shannon entropy of a byte buffer.
// Range: 0.0 (all same byte) to 8.0 (perfectly uniform distribution).
// High entropy (>7.0) indicates packing, encryption, or obfuscation.
double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[(unsigned char)data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Read a file (up to MAX_SCAN_SIZE bytes) and return its Shannon entropy.
double calculate_file_entropy(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0.0;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) { fclose(fp); return 0.0; }
    size_t read_sz = ((size_t)fsize > MAX_SCAN_SIZE) ? MAX_SCAN_SIZE : (size_t)fsize;
    uint8_t *buf = malloc(read_sz);
    if (!buf) { fclose(fp); return 0.0; }
    size_t n = fread(buf, 1, read_sz, fp);
    fclose(fp);
    double e = calculate_entropy(buf, n);
    free(buf);
    return e;
}

// Scan a file's bytes for suspicious strings (using the string_sigs database).
// Accumulates scores for each matching pattern and returns the total.
// Uses memmem() for binary-safe substring search (works on non-text files too).
int scan_suspicious_strings(const char *filepath, int *out_score) {
    *out_score = 0;
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) { fclose(fp); return 0; }
    size_t read_sz = ((size_t)fsize > MAX_SCAN_SIZE) ? MAX_SCAN_SIZE : (size_t)fsize;
    uint8_t *buf = malloc(read_sz + 1);
    if (!buf) { fclose(fp); return -1; }
    size_t n = fread(buf, 1, read_sz, fp);
    buf[n] = '\0';
    fclose(fp);

    int total = 0;
    for (int i = 0; string_sigs[i].pattern != NULL; i++) {
        size_t plen = strlen(string_sigs[i].pattern);
        if (memmem(buf, n, string_sigs[i].pattern, plen) != NULL) {
            total += string_sigs[i].score;
            if (verbose_mode)
                printf("    [str] +%-3d %-25s (%s)\n",
                       string_sigs[i].score, string_sigs[i].pattern, string_sigs[i].desc);
        }
    }
    free(buf);
    *out_score = total;
    return 0;
}

// Parse an ELF64 binary and compute SHA-256 of its .text (executable code) section.
// This hash is immune to changes in metadata, padding, or non-code sections.
// Returns 0 on success, -1 if not an ELF or .text not found.
int calculate_elf_text_sha256(const char *filepath, char *output_hex) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) { fclose(fp); return -1; }
    // check ELF magic bytes
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_shstrndx == SHN_UNDEF) {
        fclose(fp); return -1;
    }

    // read all section headers
    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { fclose(fp); return -1; }
    fseek(fp, (long)ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        free(shdrs); fclose(fp); return -1;
    }

    // read section-name string table
    Elf64_Shdr *strtab_shdr = &shdrs[ehdr.e_shstrndx];
    char *strtab = malloc(strtab_shdr->sh_size + 1);
    if (!strtab) { free(shdrs); fclose(fp); return -1; }
    fseek(fp, (long)strtab_shdr->sh_offset, SEEK_SET);
    fread(strtab, 1, strtab_shdr->sh_size, fp);
    strtab[strtab_shdr->sh_size] = '\0';

    int found = 0;
    for (int i = 0; i < ehdr.e_shnum && !found; i++) {
        if (shdrs[i].sh_name >= strtab_shdr->sh_size) continue;
        const char *name = strtab + shdrs[i].sh_name;
        if (strcmp(name, ".text") == 0 && shdrs[i].sh_size > 0) {
            uint8_t *text = malloc(shdrs[i].sh_size);
            if (!text) break;
            fseek(fp, (long)shdrs[i].sh_offset, SEEK_SET);
            fread(text, 1, shdrs[i].sh_size, fp);
            // SHA-256 of .text only
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, text, shdrs[i].sh_size);
            SHA256_Final(hash, &ctx);
            for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
                sprintf(output_hex + (j * 2), "%02x", hash[j]);
            output_hex[64] = '\0';
            free(text);
            found = 1;
        }
    }
    free(strtab);
    free(shdrs);
    fclose(fp);
    return found ? 0 : -1;
}

// ── Main Deep Scanner Orchestrator ───────────────────────────────────────────
// Runs all analysis layers on a file and returns a cumulative threat score.
//   score >= THREAT_SCORE_MALICIOUS → quarantine
//   score >= THREAT_SCORE_SUSPECT  → mark as suspect / monitor
//   score <  THREAT_SCORE_SUSPECT  → clean
//
// Layers: SHA-256 hash, ELF .text hash, Shannon entropy, string heuristics, YARA
int scan_file_deep(const char *filepath) {
    char sha256_full[65], sha256_text[65];
    int  total_score = 0;
    int  string_score = 0;
    double entropy;

    // skip sockets, pipes, special files
    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (st.st_size < 4) return 0; // too small to be meaningful

    printf("\n[scanner] \033[1m↓ deep scan:\033[0m %s (%ld bytes)\n", filepath, (long)st.st_size);

    // ── Layer 1: SHA-256 full file hash ──────────────────────────────────────
    if (calculate_file_sha256(filepath, sha256_full) == 0) {
        for (int i = 0; i < hash_db_size; i++) {
            if (strcmp(hash_database[i].hash, sha256_full) == 0) {
                printf("  [hash] \033[1;31mKNOWN MALWARE\033[0m: '%s' — score +100\n",
                       hash_database[i].name);
                return 100; // definitive match — skip further analysis
            }
        }
        if (verbose_mode) printf("  [hash] %s  (no db match)\n", sha256_full);
    }

    // ── Layer 2: ELF .text section hash (metadata-immune) ────────────────────
    if (calculate_elf_text_sha256(filepath, sha256_text) == 0) {
        for (int i = 0; i < hash_db_size; i++) {
            if (strcmp(hash_database[i].hash, sha256_text) == 0) {
                printf("  [elf.text] \033[1;31mKNOWN MALWARE CODE SECTION\033[0m: '%s' — score +100\n",
                       hash_database[i].name);
                return 100;
            }
        }
        if (verbose_mode) printf("  [elf.text] %s  (no db match)\n", sha256_text);
    }

    // ── Layer 3: Shannon entropy — detects packing / encryption ─────────────
    entropy = calculate_file_entropy(filepath);
    if (entropy >= ENTROPY_VERY_HIGH) {
        printf("  [entropy] \033[1;31m%.4f bits\033[0m — very high, likely packed/encrypted (+40)\n", entropy);
        total_score += 40;
    } else if (entropy >= ENTROPY_HIGH) {
        printf("  [entropy] \033[1;33m%.4f bits\033[0m — high, possible packing (+20)\n", entropy);
        total_score += 20;
    } else if (verbose_mode) {
        printf("  [entropy] %.4f bits — normal\n", entropy);
    }

    // ── Layer 4: Suspicious string heuristics ────────────────────────────────
    if (scan_suspicious_strings(filepath, &string_score) == 0 && string_score > 0) {
        printf("  [strings] suspicious string score: %d\n", string_score);
        total_score += string_score;
    } else if (verbose_mode) {
        printf("  [strings] no suspicious patterns found\n");
    }

    // ── Layer 5: YARA signature scan ─────────────────────────────────────────
    if (yara_rules != NULL) {
        yr_rules_scan_file(yara_rules, filepath, 0, yar_callback, (void*)filepath, 0);
    }

    // ── Result ────────────────────────────────────────────────────────────────
    printf("  [score]  %d / %d (malicious) / %d (suspect)  →  ",
           total_score, THREAT_SCORE_MALICIOUS, THREAT_SCORE_SUSPECT);
    if      (total_score >= THREAT_SCORE_MALICIOUS) printf("\033[1;31mMALICIOUS\033[0m\n");
    else if (total_score >= THREAT_SCORE_SUSPECT)   printf("\033[1;33mSUSPECT\033[0m\n");
    else                                             printf("\033[1;32mCLEAN\033[0m\n");

    return total_score;
}

// ── fanotify Setup ────────────────────────────────────────────────────────────
// Watches the entire filesystem for FAN_CLOSE_WRITE events.
// This fires whenever a file is completely written and closed — perfect for
// catching downloaded malware the moment it lands on disk.
int setup_fanotify(void) {
    fanotify_fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fanotify_fd < 0) {
        fprintf(stderr, "[gsmc] warning: fanotify_init failed (%s). on-write scanning disabled.\n",
                strerror(errno));
        fprintf(stderr, "[gsmc] hint: run as root with CAP_SYS_ADMIN for fanotify support.\n");
        return -1;
    }
    // watch the whole filesystem — FAN_CLOSE_WRITE fires when any written file is closed
    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                      FAN_CLOSE_WRITE, AT_FDCWD, "/") < 0) {
        fprintf(stderr, "[gsmc] warning: fanotify_mark failed (%s). on-write scanning disabled.\n",
                strerror(errno));
        close(fanotify_fd);
        fanotify_fd = -1;
        return -1;
    }
    printf("[gsmc] fanotify: \033[1;32mactive\033[0m — scanning every new/modified file on close-write.\n");
    return fanotify_fd;
}

// ── fanotify Event Handler ────────────────────────────────────────────────────
// Called from run_monitoring() when fanotify_fd is readable.
// Resolves the file path from the event's fd and dispatches scan_file_deep().
void handle_fanotify_event(int fan_fd) {
    char buf[4096];
    ssize_t len = read(fan_fd, buf, sizeof(buf));
    if (len <= 0) return;

    struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)buf;
    while (FAN_EVENT_OK(meta, len)) {
        if ((meta->mask & FAN_CLOSE_WRITE) && meta->fd >= 0) {
            char fdpath[64], filepath[PATH_MAX];
            snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", meta->fd);
            ssize_t plen = readlink(fdpath, filepath, sizeof(filepath) - 1);
            close(meta->fd); // MUST close the fd from fanotify

            if (plen > 0) {
                filepath[plen] = '\0';

                // skip whitelisted system paths
                int skip = 0;
                for (int i = 0; i < whitelist_size; i++) {
                    if (strncmp(filepath, whitelist[i], strlen(whitelist[i])) == 0)
                        { skip = 1; break; }
                }
                // skip internal GSM dirs and already-quarantined files
                if (!skip && (strstr(filepath, "/quarentena/") ||
                              strstr(filepath, "/YARA/")       ||
                              strstr(filepath, "gsm"))) skip = 1;
                // skip files already tagged
                char xval[4];
                if (!skip && getxattr(filepath, GSM_MALICIOUS_TAG,  xval, sizeof(xval)) > 0) skip = 1;
                if (!skip && getxattr(filepath, GSM_QUARANTINE_TAG, xval, sizeof(xval)) > 0) skip = 1;

                if (!skip) {
                    int score = scan_file_deep(filepath);
                    if (score >= THREAT_SCORE_MALICIOUS) {
                        printf("[gsmc] \033[1;31m[!!! THREAT DETECTED via fanotify !!!]\033[0m %s (score: %d)\n",
                               filepath, score);
                        setxattr(filepath, GSM_MALICIOUS_TAG, "1", 1, 0);
                        move_to_quarantine(filepath);
                    } else if (score >= THREAT_SCORE_SUSPECT) {
                        printf("[gsmc] \033[1;33m[? SUSPECT via fanotify ?]\033[0m %s (score: %d) — monitoring\n",
                               filepath, score);
                        setxattr(filepath, GSM_SUSPECT_TAG, "1", 1, 0);
                    }
                }
            }
        } else if (meta->fd >= 0) {
            close(meta->fd); // always close leftover fds
        }
        meta = FAN_EVENT_NEXT(meta, len);
    }
}
// ══════════════════════════════════════════════════════════════════════════════

void run_monitoring(int dev_fd) {
    gsm_event_t event;
    monitoring_active = 1;
    printf("\n[gsmc] monitoring started (%s mode). ctrl+c to stop.\n",
           verbose_mode ? "verbose" : "stealth");
    printf("[gsmc] fanotify on-write scanner: %s\n",
           fanotify_fd >= 0 ? "\033[1;32mACTIVE\033[0m" : "\033[1;31mINACTIVE\033[0m (needs root + CAP_SYS_ADMIN)");

    while (monitoring_active) {
        struct timeval tv = {1, 0};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(dev_fd, &fds);
        int max_fd = dev_fd;

        // also watch fanotify fd if available
        if (fanotify_fd >= 0) {
            FD_SET(fanotify_fd, &fds);
            if (fanotify_fd > max_fd) max_fd = fanotify_fd;
        }

        int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            // handle kernel module events (/dev/gsm)
            if (FD_ISSET(dev_fd, &fds)) {
                if (read(dev_fd, &event, sizeof(gsm_event_t)) == sizeof(gsm_event_t)) {
                    handle_event(&event, dev_fd);
                }
            }
            // handle fanotify on-write events (new files/downloads)
            if (fanotify_fd >= 0 && FD_ISSET(fanotify_fd, &fds)) {
                handle_fanotify_event(fanotify_fd);
            }
        }
    }
}


void manage_whitelist() {
    int choice, i, found;
    char path[256];
    printf("\n--- whitelist management ---\n1. add path to whitelist\n2. remove path\n3. list whitelist\n0. back\nchoice: ");
    scanf("%d", &choice); getchar();
    if (choice == 1) {
        printf("enter path to ignore: ");
        fgets(path, 256, stdin); path[strcspn(path, "\n")] = 0;
        if (whitelist_size < MAX_WHITELIST) {
            strncpy(whitelist[whitelist_size++], path, 255);
            save_whitelist();
            printf("path added to whitelist.\n");
        } else {
            printf("whitelist is full (%d entries).\n", MAX_WHITELIST);
        }
    } else if (choice == 2) {
        // [BUG FIX #6] This option was listed in the menu but never implemented.
        printf("enter path to remove: ");
        fgets(path, 256, stdin); path[strcspn(path, "\n")] = 0;
        found = 0;
        for (i = 0; i < whitelist_size; i++) {
            if (strcmp(whitelist[i], path) == 0) {
                // shift remaining entries left to fill the gap
                memmove(whitelist[i], whitelist[i + 1], (whitelist_size - i - 1) * 256);
                whitelist_size--;
                save_whitelist();
                printf("path removed from whitelist.\n");
                found = 1;
                break;
            }
        }
        if (!found) printf("path not found in whitelist.\n");
    } else if (choice == 3) {
        for (i = 0; i < whitelist_size; i++) printf("%d. %s\n", i+1, whitelist[i]);
    }
}

void manage_virus_list() {
    int choice;
    char path[512], hash[65];
    printf("\n--- virus list ---\n1. add file hash\n2. list hashes\n0. back\nchoice: ");
    scanf("%d", &choice); getchar();
    if (choice == 1) {
        printf("file path: ");
        fgets(path, 512, stdin); path[strcspn(path, "\n")] = 0;
        if (calculate_file_sha256(path, hash) == 0) {
            strncpy(hash_database[hash_db_size].hash, hash, 64);
            printf("name: ");
            fgets(hash_database[hash_db_size].name, 256, stdin);
            hash_database[hash_db_size].name[strcspn(hash_database[hash_db_size].name, "\n")] = 0;
            hash_database[hash_db_size].threat_level = 2;
            hash_database[hash_db_size].action = 1;
            hash_db_size++;
            FILE *fp = fopen(CONFIG_FILE, "a");
            if (fp) { fprintf(fp, "%s|2|1|%s|added_via_menu\n", hash, hash_database[hash_db_size-1].name); fclose(fp); }
            printf("hash added: %s\n", hash);
        }
    } else if (choice == 2) {
        for (int i = 0; i < hash_db_size; i++) printf("%d. %s | %s\n", i+1, hash_database[i].hash, hash_database[i].name);
    }
}

void manage_blocked_list() {
    int choice;
    char path[512];
    printf("\n--- advanced protection (files & folders) ---\n");
    printf("1. protect new path (file or folder)\n");
    printf("2. unprotect path\n");
    printf("3. list currently protected paths\n");
    printf("0. back\nchoice: ");
    scanf("%d", &choice); getchar();

    if (choice == 1) {
        printf("path: "); fgets(path, 512, stdin); path[strcspn(path, "\n")] = 0;
        if (setxattr(path, GSM_TAG, "1", 1, 0) == 0) {
            FILE *fp = fopen(BLOCKED_FILE, "a");
            if (fp) { fprintf(fp, "%s\n", path); fclose(fp); }
            printf("[gsmc] success: %s is now protected.\n", path);
        } else { perror("[gsmc] error protecting path"); }
    } else if (choice == 2) {
        printf("path: "); fgets(path, 512, stdin); path[strcspn(path, "\n")] = 0;
        if (removexattr(path, GSM_TAG) == 0) {
            printf("[gsmc] success: %s is now unprotected.\n", path);
        } else { perror("[gsmc] error unprotecting path"); }
    } else if (choice == 3) {
        printf("\nsaved protected paths in %s:\n", BLOCKED_FILE);
        FILE *fp = fopen(BLOCKED_FILE, "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) printf("- %s", line);
            fclose(fp);
        } else { printf("no paths saved in config file yet.\n"); }
    }
}

int main() {
    int dev_fd, choice;
    signal(SIGINT, signal_handler);
    load_hash_database(CONFIG_FILE);
    load_whitelist();

    // create quarantine folder on initialization
    if (mkdir(QUARANTINE_DIR, 0700) == 0) {
        printf("[gsmc] quarantine directory created at %s\n", QUARANTINE_DIR);
    }
    
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "error trying to initialize yara\n");
        return 1;
    }
    
    if (yr_compiler_create(&yara_compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "error creating the yara compiler\n");
        return 1;
    }

    // loading all .yar files from yara folder
    DIR *d = opendir(YARA_RULES_DIR);
    if (d) {
        struct dirent *dir;
        int rules_loaded = 0;
        while ((dir = readdir(d)) != NULL) {
            // check if file ends with .yar
            if (strstr(dir->d_name, ".yar")) {
                char full_path[512];
                snprintf(full_path, sizeof(full_path), "%s/%s", YARA_RULES_DIR, dir->d_name);
                
                FILE* rule_file = fopen(full_path, "r");
                if (rule_file) {
                    if (yr_compiler_add_file(yara_compiler, rule_file, NULL, full_path) != 0) {
                        fprintf(stderr, "[yara] fatal: error compiling %s (syntax error). stopping yara load.\n", dir->d_name);
                        fclose(rule_file);
                        break; // stop loop to avoid libyara crash
                    } else {
                        rules_loaded++;
                    }
                    fclose(rule_file);
                }
            }
        }
        closedir(d);
        
        if (rules_loaded > 0) {
            yr_compiler_get_rules(yara_compiler, &yara_rules);
            printf("[gsmc] %d yara rule files loaded successfully.\n", rules_loaded);
        }
    } else {
        printf("[gsmc] warning: could not open yara directory at %s\n", YARA_RULES_DIR);
    }
    
    printf("[gsmc] connecting to gsm kernel module...\n");
    dev_fd = open(DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        perror("[gsmc] fatal: could not open /dev/gsm. is the module loaded (sudo insmod gsm.ko)?");
        return 1;
    }

    printf("[gsmc] connection successful.\n");

    // initialize fanotify on-write scanner (requires root + CAP_SYS_ADMIN)
    setup_fanotify();

    printf("[gsmc] entering menu...\n");

    while (1) {
        printf("\n╔══════════════════════════════════════════════════╗\n");
        printf("║          gsm security manager menu              ║\n");
        printf("╠══════════════════════════════════════════════════╣\n");
        printf("║ 1. start monitoring (%-7s mode)          ║\n", verbose_mode ? "verbose" : "stealth");
        printf("║ 2. toggle verbose mode                          ║\n");
        printf("║ 3. virus list (hashes)                          ║\n");
        printf("║ 4. whitelist (ignore paths)                     ║\n");
        printf("║ 5. blocked list (protect files/folders)         ║\n");
        printf("║ 6. exit                                         ║\n");
        printf("╠══════════════════════════════════════════════════╣\n");
        printf("║ active hooks: unlinkat write execve             ║\n");
        printf("║               execveat connect sendto           ║\n");
        printf("╚══════════════════════════════════════════════════╝\nselection: ");
        if (scanf("%d", &choice) != 1) { while(getchar() != '\n'); continue; }
        switch (choice) {
            case 1: run_monitoring(dev_fd); break;
            case 2: verbose_mode = !verbose_mode; printf("verbose mode: %s\n", verbose_mode ? "on" : "off"); break;
            case 3: manage_virus_list(); break;
            case 4: manage_whitelist(); break;
            case 5: manage_blocked_list(); break;
            case 6: 
                if (yara_rules) yr_rules_destroy(yara_rules);
                if (yara_compiler) yr_compiler_destroy(yara_compiler);
                yr_finalize();
                close(dev_fd); 
                return 0;
        }
    }
    return 0;
}

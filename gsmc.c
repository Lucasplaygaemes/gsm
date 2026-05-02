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

#define YARA_RULES_DIR "./YARA"
#define QUARANTINE_DIR "./quarentena"

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

    // 5. yara verification (behavioral signature)
    if (yara_rules != NULL) {
        yr_rules_scan_file(yara_rules, event->target_path, 0, yar_callback, (void*)event->target_path, 0);
    }

    // 6. hash verification (database)
    if (calculate_file_sha256(event->target_path, hash) == 0) {
        for (int i = 0; i < hash_db_size; i++) {
            if (strcmp(hash_database[i].hash, hash) == 0) {
                db_entry = &hash_database[i];
                break;
            }
        }
        
        if (db_entry != NULL && db_entry->threat_level >= 1) {
            printf("\n[%s] !!! match hash: %s (malware: %s) !!!\n", timestamp, event->target_path, db_entry->name);
            setxattr(event->target_path, GSM_MALICIOUS_TAG, "1", 1, 0);
            move_to_quarantine(event->target_path);
        } else if (verbose_mode && getxattr(event->target_path, GSM_SUSPECT_TAG, val, sizeof(val)) <= 0) {
            printf("[%s] safe: %s\n", timestamp, event->target_path);
        }
    }
}

void run_monitoring(int dev_fd) {
    gsm_event_t event;
    monitoring_active = 1;
    printf("\n[gsmc] monitoring started (%s mode). ctrl+c to stop.\n", verbose_mode ? "verbose" : "stealth");
    while (monitoring_active) {
        struct timeval tv = {1, 0};
        fd_set fds;
        FD_ZERO(&fds); FD_SET(dev_fd, &fds);
        if (select(dev_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            if (read(dev_fd, &event, sizeof(gsm_event_t)) == sizeof(gsm_event_t)) {
                handle_event(&event, dev_fd);
            }
        }
    }
}

void manage_whitelist() {
    int choice;
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
        }
    } else if (choice == 3) {
        for (int i = 0; i < whitelist_size; i++) printf("%d. %s\n", i+1, whitelist[i]);
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

    printf("[gsmc] connection successful. entering menu...\n");

    while (1) {
        printf("\n╔════════════════════════════════════════════╗\n");
        printf("║         gsm security manager menu          ║\n");
        printf("╠════════════════════════════════════════════╣\n");
        printf("║ 1. start monitoring (%-7s mode)     ║\n", verbose_mode ? "verbose" : "stealth");
        printf("║ 2. toggle verbose mode                     ║\n");
        printf("║ 3. virus list (hashes)                     ║\n");
        printf("║ 4. whitelist (ignore paths)                ║\n");
        printf("║ 5. blocked list (protect files)            ║\n");
        printf("║ 6. exit                                    ║\n");
        printf("╚════════════════════════════════════════════╝\nselection: ");
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

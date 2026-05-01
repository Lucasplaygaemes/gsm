/*
 * GSM User Space Daemon (gsmc)
 * 
 * Features:
 * - Interactive Menu with Whitelist support
 * - Real-time monitoring with "Stealth Mode" (only shows threats)
 * - Virus List and Whitelist management
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
#include "gsm_shared.h"

#define DEVICE_PATH "/dev/gsm"
#define CONFIG_DIR "/hashes"
#define CONFIG_FILE "/hashes/gsm_hashes.conf"
#define WHITELIST_FILE "/hashes/gsm_whitelist.conf"
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

// Forward declarations
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
        printf("\n[GSMC] Stopping monitoring... returning to menu.\n");
        monitoring_active = 0;
    } else {
        printf("\n[GSMC] Exiting...\n");
        exit(0);
    }
}

int load_whitelist() {
    FILE *fp = fopen(WHITELIST_FILE, "r");
    if (!fp) {
        fp = fopen(WHITELIST_FILE, "w");
        if (fp) {
            fprintf(fp, "/usr/share\n/var/lib\n/proc\n/sys\n/dev\n");
            fclose(fp);
        }
        return 0;
    }
    whitelist_size = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp) && whitelist_size < MAX_WHITELIST) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0 && line[0] != '#') {
            strncpy(whitelist[whitelist_size++], line, 255);
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

void handle_event(gsm_event_t *event, int dev_fd) {
    char hash[65];
    hash_entry_t *db_entry = NULL;
    time_t now;
    char timestamp[32];

    // Check against dynamic Whitelist
    for (int i = 0; i < whitelist_size; i++) {
        if (strncmp(event->target_path, whitelist[i], strlen(whitelist[i])) == 0) return;
    }

    time(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now));

    if (event->action_taken == 2) {
        printf("\n[%s] [!!!] KERNEL BLOCKED EXECUTION: %s\n", timestamp, event->target_path);
        return;
    }

    if (calculate_file_sha256(event->target_path, hash) == 0) {
        for (int i = 0; i < hash_db_size; i++) {
            if (strcmp(hash_database[i].hash, hash) == 0) {
                db_entry = &hash_database[i];
                break;
            }
        }
        
        if (db_entry != NULL && db_entry->threat_level >= 1) {
            printf("\n[%s] !!! MATCH: %s (Malware: %s) !!!\n", timestamp, event->target_path, db_entry->name);
            setxattr(event->target_path, GSM_MALICIOUS_TAG, "1", 1, 0);
            if (db_entry->action == 2) {
                char pidstr[16];
                int len = snprintf(pidstr, sizeof(pidstr), "%d", event->pid);
                write(dev_fd, pidstr, len);
            }
        } else if (verbose_mode) {
            printf("[%s] Safe: %s\n", timestamp, event->target_path);
        }
    }
}

void run_monitoring(int dev_fd) {
    gsm_event_t event;
    monitoring_active = 1;
    printf("\n[GSMC] Monitoring started (%s mode). Ctrl+C to stop.\n", verbose_mode ? "Verbose" : "Stealth");
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
    printf("\n--- Whitelist Management ---\n1. Add path to Whitelist\n2. Remove path\n3. List Whitelist\n0. Back\nChoice: ");
    scanf("%d", &choice); getchar();
    if (choice == 1) {
        printf("Enter path to ignore: ");
        fgets(path, 256, stdin); path[strcspn(path, "\n")] = 0;
        if (whitelist_size < MAX_WHITELIST) {
            strncpy(whitelist[whitelist_size++], path, 255);
            save_whitelist();
            printf("Path added to whitelist.\n");
        }
    } else if (choice == 3) {
        for (int i = 0; i < whitelist_size; i++) printf("%d. %s\n", i+1, whitelist[i]);
    }
}

void manage_virus_list() {
    int choice;
    char path[512], hash[65];
    printf("\n--- Virus List ---\n1. Add file hash\n2. List hashes\n0. Back\nChoice: ");
    scanf("%d", &choice); getchar();
    if (choice == 1) {
        printf("File path: ");
        fgets(path, 512, stdin); path[strcspn(path, "\n")] = 0;
        if (calculate_file_sha256(path, hash) == 0) {
            strncpy(hash_database[hash_db_size].hash, hash, 64);
            printf("Name: ");
            fgets(hash_database[hash_db_size].name, 256, stdin);
            hash_database[hash_db_size].name[strcspn(hash_database[hash_db_size].name, "\n")] = 0;
            hash_database[hash_db_size].threat_level = 2;
            hash_database[hash_db_size].action = 1;
            hash_db_size++;
            FILE *fp = fopen(CONFIG_FILE, "a");
            if (fp) { fprintf(fp, "%s|2|1|%s|Added_via_menu\n", hash, hash_database[hash_db_size-1].name); fclose(fp); }
            printf("Hash added: %s\n", hash);
        }
    } else if (choice == 2) {
        for (int i = 0; i < hash_db_size; i++) printf("%d. %s | %s\n", i+1, hash_database[i].hash, hash_database[i].name);
    }
}

void manage_blocked_list() {
    char path[512]; int choice;
    printf("\n--- Protection ---\n1. Protect File\n2. Unprotect File\n0. Back\nChoice: ");
    scanf("%d", &choice); getchar();
    if (choice == 1 || choice == 2) {
        printf("Path: "); fgets(path, 512, stdin); path[strcspn(path, "\n")] = 0;
        if (choice == 1) { if (setxattr(path, GSM_TAG, "1", 1, 0) == 0) printf("Protected.\n"); else perror("Error"); }
        else { if (removexattr(path, GSM_TAG) == 0) printf("Unprotected.\n"); else perror("Error"); }
    }
}

int main() {
    int dev_fd, choice;
    signal(SIGINT, signal_handler);
    load_hash_database(CONFIG_FILE);
    load_whitelist();
    dev_fd = open(DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) return 1;

    while (1) {
        printf("\n╔════════════════════════════════════════════╗\n");
        printf("║         GSM SECURITY MANAGER MENU          ║\n");
        printf("╠════════════════════════════════════════════╣\n");
        printf("║ 1. Start Monitoring (%-7s Mode)     ║\n", verbose_mode ? "Verbose" : "Stealth");
        printf("║ 2. Toggle Verbose Mode                     ║\n");
        printf("║ 3. Virus List (Hashes)                     ║\n");
        printf("║ 4. Whitelist (Ignore Paths)                ║\n");
        printf("║ 5. Blocked List (Protect Files)            ║\n");
        printf("║ 6. Exit                                    ║\n");
        printf("╚════════════════════════════════════════════╝\nSelection: ");
        if (scanf("%d", &choice) != 1) { while(getchar() != '\n'); continue; }
        switch (choice) {
            case 1: run_monitoring(dev_fd); break;
            case 2: verbose_mode = !verbose_mode; printf("Verbose Mode: %s\n", verbose_mode ? "ON" : "OFF"); break;
            case 3: manage_virus_list(); break;
            case 4: manage_whitelist(); break;
            case 5: manage_blocked_list(); break;
            case 6: close(dev_fd); return 0;
        }
    }
    return 0;
}

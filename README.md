# GSM - General Security Manager & Real-time Antivirus (EDR)

**GSM** is a proactive security module for the Linux Kernel and a real-time behavioral antivirus (EDR). It protects files from unauthorized modification/deletion and prevents the execution of known malware by combining Syscall Hooking, SHA-256 validation, YARA signatures, and Extended Attributes (xattr).

## Key Features

*   **Multi-Layer Detection**: Combines SHA-256 file hashing with **YARA Pattern Matching** to detect malware DNA even if the file is recompiled.
*   **Automated Quarantine**: Automatically moves detected threats to the `./quarentena` folder and strips them of execution permissions.
*   **Behavioral Monitoring (EDR)**: Marks suspicious files as `suspect`. The Kernel monitors these processes in real-time and kills them if they attempt dangerous actions (like deleting files).
*   **Recursive Metadata Protection**: Lock any folder by adding the `user.gsm_protected=1` tag; the protection automatically extends to all files and subfolders within.
*   **Master Safety Lock**: Hardcoded whitelist for critical system paths (`/bin`, `/etc`, `/usr`, etc.) to prevent accidental quarantine of system tools.
*   **Interactive Management Menu**: User-space daemon (`gsmc`) to manage virus lists, whitelists, and advanced protection tags.
*   **Auto-Lock Timer**: Security password validates unlock state in RAM, automatically re-locking file protection after 60 seconds.

## Usage

### 1. Installation and Loading
Install requirements and compile the project:
```bash
sudo apt install libyara-dev libssl-dev
make
sudo insmod gsm.ko
```

### 2. Starting the Antivirus Daemon
Run the interactive daemon to start real-time monitoring:
```bash
sudo ./gsmc
```

### 3. Management Menu Options
*   **1. Start Monitoring**: Enters real-time scanning mode. Processes YARA rules and Hashes.
*   **2. Toggle Verbose Mode**: Shows every file being accessed, including safe system paths.
*   **3. Virus List**: Manage SHA-256 hashes of known threats.
*   **4. Whitelist**: Manage paths that the scanner should ignore (system paths are protected by default).
*   **5. Blocked List**: Manage persistent protection for specific files or entire directory trees.

### 4. Setting the Security Password
Define your password to temporarily unlock protected files:
```bash
echo -n "your_secret_password" | sudo tee /proc/gsm_control
```

## Protection Layers

1.  **Syscall Hooking**: Interception of `unlinkat`, `write`, `execve`, and `execveat`.
2.  **YARA Engine**: Scans file DNA for malicious patterns and dangerous API usage.
3.  **Behavioral Guard**: Identifies if a process belongs to a `suspect` file and blocks harmful actions at the Kernel level.
4.  **XATTR Guard**: Real-time verification of `user.gsm_protected`, `user.gsm_malicious`, `user.gsm_suspect`, and `user.gsm_quarantine`.

## Configuration Files
The system automatically manages these files in the `/hashes` directory:
*   `/hashes/gsm_hashes.conf`: Database of malicious SHA-256 hashes.
*   `/hashes/gsm_whitelist.conf`: User-defined safe paths.
*   `/hashes/gsm_blocked.conf`: Persistent list of protected files and folders.
*   `./YARA/`: Directory containing all `.yar` signature files.

## Requirements
*   **Linux Kernel 6.6.x**: Tested on 6.6.9.
*   **Libraries**: `libyara` (YARA) and `libcrypto` (OpenSSL).
*   **Filesystem**: Must support Extended Attributes (e.g., Ext4, XFS).

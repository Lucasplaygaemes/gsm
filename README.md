# GSM - General Security Manager & Real-time Antivirus

**GSM** is a proactive security module for the Linux Kernel and a real-time antivirus daemon. It protects files from unauthorized modification/deletion and prevents the execution of known malware by combining Syscall Hooking, SHA-256 validation, and Extended Attributes (xattr).

## Key Features

*   **Real-time Antivirus Scanning**: Automatically scans files upon creation or access and compares their SHA-256 hash against a malware database.
*   **Execution Blocking**: Intercepts `execve` and `execveat` syscalls to prevent programs marked with the `user.gsm_malicious` tag from running.
*   **Metadata-Based Protection**: Lock any file or folder by adding the `user.gsm_protected=1` flag, making it impossible to delete or modify.
*   **Interactive Management Menu**: User-space daemon (`gsmc`) with a built-in menu to manage Virus Lists, Whitelists, and Protection tags.
*   **Stealth Monitoring**: High-performance monitoring with adjustable verbosity and a dynamic whitelist to ignore system noise (e.g., `/usr/share`, `/proc`).
*   **Cryptographic Security**: GSM uses SHA-256 hashing to validate the unlock password within the RAM.
*   **Auto-Lock Timer**: Once unlocked, the system automatically re-arms its file protection after 60 seconds.

## Usage

### 1. Installation and Loading
Compile the module and the management daemon:
```bash
make
sudo insmod gsm.ko
```

### 2. Starting the Antivirus Daemon
Run the interactive daemon to start monitoring and manage your lists:
```bash
sudo ./gsmc
```

### 3. Management Menu Options
*   **1. Start Monitoring**: Enters real-time scanning mode. Only threats are shown by default (Stealth Mode). Press `Ctrl+C` to return to the menu.
*   **2. Toggle Verbose Mode**: When ON, shows every file being scanned, including safe ones.
*   **3. Virus List**: Add or remove SHA-256 hashes of known threats.
*   **4. Whitelist**: Manage paths that the scanner should ignore (e.g., system libraries, icon folders).
*   **5. Blocked List**: Manually protect/unprotect files from deletion and modification.

### 4. Setting the Security Password (Kernel Protection)
Define your security password for the volatile memory. This is required to remove protection from files marked with `user.gsm_protected`.
```bash
echo -n "your_secret_password" | sudo tee /proc/gsm_control
```

## Protection Layers

1.  **Syscall Hooking**: Interception of `unlinkat`, `write`, `execve`, and `execveat`.
2.  **SHA-256 Guard**: User-space validation of file integrity against a malware database.
3.  **XATTR Guard**: Real-time verification of `user.gsm_protected` and `user.gsm_malicious` attributes via `vfs_getxattr`.

## Configuration Files
The system automatically manages these files in the `/hashes` directory:
*   `/hashes/gsm_hashes.conf`: Database of malicious SHA-256 hashes.
*   `/hashes/gsm_whitelist.conf`: List of paths ignored by the real-time scanner.

## Requirements
*   **Linux Kernel 6.6.x**: Required for `mnt_idmap` support in xattrs.
*   **Filesystem**: Must support Extended Attributes (e.g., Ext4, XFS).
*   **Libraries**: OpenSSL (libcrypto) for SHA-256 calculations.
*   **Packages**: `attr` package installed (`sudo apt install attr`).

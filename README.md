# GSM - General Security Manager

**GSM** or **Geral Security Manager* is a proactive security module for the Linux Kernel (tested on version 6.6.9) designed to protect files and directories from unauthorized deletion or modification. It operates by intercepting system calls (Syscall Hooking) and utilizing filesystem extended attributes (xattr).

## Key Features

*   **Metadata-Based Protection**: Protect any file or folder by simply adding the `user.gsm_protected=1` flag.
*   **Write Hook (`sys_write`)**: Prevents any changes to the content of protected files, in addition to preventing deletion.
*   **Cryptographic Security**: Passwords are no longer stored in plain text. GSM uses **SHA-256** hashing to validate access within the RAM.
*   **Volatile Persistence**: The password is set upon the first use after booting and resides only in the Kernel's protected memory space.
*   **Auto-Lock Timer**: Once unlocked, the system automatically re-arms its protection after 60 seconds.

## Usage

### 1. Installation and Loading
Compile the module and insert it into the Kernel:
```
make
sudo insmod gsm.ko
```

2. Setting the Password (First Use)

After loading the module, define your security password. This will be hashed and stored in volatile memory.  

```
echo -n "your_secret_password" | sudo tee /proc/gsm_control
```

Note: GSM will only store the SHA-256 hash of this password.  

3. Protecting Files

GSM no longer relies solely on filenames. Use extended attributes to mark targets.  
```
# Add protection flag
sudo setfattr -n user.gsm_protected -v 1 /path/to/file

# Verify if the tag is applied
getfattr -d /path/to/file

# Remove protection (requires the system to be unlocked)
sudo setfattr -x user.gsm_protected /path/to/file
```
4. Temporary Unlocking
To delete or edit protected files (or critical directories like /etc/), send the password again.
```
echo -n "your_secret_password" | sudo tee /proc/gsm_control
```
The system will be unlocked for a 60-second window.  

# Current Protection Layers
Syscall Hooking: Interception of unlinkat and write functions.  
String Filtering: Native protection for any file 

XATTR Guard: Real-time verification of user.gsm_protected attributes via vfs_getxattr.  

# Requirements

Linux Kernel 6.6.x: Support for mnt_idmap in xattrs.
Filesystem: Must support XATTR (e.g., Ext4, XFS).
Packages: attr package installed (sudo apt install attr).

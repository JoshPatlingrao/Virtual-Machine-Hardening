# Virtual-Machine-Hardening

## Objective
The purpose of this lab is to setup a hardened Arch Linux installation in a virtual machine. The skills developed in this project will be the usage of CLI, researching documentations, generating backups and applying security configurations based on the foundations of Security+.

## Skills Learned
- Setting up Linux installation and configuration through CLI.
- Researching online documentation and applying changes based on the current version of the OS.
- Generating snapshots with brief descriptions as backups.

## Tools Used
- Oracle VM Virtual Box
- Arch Linux

## Steps
### 1. Download VirtualBox and Arch Linux

### 2. Configure VM

### 3. Install Arch

### 4. Configure Arch Security Configurations
#### 4.1 Kernel - Sysctle
Kernel hardening is a vital part of Linux security. Without these sceurity configurations a base Linux kernel can be vulnerable against exploits which allows an attacker to escalate privileges and accessing sensitive files.

Sysctl is the tool that's used to permanently modify certain kernel tunables.

<strong>4.1.1 kptr_restrict.conf</strong>

The purpose of this configuration file is to prevent kernel pointers from being leaked. These kernel symbol addresses can be found in ‘/proc/kallsyms’. These are subject to being downloaded by an attacker who has created an account in the system and can be used for kernel exploits. 

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'kptr_restrict.conf'
- Open the file with a text editor
- Write 'kernel.kptr_restrict=2' in the file and save

If the ‘linux-hardened’ kernel is installed then it sets the ‘kptr_restrict=2’ by default, but if the ‘linux’ kernel is installed instead then the default is set to ‘kptr_restrict=0’. Those using 'linux' kernel will need to manually configure the 'kptr_restrcit this way.

The values for this configuration can be:
- 0: which allows any user to see the kernel symbol addresses
- 1: which hides the kernel symbol addresses from non-root users
- 2: which hides kernel symbol addresses to all users, regardless of privileges
- [Insert link reference]

Option '2' was chosen as it's the most secure out of all three and prevents attackers from seeing the kernel symbol addresses even if they get access to privileegd user accounts.

<strong>4.1.2 dmesg_restrict.conf</strong>

This configuration file is for restricting non-root users from viewing the kernel logs. Attackers will try to access kernel logs as it qmay contain useful information such as kernel pointers. It’s still available to root users for troubleshooting purposes.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'dmesg_restrict.conf'
- Open the file with a text editor
- Write 'kernel.kptr_restrict=2' in the file and save

<strong>4.1.3 harden_bpf.conf</strong>

This configuration file allows only the ‘root’ account to use BPF JIT compiler. Without this restriction, an attacker could easily exploit vulnerabilities such as JIT spraying to access it.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'harden_bpf.conf'
- Open the file with a text editor
- Write these lines, then save
  - kernel.unprivileged_bpf_disabled=1
  - net.core.bpf_jit_harden=2

<strong>4.1.4 ptrace_scope.conf</strong>

This configuration file limits the usage of ‘ptrace’ to only processes that has ‘CAP_SYS_PTRACE’.

The ‘ptrace’ is a system call that allows a program to alter and inspect a running process. If an attacker gets access to the ‘ptrace’ then they can easily compromise other running programs within the computer.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'ptrace_scope.conf'
- Open the file with a text editor
- Write 'kernel.yama.ptrace_scope=2' in the file and save

### 5. Best Practices

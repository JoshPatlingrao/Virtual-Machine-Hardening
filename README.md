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

<strong>4.1.5 kexec.conf</strong>

This configuration file is for disabling the ‘kexec’ which can be used to replace the running kernel.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'kexec.conf'
- Open the file with a text editor
- Write 'kernel.kexec_load_disabled=1' in the file and save

<strong>4.1.6 tcp_hardening.conf</strong>

This configuration file is to secure the TCP/IP stack and tighten network security options.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'tcp_hardening.conf'
- Open the file with a text editor
- Write 'net.ipv4.tcp_syncookies=1' in the file

This section of the file is configured to help protect against SYN flood attacks from TCP connections. SYN flood attacks are a type of DoS attacks where an attackers sends a lot of SYN packages to get the end point to exhaust its resources and leave it unresponsive to legitimate traffic.

- Write
  - net.ipv4.conf.default.rp_filter=1
  - net.ipv4.conf.all.rp_filter=1

This section of the file is configured to enable source validation of packets received from all interfaces of the machine. By validating the source of the packets, it can confirm whether the packet came from a trusted server or was spoofed by an attacker.

- Write
  - net.ipv4.conf.all.accept_redirects=0
  - net.ipv4.conf.default.accept_redirects=0
  - net.ipv4.conf.all.secure_redirects=0
  - net.ipv4.conf.default.secure_redirects=0
  - net.ipv6.conf.all.accept_redirects=0
  - net.ipv6.conf.default.accept_redirects=0

This section of the file disables the ICMP redirect acceptance. This helps defend from an ICMP request that could be redirected by an attacker from anywhere they want.

- Write
  - net.ipv4.conf.all.send_redirects=0
  - net.ipv4.conf.default.send_redirects=0

This section disables ICMP redirect sending when on a non-router.

- Write 'net.ipv4.icmp_echo_ignore_all=1', then save

This section makes my machine ignore all ICMP requests, which an attacker can use as a DoS attack.

<strong>4.1.7 mmap_aslr.conf</strong>

This configuration file is to set the highest values for improve the ASLR effectiveness for ‘mmap’.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'mmap_aslr.conf'
- Open the file with a text editor
- Write these lines, then save
  - vm.mmap_rnd_bits=32
  - vm.mmap_rnd_compat_bits=16
 
<strong>4.1.8 sysrq.conf</strong>

This configuration file disables the Sysrq key which exposes many potentially dangerous debugging functionalities for unprivileged local users.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'sysrq.conf'
- Open the file with a text editor
- Write 'kernel.sysrq=0' in the file and save

<strong>4.1.9 unprivileged_userns_clone.conf</strong>

This configuration file disables unprivileged user namespaces, which can add a lot of attack surfaces for privilege escalation. This restricts namespaces for root users only.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'unprivileged_userns_clone.conf'
- Open the file with a text editor
- Write 'kernel.unprivileged_userns_clone=0' in the file and save

<strong>4.1.10 tcp_sack.conf</strong>

This configuration file disables TCP SACK, which is commonly exploited and but is not needed for many circumstances. Selective ACK is a type of ACK that allows endpoints to specifically communicate which packets of a large file have been lost during transmission, and allows a server to resend only those specific files again. An attacker can exploit this by keeping a long retransmission queue for an extended amount of time before processing the whole queue repeatedly which will rapidly eat up the resources of my virtual machine. Since this virtual box is only for lab purposes and no large files will be downloaded, SACK has been disabled.

Steps
- Navigate to '/etc/sysctl.d' directory
- Create a file and name it 'tcp_sack.conf'
- Open the file with a text editor
- Write 'net.ipv4.tcp_sack=0' in the file and save

### 5. Best Practices

# Virtual-Machine-Hardening: Linux Edition

## Objective

The purpose of this lab is to setup a hardened Arch Linux installation in a virtual machine. The skills developed in this project will be the usage of CLI, researching documentations, generating backups and applying security configurations based on the foundations of Security+.

### Skills Learned
- Setting up Linux installation and configuration through CLI.
- Researching online documentation and applying changes based on the current version of the OS.
- Generating snapshots with brief descriptions as backups.

### Tools Used
- Oracle VM Virtual Box
- Arch Linux

## Steps
### 1. Download VirtualBox and Arch Linux

<a href="https://www.virtualbox.org/wiki/Downloads">Oracle VM Virtual Box</a>

<a href="https://archlinux.org/download/">Arch Linux</a>
- Go to HTTP Direct Downloads section
- Click one of the links in Worldwide section
- Download from 'archlinux-2024.09.01-x86_64.iso'

Arch Linux File Integrity Check
- Open 'Windows Powershell'
- Type 'Get-Filehash' followed by a space
- Drag the .iso file into the Powershell window
- Run the command
- Compare the SHA256 hash in Powershell window with the 'sha256sums.txt' in the downloads page

If both hashes match then file integrity is confirmed. Otherwise some packets may have been dropped or lost, in which case try to re-download again.

### 2. Configure VM

- Run Oracle VM Virtualbox Manager
- Click on 'New'

![image](https://github.com/user-attachments/assets/2c3f6951-e403-4748-868f-cc6d6f414e0c)

- Name the virtual machine
- Click on dropdown arrow on ISO Image and select the Arch .iso image

![Capture 1](https://github.com/user-attachments/assets/3b73ce53-b7a7-4a5f-9168-6907fbf663e2)

- Allocate base memory and processors
  - Host machine resources will vary per person, but minimum OS requirements for Arch are as follow:
    - 512MB RAM
    - 1 Core CPU
    - 1GB Disk Space
  - Recommended requirements are as follow:
    - 2GB RAM
    - 2 - 4 Core CPU
    - 20GB Disk Space (To enable GUI usage)
- Click next when finished

![image](https://github.com/user-attachments/assets/6f898b44-15af-4210-9ecd-8dbf51021fd8)

- Allocate virtual disk size
  - Refer to previous section for minimum and recommended requirements
- Click next

![image](https://github.com/user-attachments/assets/1d022c9e-042a-45e0-923f-de775c93208d)

- Confirm VM configurations and click Finish

![Capture 2](https://github.com/user-attachments/assets/bf4c1ab1-1a7d-4cab-b342-fc75535563ac)

- Highlight your machine
- Click on Settings
- Go to General -> Advanced
- Set Shared Clipboard to Bidirectional
  - Makes it easier to copy and paste text between host and virtual machine

![Capture 3](https://github.com/user-attachments/assets/d1968a92-dbf9-4358-a73f-a986e1a01bc2)

- Got to Display
- Max out Video Memory
- Tick Enabled 3D Acceleration
  - This allows the VM to use the host machine's graphics card to render 3D graphics based on OpenGL

![image](https://github.com/user-attachments/assets/c5d05092-fd09-44e4-a554-b638377d2e99)

- Click Start to run the VM and begin Arch Linux setup

### 3. Install Arch

<strong>Start Up</strong>
- On boot, select the 'Arch Linux install medium (x86_64, BIOS)' option to boot into the Arch install

<strong>Internet Connection Check</strong>
- Run 'ping archlinux.org' command
- Wait until four replies have been received, then terminate command with Ctrl+C

<strong>Synchronise Package List</strong>
- Run 'pacman -Sy'

<strong>Install Latest Keys</strong>
- Run 'pacman -Sy archlinux-keyring'
- Enter 'y' to confirm

<strong>Arch Install</strong>
- Run 'archinstall'
- If command is not found, install with 'pacman -Sy archinstall'

<strong>Configure Arch</strong>
- Go to Mirrors -> Mirror Region
- Select the region closest to you
  - This makes ensures that whenever the OS is updated, it will pull from the mirror region specified here.
---
- Go to Disk Configuration -> Partitioning -> Use Best Effort Default
- Select ATA VBOX HARDDISK
  - Confirm that this is the virtual disk configured in the VM manager by looking at its disk space. It should be close to what you configured.
- Select 'xfs' as filesystem for main partition
  - For this lab 'xfs' is chosen, but any file system can be used
---
- Go to Bootloader
- Select 'Grub' which should be default
---
- Go to Root Password
- Setup your password
  - Password will not be displayed for security purposes
  - Password strength will be displayed after entering initial password, this will based on length and characters used
---
- Go to User Account -> Add User
- Enter user name
- Setup password
- For the purposes of this lab, make this account a superuser
- Confirm and Exit
---
- Go to Profile -> Type
- Select Desktop
- For the purposes of this lab, select 'KDE Plasma' as desired desktop environment
---
- Go to Audio Server
- Select Pipewire
  - It offers the best quality. Pulseaudio will soon be obsolete.
---
- Go to Kernels
- For the purposes of this lab, select 'linux'
---
- Go to Additional Packages
- Install any additional packages you want through 'sudo package_1 package_2' this format
---
- Go to Network Configuration
- Select NetworkManager
---
- Go to Timezone
- Select your timezone
---
- Go to Install to begin installation
---
<strong>Post Installation Steps</strong>
- Select 'yes' to enter chroot environment
- Run 'neofetch' to visually confirm instalation
- Install additional tools if you want
  - For the purposes of this lab, run 'pacman -Sy firefox libreoffice-fresh flatpak make htop' to install these tools
- When finished, run 'exit'
- Run 'shutdown now' to power off VM
---
- Go to VM Settings in VM Manager
- Go to Storage tab
- Under Controller:IDE, select the Arch .iso
- Click on the disk icon at Optical Drive and select Remove Disk
- Close Settings
- Click Start to boot into Arch

![image](https://github.com/user-attachments/assets/ccf52fbe-6065-47d6-a2a3-a11cf7c0ce81)

### 4. Configure Arch Security Configurations
#### 4.1 Kernel - Sysctl
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

<strong>4.1.11 no-conntrack-helper.conf</strong>

This configuration file disables the netfilter’s automatic conntrack helper assignment as it enables a lot of code in the kernel that parses incoming network patches which is potentially unsafe

Steps
- Navigate to '/etc/modprobe.d/' directory
- Create a file and name it 'no-conntrack-helper.conf'
- Open the file with a text editor
- Write 'options nf_conntrack nf_conntrack_helper=0' in the file and save

#### 4.2 Root Account

Root accounts are privileged accounts that have full access to all of the VM's resources. Implementing multiple defensive measure is paramount to minimizing the possibility of an attacker gaining access to it.

<strong>4.2.1 Restricting 'su'</strong>

The 'su' is a CLI command that allows a user to switch accounts from the terminal. By default, it will try to log the user in as 'root' which easily exposes the root account to password attacks.

Steps
- Navigate to '/etc/pam.d/' directory
- Open the 'su' file with a text editor
- Uncomment the 'auth required pam_wheel.so use_uid' line and save

<strong>4.2.2 Deny SSH Root Login</strong>

This configuration file prevents anyone from connecting remotely through SSH and logging in as 'root'. While it may be convenient to use SSH to login as 'root', the benefit of preventing an attacker from doing the same outweighs the inconvenience. The VM's purpose is to be used as a lab and therefore will not contain any sensitive data which which may need to be remotely accessed which further reinforces this configuration in this case.

Steps
- Navigate to '/etc/ssh/' directory
- Open the 'sshd_config' file with a text editor
- Write 'PermitRootLogin no' in a new line and save

This section only applies if VM machine Network configuration was set to Bridged Adapter, which will allow any computer within the network to access the VM via SSH.

<strong>4.2.3 Increase the Number of Hashing Rounds</strong>

This configuration file is to ensure that the passwords will undergo multiple rounds of SHA512 hashing, making it difficult for attackers to crack in the case they steal the hashed password.

Steps
- Navigate to '/etc/pam.d/' directory
- Open the 'system-auth' file with a text editor
- Write 'password required pam_unix.so sha512 shadow nullok rounds=50000' in a new line and save

The number of rounds can be modified to any amount, but current setting is at 50,000 rounds as a balance between functionaility and security. Larger numbers will provide better security but result in longer waiting times when logging in as the machine runs multiple hashing rounds. Smaller numbers will results in relatively faster loading times but will make it easier for attackers to crack the password.

The current password will not be automatically hashed. A new password must be generated using 'passwd username', where the 'username' part is the user account which needs to replace its current password.

#### 4.3 Umask

This configuration file is to set the ‘umask’, what defines the permissions for newly created files. The default is normally set to 022, which gives read access for all users for any newly created files. Some files may contain sensitive information that has been put in there by the author.

Steps
- Navigate to '/etc/' directory
- Open the 'login.defs' file with a text editor
- Modify UMASK value from 022 to 0077 and save

The value has been modified to 0077, giving read, write and execute permission only to the owner. This gives owner more control over who can read the files they made as they can modify their file permissions as they need while keeping its confidentiality limited to them.

This can be confirmed through the 'umask -S' command which will return the symbolic notation of the read, write and execute permission.

#### 4.4 DMA Attacks

This configuration file is to disable to Thunderbolt and Firewire modules as these can enable DMA attacks.

Steps
- Navigate to '/etc/modprobe.d/' directory
- Create a file and name it 'blacklist-dma.conf'
- Open the file with a text editor
- Write these commands and save
  - install firewire-core /bin/true
  - install thunderbolt /bin/true

Direct Memory Access Attacks are a type of side channel attack that exploits the presence of high-speed expansion ports that permit DMA. DMA allows a connected device – such as an external storage or a camera – to transfer data between itself and the computer at the fastest speed possible through direct hardware access to read and write directly to the main memory without any interaction or supervision from the OS. If an attacker can access this channel, then they can easily bypass security mechanisms in the computer, see sensitive data and install malware or backdoors.

#### 4.5 Core Dumps

This configuration file is to disable core dumps.

Steps
- Navigate to '/etc/sysctl.d/' directory
- Create a file and name it 'coredump.conf'
- Open the file with a text editor
- Write 'kernel.core_pattern=|/bin/false' in the file and save

Core dumps contain the recorded state of the working memory of a program at a specific time, usually when that program has crashed. The information within can be very sensitive such as passwords or encryption keys, which can be used to compromise other files or accounts within the computer.

#### 4.6 PAM

This configuration file is to configure the PAM.

Steps
- Navigate to '/etc/pam.d/' directory
- Open the 'system-auth' file with a text editor
- Write 'password required pam_cracklib.so retry=2 minlen=10 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1' in the 'password' section
- Modify the 'password required pam_unix.so sha512 shadow nullok rounds=50000' to 'password required pam_unix.so use_authtok sha512 shadow nullok rounds=50000'
  - The 'use_authtok' instructs the pam_unix module to not prompt for a password but use the one provided by pam_quality which has these policies enforced
- Save

PAM is a framework for system-wide user authentication and can be used to enforce password policies throughout the system. These are the parameters I’ve set:
- retry: set to 3 so it gives the user 3 times to enter their password in case of mistakes
- minlen:  makes the user set a password with a minimum length of 10 characters
- difok: ensures that the new password generated by the user has at least 10 different characters from previous. Even if user sticks to 10 character minimum length then the new password has no similar characters from previous which further increases its strength
- dcredit: enforces at least 1 digit
- ucredit: enforces at least 1 uppercase letter
- lcredit: enforces at least 1 lowercase letter
- ocredit: enforces at least 1 other character
- badwords: ensures words like ‘myservice’ and ‘mydomain’ can’t be included in passwords
  
Due to updates in NIST’s password guidelines, usage of at least 1 special character is no longer enforced but is still optional. This is due to human behaviour which often leads to usage of special characters which can make it easier for attackers to predict or crack.

#### 4.7 Blacklist Uncommon Network Protocols

This configuration file is to disable uncommon network protocols.

Steps
- Navigate to '/etc/modprobe.d/' directory
- Create a file and name it 'uncommon-network-protocols.conf'
- Open the file with a text editor
- Write the command in this format 'install protocol_name /bin/true', where 'protocol_name' is replaced with the uncommon protocol
  - dccp, sctp, rds, tipc, n-hdlc, ax25, netrom, x25, rose, decnet, econet, af_802154, ipx, appletalk, psnap, p8023, llc, p8022
- Save

The kernel allows unprivileged users to load certain vulnerable modules through module auto-loading which increases the attack surface as these modules have known exploits. To decrease the attack surface, uncommon or rarely used network protocols will be blacklisted.

#### 4.8 Disable Mounting of Uncommon Filesystems

This configuration file is to disable uncommon filesystems.

Steps
- Navigate to '/etc/modprobe.d/' directory
- Create a file and name it 'uncommon-filesystems.conf'
- Open the file with a text editor
- Write the command in this format 'install filesystem_name /bin/true', where 'filesystem_name' is replaced with the uncommon filesystem
  - cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf
- Save

These filesystems are rarely used and will be disabled to reduce further vulnerabilities and attack surfaces of the computer.

### 5. Best Practices

A system can never be fully secure, there will always be zero-day vulnerabilities to be exploited or human errors which could compromise the system, but the latter can at least be mitigated with through education of good security practices.
- Disable/remove protocols, applications and files you don't need.
- Develop strong password policies through NIST guidelines.
- Regularly update systems to patch out vulnerabilities.
- Be mindful of information which could be used to compromise your system.

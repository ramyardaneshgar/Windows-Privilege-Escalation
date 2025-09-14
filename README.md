# Windows-Privilege-Escalation
Windows Privilege Escalation -  using tools like winPEAS, AccessChk, PrivescCheck, and secretsdump.py; with exploitation via schtasks, icacls, sc, reg save, and runas.

By Ramyar Daneshgar 


## Task 2: Windows Privilege Escalation Basics

To begin, I noted that users who can modify system configurations typically belong to the **Administrators** group, as this group is granted broad control over local machine policies. Additionally, I acknowledged that the **SYSTEM** account inherently has more privileges than any local administrator account because it operates at the kernel level, which is especially important when targeting the highest level of access on a compromised host.

---

## Task 3: Harvesting Passwords from Usual Spots

### PowerShell History

One of the first areas I checked was PowerShell command history. Since commands executed in interactive sessions are often stored in `ConsoleHost_history.txt`, I retrieved the file with:

```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

This revealed a credential used with `cmdkey` for the user `julia.jones`, including the password `ZuperCkretPa5z`. This suggested either credential stuffing or possible lateral movement.

### IIS Configuration Files

Next, I checked for sensitive data hardcoded in IIS configuration files, which often store database credentials in plaintext for legacy applications. Using `findstr` on the path to `web.config`, I discovered a SQL connection string that included the password `098n0x35skjD3` for the user `db_admin`. This demonstrated poor secrets management and highlighted how developers often overlook secure configuration practices.

### Stored Windows Credentials

I ran `cmdkey /list` to enumerate saved credentials and found an entry for `mike.katz`. Using `runas /savecred`, I launched a shell under his context without needing the password, because Windows Credential Manager had cached it. This allowed me to access `mike.katz`’s desktop and extract the flag.

### PuTTY Saved Sessions

Because PuTTY stores session credentials in the Windows Registry, I queried it with:

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

This led me to retrieve the saved `ProxyPassword` for the user `thom.smith`, which was stored in plaintext as `CoolPass2021`. This reinforced the need for caution when storing credentials locally, even in trusted software.

---

## Task 4: Other Quick Wins - Scheduled Tasks

Scheduled tasks can be abused when associated scripts are writable by unprivileged users. I identified a scheduled task named `vulntask` using:

```
schtasks | findstr "vuln"
```

It pointed to `C:\tasks\schtask.bat` and was set to run as `taskusr1`. Since I had write permissions on the `.bat` file, I replaced its contents with a reverse shell command using `nc64.exe`. After triggering the task with `schtasks /run`, I caught a shell with `taskusr1` privileges. This is a common privilege escalation vector caused by improper task permission configuration.

---

## Task 5: Abusing Service Misconfigurations

### Insecure Permissions on Service Executable

I ran `sc qc windowsscheduler` to inspect the service configuration and noted it ran as `svcusr1`. Then `icacls` revealed that the executable was writable by the `Everyone` group. This meant I could overwrite it with a reverse shell payload using `msfvenom`, and when the service restarted, it would execute as `svcusr1`. After replacing the binary and restarting the service with `sc start`, I received a shell under `svcusr1`.

### Unquoted Service Path

Unquoted service paths allow privilege escalation when Windows mistakenly executes a binary in a directory with spaces. I checked `sc qc "disk sorter enterprise"` and confirmed it pointed to:

```
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
```

Because this path was not quoted and the directories were writable, I dropped a reverse shell payload as `C:\MyPrograms\Disk.exe`, which Windows would execute due to how it parses unquoted paths. Restarting the service triggered execution, and I caught a shell as `svcusr2`.

### Insecure Service Permissions

Using `Accesschk`, I determined that the service `thmservice` allowed `BUILTIN\Users` full control, including the ability to change the service binary path. I uploaded a reverse shell payload and reconfigured the service to point to my executable using `sc config`, setting the `obj` to `LocalSystem`. Starting the service resulted in a SYSTEM-level shell, confirming the danger of lax DACLs on services.

---

## Task 6: Abusing Dangerous Privileges

### SeBackupPrivilege and SeRestorePrivilege

To exploit `SeBackupPrivilege`, I used `reg save` to dump the SAM and SYSTEM registry hives. I copied them to my attack box using a temporary SMB server (`smbserver.py`). I then used `secretsdump.py` to extract NTLM hashes. With the Administrator hash, I performed a Pass-the-Hash attack using `psexec.py`, gaining a SYSTEM shell. This highlights how sensitive local data can be exfiltrated without triggering alarms, particularly when backup privileges are misused.

### SeTakeOwnershipPrivilege

I exploited `SeTakeOwnershipPrivilege` by taking ownership of `utilman.exe` and replacing it with `cmd.exe`. Triggering utilman from the login screen gave me a SYSTEM shell. This technique works when user accounts with this privilege can tamper with system binaries without triggering UAC or Defender, a frequent misconfiguration in loosely secured environments.

---

## Task 7: Abusing Vulnerable Software

I identified that Druva inSync 6.6.3 was installed, a known vulnerable application. I executed a PowerShell exploit (`exp.ps1`) that sent a malicious RPC command to the service, creating a new user `pwnd` and adding it to the Administrators group. After switching users with an elevated PowerShell session, I verified admin rights and accessed the final flag. This showed how insecure RPC endpoints in poorly maintained enterprise software can lead to full compromise.

---

## Task 8: Tools 

To streamline enumeration and privilege escalation, I ran the following tools:

- **WinPEAS** to automate detection of misconfigurations, unquoted paths, credential leaks, and dangerous privileges.
- **PrivescCheck** to generate a detailed report of exploitable conditions based on common escalation paths.
- **Metasploit's local_exploit_suggester** for automated assessment when I had a Meterpreter shell.

These tools reduced manual overhead and validated many of the attack paths I had discovered manually.


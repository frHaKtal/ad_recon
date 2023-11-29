#!/bin/bash

echo "┌───────────────────────────────┐"
echo "│┏━┓╺┳┓   ┏━┓┏━╸┏━╸┏━┓┏┓╻╻┏┓╻┏━╸│"
echo "│┣━┫ ┃┃   ┣┳┛┣╸ ┃  ┃ ┃┃┗┫┃┃┗┫┃╺┓│"
echo "│╹ ╹╺┻┛   ╹┗╸┗━╸┗━╸┗━┛╹ ╹╹╹ ╹┗━┛│"
echo "│         by _frHaKtal_         │"
echo "└───────────────────────────────┘"

rm *.ad >/dev/null
echo "-> Find Subnet.."
#SUBNET=$(ip addr | grep -i eth0 | grep -i inet | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}[\/]{1}[0-9]{1,2}")
SUBNET="192.168.56.1/24"
echo "[*] Subnet: "$SUBNET

echo "-> Scan Network.."
crackmapexec smb $SUBNET > cme.ad
#cat cme.ad
#echo $smb > host_with_samba.txt
##traiter la sortie pour n' avoir que les ip samba
cat cme.ad | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | tr ' ' '\n' > ip.ad
cat cme.ad | awk '{print $12}'| tr -d "()" | tr -s '\n' | sed "s/domain://g" | sort -u > domain.ad
#cme_domain=$(cat cme.ad | awk '{print $12}'| tr -d "()" | sed "s/domain://g" | tr ' ' '\n')
#echo $smb | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' > host_with_samba_ip.txt


echo "-> Find DC IP..."

#for xx in $(cat domain.ad)
#do
#    echo "[*] Domain detected: "$xx
#done

#DCIP=$(echo $smb | grep "signing:True" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+')
#DCIP=$(nmcli dev show eth0 | grep -m 1 -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+')
#echo $DCIP > tee DCIP_eth0.txt
#nslookup -type=srv _ldap._tcp.dc._msdcs.north.sevenkingdoms.local 192.168.56.10
#nslookup -type=srv _ldap._tcp.dc._msdcs.DOMAIN IP (retour de cme)


nmap -v -p 53 192.168.56.1/24 | grep "Discovered open port" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | sort -u > dcip.ad
echo "[*]  DCIP: "
cat dcip.ad

#scan vuln des host avec samba
if grep -q "SMBv1:True" cme.ad
then
echo "-> Scan smb vuln.."
cat cme.ad | grep "SMBv1:True" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | tr ' ' '\n' | xargs -I@ nmap -Pn --script smb-vuln* @ -oN host_samba_vuln.ad
cat host_samba_vuln.ad
fi


#scan dit normal
#echo "-> Nmap Scanning open ports"
#nmap -Pn -sV -oN host_scan_nmap.ad $SUBNET
#nmap -Pn -sV -sU -oN host_scan_nmap_udp.ad $SUBNET


echo "-> List guest access on smb share.."
cat ip.ad | xargs -I@ enum4linux-ng -A -u " " -p " " @
cat ip.ad | xargs -I@ enum4linux-ng -A -u "guest" -p " " @
cat ip.ad | xargs -I@ smbmap -u " " -p " " -P 445 -H @
cat ip.ad | xargs -I@ smbmap -u "guest" -p " " -P 445 -H @
cat ip.ad | xargs -I@ smbclient -U "%" -L //@
cat ip.ad | xargs -I@ smbclient -U "guest%" -L //@
cat ip.ad | xargs -I@ crackmapexec smb @ -u " " -p " "
cat ip.ad | xargs -I@ crackmapexec smb @ -u "guest" -p " "
cat ip.ad | xargs -I@ crackmapexec smb @ -u "anonymous" -p " "
cat ip.ad | xargs -I@ nbtscan @ -v


echo "-> Enumerate ldap.."
cat ip.ad | xargs -I@ nmap -Pn -n -sV --script "ldap* and not brute" -p 389 @ -oN host_scan_ldap.ad
cat ip.ad | xargs -I@ ldapsearch -x -H ldap://@ -s base > ldapsearch.ad


echo "-> Find user list.."
cat ip.ad | xargs -I@ enum4linux-ng -U @ > enum4linux.ad
cat ip.ad | xargs -I@ crackmapexec smb @ --users > crackmapexec_users.ad
cat enum4linux.ad | grep "username:"
cat crackmapexec_users.ad

echo "-> Vulnerabilities scan.."
echo "-> LLMNR/NBT-NS Poisoning"
cat ip.ad | xargs -I@ sh -c 'nmap -Pn @ --script smb2-security-mode.nse -p 445 | grep -q -E "Message signing enabled but not required|Message signing disabled" && echo "\033[1;31m "@" VULNABLE TO LLMNR/NBT-NS Poisoning"'
echo "-> Unauthent PetitPotam CVE-2022-26925"
cat ip.ad | xargs -I@ crackmapexec smb @ -M petitpotam
echo "-> Zerologon CVE-2020-1472"
cat ip.ad | xargs -I@ crackmapexec smb @ -M zerologon
echo "-> Eternal Blue MS17-010"
cat ip.ad | xargs -I@ crackmapexec smb @ -M ms17-010

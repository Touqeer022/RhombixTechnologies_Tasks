# Snort NIDS Lab - Step-by-Step Setup Guide

Host: Windows + VirtualBox. Snort 2.9.x on Ubuntu 22.04 (apt install works directly).

## Lab design

| VM | OS | IP | Role |
|---|---|---|---|
| Attacker | Kali Linux | 192.168.56.10 | Runs Nmap, hping3, hydra |
| Victim | Ubuntu Server / Metasploitable 2 | 192.168.56.20 | Target (web, ssh, ftp) |
| Sensor | Ubuntu 22.04 | 192.168.56.30 | Runs Snort (IDS) |

Analogy: Snort ek CCTV guard ki tarah hai jo gali (network) ke mod par khara hai. Attacker chor hai, victim ghar hai, aur guard sirf dekhta aur alarm bajata hai (IDS), rokta nahi (IPS).

## Step 1 - VirtualBox network (Windows PowerShell)

Internal network use karein taaki lab internet se alag rahe.

```powershell
# Replace VM names with yours. Run in PowerShell on the Windows host.
cd "C:\Program Files\Oracle\VirtualBox"
.\VBoxManage.exe modifyvm "Kali"    --nic2 intnet --intnet2 "snortlab" --nicpromisc2 allow-all
.\VBoxManage.exe modifyvm "Victim"  --nic2 intnet --intnet2 "snortlab" --nicpromisc2 allow-all
.\VBoxManage.exe modifyvm "Sensor"  --nic2 intnet --intnet2 "snortlab" --nicpromisc2 allow-all
```

Important: Sensor ka adapter promiscuous mode "Allow All" hona chahiye, warna Snort ko dusron ki traffic nazar nahi aayegi. Adapter 1 ko NAT rakhein taaki Sensor/Kali par packages install ho sakein.

## Step 2 - Static IPs on the lab adapter

On each VM (adapter name may be `enp0s8`; check with `ip a`):

```bash
# Sensor (Ubuntu 22.04) - netplan
sudo tee /etc/netplan/60-lab.yaml > /dev/null <<'EOF'
network:
  version: 2
  ethernets:
    enp0s8:
      addresses: [192.168.56.30/24]
EOF
sudo chmod 600 /etc/netplan/60-lab.yaml
sudo netplan apply
```

Kali (temporary, until reboot):

```bash
sudo ip addr add 192.168.56.10/24 dev eth1
sudo ip link set eth1 up
```

Victim: same method with `192.168.56.20/24`. Test: `ping 192.168.56.20` from Kali.

## Step 3 - Install Snort on the Sensor

```bash
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y snort
snort -V
```

If the installer asks for interface and HOME_NET, give `enp0s8` and `192.168.56.0/24`.

## Step 4 - Configure Snort

```bash
sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak
sudo nano /etc/snort/snort.conf
```

Set/confirm these lines:

```
ipvar HOME_NET 192.168.56.0/24
ipvar EXTERNAL_NET !$HOME_NET
var RULE_PATH /etc/snort/rules
include $RULE_PATH/local.rules
```

Optional (cleaner lab): comment out the other `include $RULE_PATH/*.rules` lines so only your custom rules fire.

Output alert format (find the `output` section and add):

```
output alert_fast: alert
```

Copy rules and create the log folder:

```bash
sudo cp local.rules /etc/snort/rules/local.rules
sudo mkdir -p /var/log/snort
sudo chown -R snort:snort /var/log/snort 2>/dev/null || true
```

## Step 5 - Test configuration

```bash
sudo snort -T -c /etc/snort/snort.conf -i enp0s8
```

`Snort successfully validated the configuration!` aana chahiye. Error aaye to rule file ki syntax check karein.

## Step 6 - Run Snort

Console alerts (best for live demo / screenshots):

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s8
```

Logging to file (best for analysis):

```bash
sudo snort -q -c /etc/snort/snort.conf -i enp0s8 -l /var/log/snort -A fast
```

Quick check with a ping from Kali: `ping -c 3 192.168.56.20`. Rule 1000001 ka alert aana chahiye.

## Step 7 - Start the victim services

On the victim (if Ubuntu, not Metasploitable):

```bash
sudo apt install -y apache2 openssh-server vsftpd
sudo systemctl enable --now apache2 ssh vsftpd
```

## Step 8 - Run attacks from Kali

```bash
sudo apt install -y hping3 hydra nmap netcat-traditional
chmod +x attack_simulation.sh
./attack_simulation.sh 192.168.56.20
```

Har test ke baad Sensor ka console dekhein aur screenshot lein.

## Step 9 - Analyse logs

```bash
python3 analyze_alerts.py /var/log/snort/alert
```

Optional packet capture for evidence (Wireshark):

```bash
sudo snort -c /etc/snort/snort.conf -i enp0s8 -l /var/log/snort -b
```

## Troubleshooting

| Problem | Fix |
|---|---|
| No alerts at all | Sensor NIC promiscuous mode "Allow All"? Correct interface in `-i`? |
| Rules not loading | Check `include $RULE_PATH/local.rules` and file permissions |
| SYN scan rule never fires | Nmap speed is fine; lower threshold to `count 10` |
| Duplicate/too many alerts | Use `detection_filter` or `threshold` in rules |

## Snort 3 note

If your instructor requires Snort 3, rules syntax is almost identical, but config uses `snort.lua` and `snort -c /usr/local/etc/snort/snort.lua -R local.rules -i enp0s8 -A alert_fast`. HTTP rules use `http_uri` sticky buffers differently (`http_uri; content:"../";`).

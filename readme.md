## SSH Brute Force Detection with Wazuh
# Detecting SSH attacks with Wazuh, from reconnaissance to a correlated brute-force alert.

# Project Overview
This laboratory project demonstrates a full offensive-to-defensive security lifecycle within an isolated virtual network. From a Red Team perspective, network reconnaissance and an automated SSH credential brute-force attack are executed against a Linux server. From a Blue Team (SOC Analyst) perspective, endpoint logs are ingested into a Wazuh SIEM instance to detect, triage, and correlate the intrusion attempt against the MITRE ATT&CK framework.

 # Lab Architecture 

| Role |  Hostname / OS | IP Address | Key Tools |
| --- | --- | --- | --- | 
| Attacker (Red Team ) | Kali Linux | 192.168.56.103 | Nmap, THC-Hydra|
| Target Endpoint | Ubuntu Server (ubuntu-target) | 192.168.56.104 | OpenSSH Server (Port 22), Wazuh Agent (ID: 001) | 
| SIEM Server (Blue Team) | Wazuh Server (wazuh-server) | 192.168.56.105 | Wazuh Manager, Indexer, Threat Hunting Dashboard |

                           NAT                                                                    Host-only
             Internet access only                             Private network between the VMs; all lab traffic

# RECONNAISSANCE
From Kali, the first step was to confirm the target was alive on the network and to see which
services it exposed.
ping -c 4 192.168.56.104
ssh marius@192.168.56.104
EVIDENCE ping to 192.168.56.104: 4 packets transmitted, 4 received, 0% packet loss. ssh returned the
banner Welcome to Ubuntu 26.04.1 LTS and the shell prompt changed to marius@Ubuntu, confirming a
normal login worked before any attack was attempted.

<img width="1573" height="751" alt="ssh-connection-verified" src="https://github.com/user-attachments/assets/28b2ec63-6757-42e9-a3cd-8ef83a62c84c" />


# Deploying the Wazuh agent on the target
In the Wazuh dashboard, I used the Deploy new agent wizard: Linux, package DEB amd64,
manager address 192.168.56.105. The wizard generated the installation commands, which I ran on
the target.
EVIDENCE The agent registered as ubuntu-target, ID 001, IP 192.168.56.104, OS Ubuntu 26.04.1 LTS, agent version 4.14.5, status active.

<img width="1852" height="364" alt="install-wazuh-agent" src="https://github.com/user-attachments/assets/a47249f4-2701-448e-94ec-2087b9f5ba88" />

<img width="1920" height="923" alt="wazuh-agent-ubuntu-target-active" src="https://github.com/user-attachments/assets/5c19f5a4-b1ba-4c2f-904b-717f0e7c4a1c" />


# First failed SSH logins from Kali
From Kali, I tried connecting over SSH with deliberately wrong passwords, to see how the target and Wazuh would react to a failed authentication.
ssh marius@192.168.56.104

<img width="1920" height="922" alt="first-failed-ssh" src="https://github.com/user-attachments/assets/9661121d-d629-4296-98e6-e0f92bd0079a" />

# Checking which machine the attempts actually came from
Before trusting the alerts, I checked the source of the failed logins directly in the alert's raw data.
EVIDENCE data.srcip = 192.168.56.104 and the raw log line read "Failed password for marius from 192.168.56.104 port 51230 ssh2".

#MISTAKE FOUND The source IP was the target itself, not Kali. The terminal running the attempt was still
connected via SSH into the target (prompt marius@Ubuntu), so the "attack" never left the target machine.
Checking the shell prompt and running hostname -I confirmed the mistake: it should read kali@kali and show 192.168.56.103 before any attack command is run.

 # Repeating the test from the correct machine
Back on Kali (prompt kali@kali, hostname -I showing 192.168.56.103), the same failed-login
attempts were repeated.
EVIDENCE Opening the resulting Wazuh alert and checking its fields: data.srcip = 192.168.56.103,
data.dstuser = marius, agent.name = ubuntu-target. The raw log line now read "Failed password for marius from 192.168.56.103 ... ssh2".

<img width="1920" height="922" alt="wazuh-brute_force-kali" src="https://github.com/user-attachments/assets/b4fb341b-cdb3-4f3b-b666-1046a100471c" />

KEY FINDING The failed logins were now correctly attributed to the Kali attacker machine, confirming the lab's
attack path works end-to-end: Kali -> Target -> Wazuh.

## Automating the attack with Hydra
A handful of manually-typed wrong passwords is not an automated attack. To build a realistic,
repeatable brute-force test, I used Hydra with a small password list, the real password included as the last entry.

sudo apt install hydra -y
nano password.txt                   # 5 wrong passwords, then the real one, one per line
hydra -l marius -P                  password.txt ssh://192.168.56.104

<img width="1920" height="407" alt="kali_hydra_ssh-brute-force_success" src="https://github.com/user-attachments/assets/4930ae05-deb8-4f2e-8f28-28c4ec57fa7a" />

# Wazuh's detection of the brute-force attack
Instead of logging each failed attempt separately,
Wazuh correlated the repeated failures from the same source and user, and raised a dedicated alert.

# DETECTION Rule 5763 · Level 10 ·  "sshd: brute force trying to get access to the system. Authentication
failed."
Fired after 8 failed attempts in a short window (rule.frequency: 8). MITRE ATT&CK mapping: T1110, tactic
Credential Access, technique Brute Force.
EVIDENCE Document details for the alert: agent.name = ubuntu-target, agent.ip = 192.168.56.104,
data.srcip = 192.168.56.103 (Kali), data.dstuser = marius, decoder.name = sshd.

<img width="1920" height="923" alt="brute-force-events_details" src="https://github.com/user-attachments/assets/4991eee0-0a4c-42ef-8f7e-1c059b8bafbe" />

<img width="1920" height="923" alt="brute-force_Mitre-T1110" src="https://github.com/user-attachments/assets/39168af0-0e49-46a3-82e9-ce64deb3a600" />


## Detection & SOC Analysis (Wazuh SIEM)
During the attack, the Wazuh Agent installed on ubuntu-target monitored authentication events.

<img width="1920" height="922" alt="eventsWazuh-dashboard" src="https://github.com/user-attachments/assets/745827bc-9b84-4291-985a-ebb9c0805684" />

# Telemetry Field                    Observed Alert Value                                                                         Analytical Significance
Rule ID & Level                     Rule 5763 (Severity Level 10)                                                                 High-severity threshold alert triggered by repeated failures.
Rule Description                    sshd: brute force trying to get access to the system. Authentication failed.                  Confirms automated credential guessing rather than a single typo.
Source & Destination                Src: 192.168.56.103 → Dst: 192.168.56.104 (User: marius)                                      Pinpoints the exact internal attacker IP and targeted account.
MITRE ATT&CK                        Tactic: Credential Access • Technique: Brute Force (T1110)                                    Standardizes incident classification for SOC escalation.

### Recommendations
To mitigate and prevent brute-force attacks against SSH services in a production environment, the following security controls are recommended:
Use strong, unique passwords.
Restrict SSH keys.
Enforce SSH Key-Based Authentication: Disable password logins
Disable Direct Root Login: Prevent remote root logins to minimize privilege escalation exposure by configuring 
Configure Network Access Controls
Limit repeated login attempts
Continuous SIEM Monitoring & Alerting

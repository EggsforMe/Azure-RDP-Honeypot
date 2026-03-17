# Azure RDP Honeypot

A cloud-based honeypot built on Microsoft Azure to observe and log real-world brute force attacks targeting **Remote Desktop Protocol (RDP)** on port 3389.

---

## What Is This?

This project intentionally exposes a Windows virtual machine to the internet to attract real attackers. It then logs and analyzes their behaviour using Azure's built-in monitoring tools.

---

## VM Specifications

| Setting | Details |
|---|---|
| VM Name | vm1 |
| Operating System | Windows Server 2019 Datacenter |
| Size | Standard B2ls v2 (2 vCPUs, 4 GiB RAM) |
| Region | Australia East (Zone 1) |
| Resource Group | cyber-projects |
| Port Exposed | 3389 (RDP) |
| Date Created | March 11, 2026 |

---

## How It Works

```
Attackers (Internet)
       │
       ▼
Azure VM — vm1 (Port 3389 wide open)
       │
       ▼
Data Collection Rule (Windows Security Events)
       │
       ▼
Log Analytics Workspace
       │
       ▼
KQL Queries → Attack Map
```

---

## Results (After ~24 Hours)

| Metric | Result |
|---|---|
| Total failed login attempts | **72,220** |
| Unique attacker IPs | 7 |
| Top attacker | 80.94.95.83 (~7,077 attempts) |
| Most tried usernames | ADMIN, ADMINISTRATOR, USER, SYSTEM |

---

## Sample KQL Queries

**Total failed logins:**
```kql
Event
| where EventID == 4625
| summarize Attempts = count() by Computer
```

**Top attacking IPs:**
```kql
Event
| where EventID == 4625
| extend IpAddress = extract(@'Name="IpAddress">([^<]+)<', 1, EventData)
| where IpAddress != "" and IpAddress != "-"
| summarize Attempts = count() by IpAddress
| order by Attempts desc
```

**Attacks over time:**
```kql
Event
| where EventID == 4625
| summarize Attacks = count() by bin(TimeGenerated, 30min)
| render timechart
```


## Attack Analysis

### Overview
Within minutes of the VM being deployed and exposed to the internet, automated scanners discovered it and began brute force attempts. Over **72,220 failed login attempts** were recorded, demonstrating how quickly exposed systems are found and targeted in the wild.

---

### Attack Timeline

| Time (UTC) | Attempts per 30 min | Observation |
|---|---|---|
| 6:00 – 6:30 AM | ~16,000 | Initial wave begins |
| 6:30 – 7:00 AM | ~25,000 | Peak attack intensity |
| 7:00 – 7:30 AM | ~24,000 | Sustained high volume |
| 7:30 – 8:00 AM | ~5,000 | Sharp drop off |
| 8:00 AM onwards | <500 | Occasional probes only |

<img width="1536" height="497" alt="Screenshot 2026-03-12 101210" src="https://github.com/user-attachments/assets/146c3aa3-a78b-4384-8c10-968dfb0d72cd" />

---

### Key Findings

**1. Automated bots quickly scan open port**

The VM was discovered and attacked within hours of deployment. This shows how constantly the internet is being scanned by automated tools.

**2. The spike pattern is bot behaviour**

The sharp spike followed by a sudden drop is a well-known pattern of automated credential stuffing tools. The bot hammers the target aggressively, then moves on to the next IP once it determines the attack isn't succeeding quickly.

**3. Attackers target high-privilege and neglected accounts**
Usernames like `AZADMIN`, `BACKUP` and `SYSTEM` are being tried because it might grant attackers access to accounts with high privileges or be overlooked by administrators. Service accounts and backup accounts are common targets because they are often set up and forgotten, with weak or unchanged passwords.

**4. Multiple IPs, same subnet**

IPs like `185.156.73.169`, `185.156.73.59` and `185.156.73.24` all share the same subnet, suggesting they are operated by the **same threat actor** using multiple machines to distribute the attack.

| Username | Attempts | Why Attackers Try It |
|---|---|---|
| ADMINISTRATOR | 2,128 | Default Windows admin account |
| ADMIN | 2,126 | Common shorthand |
| USER | 997 | Generic fallback |
| SYSTEM | 950 | Built-in Windows account |
| BACKUP | 953 | Often overlooked service account |
| scan / test | 599 | Commonly left-over dev accounts |

---

## Screenshots

| Description | Preview |
|---|---|
| VM Overview | <img width="940" height="266" alt="image" src="https://github.com/user-attachments/assets/cc37243c-7b21-465e-a627-59372713621b" />|
| NSG Rules | <img width="956" height="370" alt="image" src="https://github.com/user-attachments/assets/a886db45-13b6-4641-b7f9-018cd937b45f" /> |
| KQL Query Results | <img width="447" height="244" alt="Screenshot 2026-03-12 100755" src="https://github.com/user-attachments/assets/90cddf4e-a6c2-42c5-9194-4aecdb653474" />|
| Wordlists and Attempts Chart | <img width="1167" height="266" alt="Screenshot 2026-03-12 130340" src="https://github.com/user-attachments/assets/c93b4b3d-53aa-46db-9d52-b266d9fc7bed" />|

---

## What I Learned

- How to deploy and configure an Azure Virtual Machine
- How Network Security Groups (NSGs) control traffic
- How to collect Windows Security Events using Data Collection Rules
- How to query logs using KQL (Kusto Query Language)
- How real-world brute force attacks behave in the wild

---

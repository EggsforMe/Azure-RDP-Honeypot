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

---

## Screenshots

| Description | Preview |
|---|---|
| VM Overview | <img width="940" height="266" alt="image" src="https://github.com/user-attachments/assets/cc37243c-7b21-465e-a627-59372713621b" />
 |
| NSG Rules | <img width="956" height="370" alt="image" src="https://github.com/user-attachments/assets/a886db45-13b6-4641-b7f9-018cd937b45f" />
 |
| KQL Query Results | <img width="447" height="244" alt="Screenshot 2026-03-12 100755" src="https://github.com/user-attachments/assets/90cddf4e-a6c2-42c5-9194-4aecdb653474" />
|
| Attack Timeline Chart | <img width="1167" height="266" alt="Screenshot 2026-03-12 130340" src="https://github.com/user-attachments/assets/c93b4b3d-53aa-46db-9d52-b266d9fc7bed" />
|

---

## What I Learned

- How to deploy and configure an Azure Virtual Machine
- How Network Security Groups (NSGs) control traffic
- How to collect Windows Security Events using Data Collection Rules
- How to query logs using KQL (Kusto Query Language)
- How real-world brute force attacks behave in the wild

---

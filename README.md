# Azure-RDP-Honeypot
Azure RDP Honeypot
A cloud-based honeypot built on Microsoft Azure to observe and log real-world brute force attacks targeting Remote Desktop Protocol (RDP) on port 3389.

What Is This?
This project intentionally exposes a Windows virtual machine to the internet to attract real attackers. It then logs and analyzes their behaviour using Azure's built-in monitoring tools.

VM Specifications
SettingDetailsVM Namevm1Operating SystemWindows Server 2019 DatacenterSizeStandard B2ls v2 (2 vCPUs, 4 GiB RAM)RegionAustralia East (Zone 1)Resource Groupcyber-projectsPort Exposed3389 (RDP)Date CreatedMarch 11, 2026

How It Works
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

Results (After ~24 Hours)
MetricResultTotal failed login attempts72,220Unique attacker IPs7Top attacker80.94.95.83 (~7,077 attempts)Most tried usernamesADMIN, ADMINISTRATOR, USER, SYSTEM

Sample KQL Queries
Total failed logins:
kqlEvent
| where EventID == 4625
| summarize Attempts = count() by Computer
Top attacking IPs:
kqlEvent
| where EventID == 4625
| extend IpAddress = extract(@'Name="IpAddress">([^<]+)<', 1, EventData)
| where IpAddress != "" and IpAddress != "-"
| summarize Attempts = count() by IpAddress
| order by Attempts desc
Attacks over time:
kqlEvent
| where EventID == 4625
| summarize Attacks = count() by bin(TimeGenerated, 30min)
| render timechart

Screenshots
DescriptionPreviewVM Overview(coming soon)NSG Rules(coming soon)KQL Query Results(coming soon)Attack Timeline Chart(coming soon)

What I Learned

How to deploy and configure an Azure Virtual Machine
How Network Security Groups (NSGs) control traffic
How to collect Windows Security Events using Data Collection Rules
How to query logs using KQL (Kusto Query Language)
How real-world brute force attacks behave in the wild

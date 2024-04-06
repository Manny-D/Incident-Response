# Microsoft Sentinel: Incident Response

![Main](https://github.com/Manny-D/Incident-Response/assets/99146530/173f8cb9-9fda-4417-af46-feef16830221)


## Introduction
In this project, I acted as a Cyber Incident Responder (CIR) in my homelab, Security Operation's Center (SOC), successfully triaging and resolving various security incidents originating from my [Azure HoneyNet project](https://github.com/Manny-D/Azure-Honeynet-SOC). This report delves into 4 specific incidents and summarizes what I've learned, and highlights the effectiveness of the implemented incident response protocols.  

<br>

## Scope
This document will details the following 4 incidents:
- Incident ID: 29 - Brute Force ATTEMPT - Windows
- Incident ID: 10 - Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update)
- Incident ID: 9 - Malware Detected
- Incident ID: 82 - Brute Force ATTEMPT - Linux Syslog

<br>

## Incident ID: 29 - Brute Force ATTEMPT - Windows | Severity: High

<img width="396" alt="Detailed" src="https://github.com/Manny-D/Incident-Response/assets/99146530/05a5e2c4-55c8-4ca3-a6f0-8f00f0b5f690"> <br>
<img width="1366" alt="Image 1" src="https://github.com/Manny-D/Incident-Response/assets/99146530/6e27b0d5-9d30-4c5e-8cfa-23275bc7768e"> <br>

<br>

<b>Incident Summary</b>

On January 6th at 11:25 UTC, Azure Sentinel flagged brute-force attacks (14,000+ attempts) from 14.192.144.254, targeting the "window-xxx" VM, indicating unauthorized access attempts a threat actor(s). 

<br>

<b>Impact Assessment</b>

Due to the high volume of brute force attempts and triggered security alerts, this incident was classified as a potential security breach.

<br>

<b>Detection and Analysis</b>

1. <b>Validate Alert & Isolate System</b>: Confirm the legitimacy of the Azure Sentinel alert and immediately isolate the "window-xxx" VM to prevent further attempts.
2. <b>Change Credentials & Investigate Attack</b>: Reset passwords for all potentially compromised accounts and investigate the attack origin, nature, timeframe, and method used.
3. <b>Review Network & System Logs</b>: Analyze logs from the isolated system and other Network Security Groups (NSGs) for suspicious activity.
4. <b>Privilege & Data Integrity</b>: Assess user accounts with elevated privileges and ensure the integrity of sensitive data on the system.

<br>

<b>Containment, Eradication and Recovery</b>

1. <b>Enforce Network Restrictions</b>: Implement temporary network segmentation and adjust NSG rules to isolate "window-xxx" VM and limit unnecessary traffic.
2. <b>Strengthen Authentication</b>: Reset Credentials & Enable MFA: Enforce strong password policies and reset passwords for affected accounts. Additionally, enable multi-factor authentication (MFA) for all user accounts.
3. <b>Scan for Malware & Monitor System</b>: Conduct Malware Scan & Monitor Activity: Perform a full virus scan on "window-xxx" VM to detect potential malware. Continuously monitor the system for any suspicious activity to ensure its ongoing security.

<br>

## Incident ID: 10 - Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update) | Severity: High <br>
<img width="1367" alt="Image 2" src="https://github.com/Manny-D/Incident-Response/assets/99146530/334a9c0b-9f9a-4493-b336-9133b49fb994"> <br>


<br>

<b>Incident Summary</b>

On January 5th at 11:13 PM UTC, Azure Sentinel flagged a potential privilege escalation. A user account accessed critical Azure Key Vault credentials multiple times. This activity coincides with a high number of password resets and global admin role assignments, requiring further investigation.

<br>

<b>Impact Assessment</b>

Though this scenario was simulated, it highlights potential risks of privilege escalation and unauthorized access to sensitive information.

<br>

<b>Recommendations</b>

1. <b>Investigate User Access</b>: Verify user's account access to Azure Key Vault and other sensitive resources for potential compromise.
2. <b>Strengthen Access Controls</b>: Review and update access control policies to prevent similar incidents.
3. <b>Rotate Credentials</b>: Reset critical credentials and implement frequent rotation to minimize damage from potential breaches.
4. <b>Monitor & Revoke Access (if needed)</b>: Closely monitor user's activity and revoke access to sensitive resources if necessary.

<br>

<b>Classification</b>

This incident aligns with potential NIST 800-61 privilege escalation, requiring investigation due to access to sensitive Azure Key Vault credentials.

<br>

## Incident ID: 9 - Malware Detected | Severity: High

<img width="1305" alt="Image 4" src="https://github.com/Manny-D/Incident-Response/assets/99146530/bcbc03d8-a3ec-408e-82f0-bd2651530d63"> <br>

<br>

<b>Incident Summary</b>

On January 5th at 6:05 PM UTC, Malware was detected on the "window-xxx" VM, potentially compromising system and data confidentiality, integrity, and availability.

<br>

<b>Detection and Analysis</b>:

1. Validate alert to confirm if it's a True Positive.
2. Identify affected user(s) (if any).
3. Notify stakeholders and provide protection guidance.
4. Scan for and remove malware.
5. Isolate workstation if necessary.

<br>

<b>Containment, Eradication and Recovery</b>

1. Isolate infected workstation(s) and potentially impacted system(s).
2. Restore workstation(s) to a clean state (using imaging or clean install).
3. Bolster security to prevent future malware.

<br>

## Incident ID: 82 - Brute Force ATTEMPT - Linux Syslog Severity: Medium <br>

<img width="1367" alt="Image 3" src="https://github.com/Manny-D/Incident-Response/assets/99146530/87cb5e0c-6dd1-455f-bc0a-567fe19e8cce"> <br>

<br>

<b>Incident Summary</b>

Azure Sentinel flagged a brute-force attack on a Linux VM on January 6th at 8:55 PM UTC, from a suspicious IP (61.177.172.160) linked to prior incidents.

<br>

<b>Impact Assessment</b>

The brute force attack targeted a local account on the Linux VM, suggesting an attempt to gain unauthorized access privileges specific to that system.

<br>

<b>Detection and Analysis</b>

1. <b>Validate Alerts & Isolate System</b>: Confirm Azure Sentinel alerts and isolate the affected Linux VM to prevent further compromise.
2. <b>Reset Compromised Account</b>: Reset the password for the targeted local Linux account.
3. <b>Tighten Network Controls</b>: Lockdown Network Security Groups (NSGs) to restrict unauthorized access.
4. <b>Investigate IP Address</b>: Analyze other incidents linked to IP 114.132.168.163 to determine the attack scope.

<br>

<b>Containment, Eradication and Recovery</b>

1. <b>Quarantine & Investigate</b>: Isolate the infected workstation and potentially impacted systems for further analysis.
2. <b>Remediate Workstation</b>: Restore the infected workstation to a confirmed clean state.
3. <b>Review & Strengthen</b>: Analyze logs and security measures to identify vulnerabilities and prevent future incidents.

<br>

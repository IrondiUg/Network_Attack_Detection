# Network Attack Detection & Reporting Using Cowrie Honeypot
## 1. Introduction
This project documents the deployment and use of a Cowrie Honeypot to detect, observe, and log simulated network attacks within a controlled virtual lab environment. The objective was to understand attacker reconnaissance techniques, credential abuse, and post-authentication behavior while ensuring that no real system resources were exposed or compromised.
________________________________________
## 2. Objectives
-	Deploy a functional honeypot environment for attack detection
-	Simulate network reconnaissance and unauthorized access attempts
-	Capture and analyze network traffic generated during attacks
-	Review and interpret honeypot logs as evidence of malicious activity
-	Produce a structured incident report
________________________________________
##  3. Lab Environment
### 3.1 Virtualization Platform
  - Hypervisor: VMware Workstation
### 3.2 Virtual Machines
  -  kali 1 (attacker - 192.168.36.128)
  -  kali 2 (Cowrie Honeypot Server - 192.168.36.130)

Attacker VM	Kali Linux	Performs scanning and attack simulations
Honeypot VM	Kali Linux + Cowrie	Hosts the Cowrie SSH honeypot
________________________________________
## 4. Cowrie Honeypot Overview
Cowrie is a medium-interaction SSH honeypot designed to emulate a vulnerable Linux system. It accepts all usernames and passwords by design, allowing attackers to proceed into a simulated shell environment. All interactions are logged for analysis.
Key features used in this project:
-	Fake SSH service emulation
-	Credential capture
-	Command logging
-	Simulated filesystem
________________________________________
## 5. Installation & Configuration Summary
### 5.1 Cowrie Deployment
-	Cowrie was installed from the official GitHub repository. https://github.com/cowrie/cowrie
-	A Python virtual environment was used to isolate dependencies.
-	Required Python packages were installed using pip.
-	Cowrie services were started using the built-in launcher.
Follow the steps in this video to set up Cowrie honeypot 👉🏾 https://youtu.be/-ufsdzLr5Oc?si=BbEQvEAqsc9KqL3U

### 5.2 SSH Configuration
-	Cowrie was configured to emulate an SSH server on port 2222. A realistic SSH banner was used to mimic a vulnerable OpenSSH version.
-	Root and other common usernames were accepted to simulate misconfiguration.

### 5.3 Filesystem Customization
The fake filesystem presented to attackers was customized to increase realism:
-	Simulated directories such as /root, /etc, and /var
-	Fake sensitive files (e.g., password lists, backup files)
All modifications were made strictly within Cowrie’s simulated filesystem to avoid exposing the real host.
________________________________________
## 6. Attack Simulation
### 6.1 Network Reconnaissance (Nmap)
From the attacker VM, Nmap was used to perform reconnaissance against the Cowrie honeypot in order to identify open ports and exposed services.
The scan revealed an open SSH service on the target system, confirming that the honeypot was reachable and actively listening for connections.
Typical scan types included:
-	Basic TCP scan to identify open ports
-	Service version detection to enumerate SSH details
The discovery of the open SSH port informed the next phase of the attack, which involved direct SSH connection attempts to the honeypot.

![Screenshot 2026-02-03 110743](https://github.com/user-attachments/assets/c73c8e98-3471-400c-a838-b97da4aa7846)

## 6.2 SSH Login Attempts and Access Simulation
After identifying the open SSH port using Nmap, the attacker VM initiated an SSH connection to the Cowrie honeypot using the discovered IP address.
Multiple login attempts were performed using common usernames and passwords. Cowrie accepted the credentials and provided a simulated shell environment, creating the appearance that the attacker machine had successfully gained access to the server.
This access was fully simulated and did not grant real system privileges; however, it allowed Cowrie to log authentication attempts and attacker commands for analysis.

![Screenshot 2026-02-03 122406](https://github.com/user-attachments/assets/048d4774-1693-47ac-893c-0e6c294bb9de)

________________________________________
## 7. Traffic Capture with Wireshark
Wireshark was deployed to monitor network traffic between the attacker VM and the Cowrie honeypot during the reconnaissance and access phases.
While Nmap scans and SSH connections were performed, Wireshark captured:
-	TCP connection attempts to the SSH port
-	SSH handshake and session traffic
-	Evidence of successful connection establishment from the attacker VM
The packet capture confirmed that network-level communication occurred prior to and during the simulated compromise, demonstrating how attackers gain access following service discovery.

![Screenshot 2026-02-03 113646](https://github.com/user-attachments/assets/9c65d7a3-0145-4cbd-9697-42285a348fd9)

The captured traffic served as supporting evidence alongside Cowrie logs, providing visibility at both the network and application layers.
________________________________________
## 8. Log Analysis & Evidence
### 8.1 Cowrie Logs
Cowrie generated detailed logs containing:
-	Source IP addresses
-	Usernames and passwords attempted
-	Timestamps of activity
-	Commands entered by the attacker
Primary log files:
-	cowrie.log

![Screenshot 2026-02-03 123105](https://github.com/user-attachments/assets/eae220d4-79b3-45f0-a4f3-ac920adf8627)

### 8.2 Observed Attacker Behavior
-	Initial reconnaissance using Nmap
-	Attempted SSH authentication
-	Post-login command execution such as directory listing and file access
These behaviors align with common real-world intrusion patterns.
________________________________________
## 9. Findings
-	Cowrie successfully detected and logged all simulated attack activities.
-	The honeypot convincingly emulated a vulnerable SSH server.
-	Attackers were unable to access real system resources.
-	Network and application-layer evidence correlated correctly.
________________________________________
## 10. Conclusion
This project demonstrated the effectiveness of honeypots in detecting and analyzing unauthorized network activity. Cowrie provided valuable insight into attacker techniques without placing real systems at risk. The combination of honeypot logs and network traffic capture offers a strong foundation for incident investigation and security monitoring.
________________________________________
## 11. Disclaimer
All activities were performed in a controlled lab environment for educational purposes only. No real systems or external networks were targeted during this exercise.



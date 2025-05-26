# intern-task1
first task of cybersecurity internship
 Network Reconnaissance & Security Analysis Tool 

A Python-based tool for performing structured network reconnaissance, service enumeration, vulnerability detection (via NVD CVE database), and packet capture analysis. 

This script is ideal for penetration testers, red teamers, and security analysts who need to gather intelligence on a target host in a professional and automated manner. 
📌 Features 

    ✅ TCP SYN Scan (nmap -sS) for stealthy port discovery
    ✅ Service Detection (nmap -sV) to identify running services and versions
    ✅ Real-time CVE lookup using the NVD API 
    ✅ Live packet capture using Scapy 
    ✅ Structured and professional TXT report generation 
    ✅ Auto-generated security recommendations  based on findings
    ✅ Support for both IPv4/IPv6 addresses and domain names 
     

🛠 Requirements 

Before running this script, ensure you have the following installed: 
bash
 
 
1
pip install scapy requests
 
 

Also make sure: 

    nmap is installed and accessible in your system PATH.
    You run the script with sufficient privileges (especially for packet capture).
     

🚀 Usage 

    Clone or save the script locally.
    Run the script:
     

bash
 
 
1
python recon_tool.py
 
 

    Enter a valid domain name or IP address  when prompted.
     

Example: 
 
 
1
Enter domain or IP address: example.com
 
 
📁 Output 

A .txt report will be generated in the current directory with a name like: 
 
 
1
recon_report_example_com.txt
 
 

The report includes: 

    Executive Summary
    Target Information
    Open Ports & Services
    Vulnerability Findings (CVEs)
    Packet Capture Log
    Recommendations
    Timestamps
     

⚙️ How It Works 

    Target Resolution : The input domain/IP is resolved if necessary.
    Nmap Scan : A stealth SYN scan is performed to detect open ports.
    Service Detection : Nmap identifies running services and their versions.
    CVE Lookup : Uses the NIST NVD API to find relevant CVEs.
    Packet Capture : Scapy captures live traffic during scan.
    Report Generation : Full analysis written into a clean text file.
     


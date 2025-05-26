import subprocess
import socket
import datetime
import os
import re
import time
import json
from scapy.all import sniff, IP, TCP, UDP
import requests

# --- GLOBALS ---
USER_AGENT = "ReconTool/1.0"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/v2.0/search "

def resolve_domain(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.error:
        return None

def perform_nmap_scan(ip):
    print(f"[+] Running Nmap scan on {ip}")
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    result = subprocess.run(
        ['nmap', '-sS', '-sV', '-T4', '-Pn', ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode not in (0, 1):  # 1 is for open ports found
        print("[-] Nmap scan failed.")
        print(result.stderr)
        exit(1)
    return result.stdout, timestamp

def parse_nmap_output(scan_output):
    services = []
    lines = scan_output.splitlines()
    for line in lines:
        match = re.match(r'^(\d{1,5})/tcp\s+open\s+(\S+)\s+([\w\.\s\-\/]+)', line)
        if match:
            port, service, version = match.groups()
            version = version.strip()
            services.append((port, service, version))
    return services

def fetch_cves(service_name, version):
    """Query NVD NIST API for real CVEs based on keyword"""
    query = f"{service_name} {version}"
    headers = {"User-Agent": USER_AGENT}
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }
    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params)
        if response.status_code != 200:
            print(f"[-] Failed to query NVD API: {response.status_code}")
            return []

        data = response.json()
        cves = []
        for item in data.get('result', {}).get('CVE_Items', []):
            cve_id = item['cve']['CVE_data_meta']['ID']
            desc = item['cve']['description']['description_data'][0]['value']
            severity = "Unknown"
            if 'baseMetricV3' in item['impact']:
                severity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            elif 'baseMetricV2' in item['impact']:
                severity = item['impact']['baseMetricV2']['severity']
            cves.append((cve_id, severity, desc[:80]))
        return cves
    except Exception as e:
        print(f"[-] Error fetching CVEs: {e}")
        return []

def start_packet_capture(duration=30):
    print(f"\n[+] Starting packet capture for {duration} seconds...")
    packets = []

    def packet_handler(pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            length = len(pkt)
            packets.append((src, dst, proto, length))
            print(f"Captured: {src} → {dst}, Proto={proto}, Size={length}")

    sniff(prn=packet_handler, timeout=duration, store=False)
    print("[+] Packet capture completed.")
    return packets

def generate_report(target, resolved_ip, scan_output, scan_time, services, packets):
    report_time = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    filename = f"recon_report_{target.replace('.', '_')}.txt"

    with open(filename, 'w') as f:
        f.write("="*60 + "\n")
        f.write("         Network Reconnaissance & Security Analysis Report\n")
        f.write("="*60 + "\n\n")

        f.write("Executive Summary:\n")
        f.write("This report includes network scan results, CVE findings, and captured packets.\n\n")

        f.write("Target Information:\n")
        f.write(f"Original Input:      {target}\n")
        f.write(f"Resolved IP Address: {resolved_ip}\n")
        f.write(f"Date of Scan:        {scan_time}\n\n")

        f.write("Scan Details:\n")
        f.write("Scan Type:           TCP SYN + Service Detection\n")
        f.write("Tool Used:           Nmap\n\n")

        f.write("Open Ports & Services:\n")
        f.write("-"*60 + "\n")
        f.write(f"{'Port':<10}{'Service':<15}{'Version'}\n")
        f.write("-"*60 + "\n")
        for port, service, version in services:
            f.write(f"{port:<10}{service:<15}{version}\n")
        f.write("\n")

        f.write("Vulnerability Summary:\n")
        f.write("-"*60 + "\n")
        for port, service, version in services:
            cves = fetch_cves(service, version)
            if cves:
                f.write(f"{service} ({version}):\n")
                for cve_id, severity, desc in cves:
                    f.write(f" - {cve_id} [{severity}]: {desc}\n")
            else:
                f.write(f"{service} ({version}): No known vulnerabilities found.\n")
            f.write("\n")

        f.write("Packet Capture Summary:\n")
        f.write("-"*60 + "\n")
        if packets:
            f.write(f"{'Src':<15} {'Dst':<15} {'Proto':<6} {'Size'}\n")
            for src, dst, proto, size in packets:
                f.write(f"{src:<15} {dst:<15} {proto:<6} {size}\n")
        else:
            f.write("No packets captured.\n")
        f.write("\n")

        f.write("Recommendations:\n")
        f.write("-"*60 + "\n")

        rec_set = set()

        for port, service, version in services:
            s = service.lower()
            v = version.lower()

            if 'http' in s and 'ssl' not in s:
                rec_set.add("- Consider enabling HTTPS for secure communication.")
            if 'ftp' in s:
                rec_set.add("- Replace insecure FTP with SFTP or FTPS.")
            if 'telnet' in s:
                rec_set.add("- Avoid using Telnet. Use SSH instead for secure remote access.")
            if 'ssh' in s:
                rec_set.add("- Restrict SSH access with firewall rules or VPN.")
            if 'smtp' in s or 'imap' in s:
                rec_set.add("- Ensure mail servers enforce authentication and encryption (SSL/TLS).")
            if 'mysql' in s or 'postgres' in s:
                rec_set.add("- Secure database access with strong passwords and IP restrictions.")
            if 'outdated' in v or 'unknown' in v:
                rec_set.add("- Investigate unknown versions and apply updates if necessary.")

        # Universal security best practices
        rec_set.update([
            "- Close unused ports",
            "- Regularly update all services and OS",
            "- Use strong, unique credentials",
            "- Monitor logs for unusual access patterns"
        ])

        for rec in sorted(rec_set):
            f.write(f"{rec}\n")
        f.write("\n")

        f.write("Timestamps:\n")
        f.write(f"- Scan Started:     {scan_time}\n")
        f.write(f"- Report Generated: {report_time}\n")

    return filename

def main():
    print("🔍 Network Reconnaissance & Security Analysis Tool")
    target = input("Enter domain or IP address: ").strip()

    resolved_ip = resolve_domain(target)
    if not resolved_ip:
        print("❌ Could not resolve domain. Exiting.")
        return

    print(f"✅ Resolved IP: {resolved_ip}")
    print("🚀 Running nmap scan...")

    scan_output, timestamp = perform_nmap_scan(resolved_ip)
    services = parse_nmap_output(scan_output)

    print("📡 Capturing network traffic for 30 seconds...")
    packets = start_packet_capture(duration=30)

    print("🛠 Generating report...")
    report_file = generate_report(target, resolved_ip, scan_output, timestamp, services, packets)
    print(f"✅ Report saved as: {report_file}")

if __name__ == "__main__":
    main()

import subprocess import socket import ipaddress import datetime import os import re import requests

USER_AGENT = "ReconTool/1.0" NVD_API_URL = "https://services.nvd.nist.gov/rest/json/v2.0/search"

def get_local_ip(): s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) try: s.connect(("8.8.8.8", 80)) local_ip = s.getsockname()[0] finally: s.close() return local_ip

def get_subnet_cidr(local_ip): try: output = subprocess.check_output(['ip', 'addr'], text=True) for line in output.splitlines(): if local_ip in line: parts = line.strip().split() for part in parts: if "/" in part: return part except Exception as e: print(f"[!] Error getting subnet: {e}") return None

def scan_network(subnet): print(f"[+] Scanning local network: {subnet} using TCP SYN scan and service detection...") timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') try: result = subprocess.run(['nmap', '-sS', '-sV', '-T4', '-Pn', subnet], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) if result.returncode not in (0, 1): print("[-] Nmap scan failed.") print(result.stderr) return None, timestamp return result.stdout, timestamp except Exception as e: print(f"[!] Error running Nmap: {e}") return None, timestamp

def parse_nmap_output(scan_output): services = [] lines = scan_output.splitlines() for line in lines: match = re.match(r'^(\d{1,5})/tcp\s+open\s+(\S+)\s+([\w.\s-/]+)', line) if match: port, service, version = match.groups() services.append((port, service, version.strip())) return services

def fetch_cves(service_name, version): query = f"{service_name} {version}" headers = {"User-Agent": USER_AGENT} params = { "keywordSearch": query, "resultsPerPage": 5 } try: response = requests.get(NVD_API_URL, headers=headers, params=params) if response.status_code != 200: print(f"[-] Failed to query NVD API: {response.status_code}") return []

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

def save_results(scan_output, timestamp): filename = f"wifi_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt" services = parse_nmap_output(scan_output)

with open(filename, 'w') as f:
    f.write("="*60 + "\n")
    f.write("       Wi-Fi LAN Recon Report with CVEs\n")
    f.write("="*60 + "\n")
    f.write(f"Scan Time (UTC): {timestamp}\n\n")
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

print(f"[+] Results saved to: {filename}")

def main(): print("\n🔍 Wi-Fi Network Recon Tool (LAN Scanner + CVE Lookup)") local_ip = get_local_ip() print(f"[+] Your Local IP: {local_ip}")

subnet_cidr = get_subnet_cidr(local_ip)
if not subnet_cidr:
    print("[-] Could not determine subnet. Try manually providing the subnet.")
    return

scan_output, timestamp = scan_network(subnet_cidr)
if scan_output:
    save_results(scan_output, timestamp)

if name == "main": main()


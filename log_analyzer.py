from pyfiglet import Figlet
from termcolor import colored
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv
import google.generativeai as genai
import os, re, sys, requests, json, getpass, datetime

# Read comments carefully, you'll find something funny
load_dotenv()
gemini_api_key = os.environ['GEMINI_API_KEY']
abuse_ip_api_key = os.environ['ABUSE_IP_API_KEY']
virustotal_api_key = os.environ['VIRUSTOTAL_API_KEY']

abuse_ip_url = "https://api.abuseipdb.com/api/v2/check"
virustotal_url = "https://www.virustotal.com/api/v3/ip_addresses/"

f = Figlet(font = "slant")
banner_text = f.renderText("log analyzer")
print(colored(banner_text, color = "blue"))

def parse_file():
    file_path = sys.argv[1]
    if (file_path):
        print(f"\n[+] Parsing log file '{file_path}'...")
    else:
        print(f"\n[ERROR] Log file couldn't find.")
        return
    logs = open(file_path).read().splitlines()
    
    ip_addresses = {}
    total_requests = 0
    status_code_404 = 0
    status_code_200 = 0

    for log in logs:
        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", log)
        method_match = re.search(r'"method":"(.*?)"', log)
        status_match = re.search(r'"status":(\d+)', log)
        user_agent_match = re.search(r'"user_agent":"(.*?)"', log)

        if not ip_match:
            continue

        ip_address = ip_match.group(0)
        method = method_match.group(1) if method_match else None
        status = int(status_match.group(1)) if status_match else None
        user_agent = user_agent_match.group(1) if user_agent_match else None

        if ip_address not in ip_addresses:
            ip_addresses[ip_address] = {
                "methods": set(),
                "statuses": set(),
                "user_agents": set()
            }

        if method:
            ip_addresses[ip_address]["methods"].add(method)
            total_requests += 1
        if status:
            ip_addresses[ip_address]["statuses"].add(status)
            status_code_404 += 1 if status >= 400 else 0
            status_code_200 += 1 if status >= 200 else 0
        if user_agent:
            ip_addresses[ip_address]["user_agents"].add(user_agent)

    print(f"""[+] Parsed total {total_requests} requests.
[+] Unique IPs: {list(ip_addresses.keys())}
[+] Overall 404/200 ratio: {status_code_404}/{status_code_200}""")
    
    return {"ip_addresses": ip_addresses, "total_requests": total_requests, "404/200 ratio": f"{status_code_404}/{status_code_200}"}
        
def check_abuseip(ip):
    if not abuse_ip_api_key:
        print("\n[Error] API Key couldn't found")
        return
    try:
        response = requests.get(abuse_ip_url, headers={'Key': abuse_ip_api_key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10)
        response.raise_for_status()
        result = response.json().get('data', {})
        print(f"score: {result.get('abuseConfidenceScore', 0)} country: {result.get('countryCode', 'N/A')}")
        return f"score: {result.get('abuseConfidenceScore', 0)} country: {result.get('countryCode', 'N/A')}"
    except requests.RequestException: return

def check_virustotal(ip):
    if not virustotal_api_key:
        print("\n[Error] API Key couldn't found")
        return
    try:
        response = requests.get(f"{virustotal_url}{ip}", headers={'x-apikey': virustotal_api_key}, timeout=10)
        response.raise_for_status()
        result = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        print(f"Malicious vendors: {result.get('malicious', 0)}")
        return f"malicious_vendors: {result.get('malicious', 0)}"
    except requests.RequestException: return

def gemini_analysis(prompt):
    genai.configure(api_key = gemini_api_key)
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    response = model.generate_content(prompt)
    return response.text

def main():
    result = parse_file()
    virus_total_result = {}
    abuse_ip_result = {}
    print(f"\n[+] Checking abusedIPDB and VirusTotal...")
    for ip in result["ip_addresses"].keys():
        print(f"\n[+] {ip}: ")
        virus_total_result[ip] = check_virustotal(ip)
        abuse_ip_result[ip] = check_abuseip(ip)

    prompt = (
        f"You have to create a detailed report for a SOC analyst based on log statistics:\n"
        f"- Unique IPs: {list(result['ip_addresses'].keys())}\n"
        f"- Date: {datetime.date.today()}\n"
        f"- Total requests: {result['total_requests']}\n"
        f"- Overall 404/200 ratio: {result['404/200 ratio']}\n"
        f"- Virustotal result: {virus_total_result}\n"
        f"- AbuseIP result: {abuse_ip_result}\n"
        f"Write the report in Markdown format. "
        f"Use '[+]' at the start of each key line."
        f"Headers for report: Executive Summary, Log Statistics, VirusTotal Analysis (list format), AbuseIP result (list format), Threat Assessment, Recommendations, Next Steps"
        # this what you looking for: https://one-more-time.netlify.app/
    )

    gemini_result = gemini_analysis(prompt=prompt)
    print(f"\n{gemini_result}")
    report_path = "reports/soc_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(gemini_result)

    print(f"\n[+] Report saved as {report_path}")

main()
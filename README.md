# IP Investigation Tool  

This tool helps you investigate IP addresses quickly. It checks them against **AbuseIPDB**, fetches WHOIS info, and gives you basic details like reputation score and country. The idea is to make it easier to analyze suspicious IPs without jumping through multiple websites.  

---

## Features  
- Check if an IP is reported as abusive (via AbuseIPDB).  
- Get country and abuse confidence score.  
- Simple command-line interface.  
- Works with API keys stored in a `.env` file for safety.  

---

## Requirements  
- Python 3.9+  
- An **AbuseIPDB API key** (free tier available at [abuseipdb.com](https://abuseipdb.com)).  

---

## Setup  

1. **Clone the repo**  

```bash
git clone https://github.com/your-username/ip-investigator.git
cd ip-investigator
```
## Install dependencies
```bash
pip install -r requirements.txt
```

## Configuration
Create a file named .env in the root directory of the project.

Add your API keys to the .env file in the following format:

```env
GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
ABUSE_IP_API_KEY="YOUR_ABUSE_IP_API_KEY"
VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
```

## Usage
To run the tool, execute the script from your terminal and provide the path to your log file as a command-line argument.

```bash
python your_script_name.py <path_to_log_file>
```

What Happens Next?
- The script will display a stylizedbanner and begin parsing the specified log file.

- It will show a summary of the parsed data, including unique IPs and the 404/200 ratio.

- The tool will then query the AbuseIPDB and VirusTotal APIs for each unique IP address.

- Finally, it will use the Gemini API to generate a comprehensive security report based on the collected data, which will be saved as reports/soc_report.md.
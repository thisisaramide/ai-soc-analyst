import sys
import os
import re
import requests
import base64
import json
from dotenv import load_dotenv  # <--- Loads your hidden keys
from crewai import Agent, Task, Crew, Process, LLM

# --- 1. CONFIGURATION ---
# Load secrets from the .env file
load_dotenv()

SERPER_API_KEY = os.getenv("SERPER_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Set environment variables required by libraries
os.environ["SERPER_API_KEY"] = SERPER_API_KEY
os.environ["OPENAI_API_KEY"] = "NA"

# --- HELPER: SMART CLEANER ---
def smart_extract(text, type_hint=None):
    text = str(text).strip()
    # Handle messy JSON inputs
    if "{" in text and "}" in text:
        try:
            data = json.loads(text)
            return list(data.values())[0]
        except:
            pass
    # Regex Fallback
    if type_hint == "ip":
        match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        if match: return match.group(0)
    return text.replace('"', '').replace("'", "").strip()

# --- 2. RAW PYTHON FUNCTIONS (Running tools directly to prevent AI looping) ---

def run_virustotal(ioc):
    clean_ioc = smart_extract(ioc)
    print(f"   [DEBUG] VT Checking: {clean_ioc}") 
    endpoint = "ip_addresses"
    target_id = clean_ioc

    if re.search(r"(http|https|www)", clean_ioc, re.IGNORECASE):
        endpoint = "urls"
        try: target_id = base64.urlsafe_b64encode(clean_ioc.encode()).decode().strip("=")
        except: return "Error encoding URL"
    elif len(clean_ioc) in [32, 40, 64] and "." not in clean_ioc:
        endpoint = "files"

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{target_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return f"VirusTotal Result: {stats['malicious']} vendors flagged it as MALICIOUS."
        elif response.status_code == 404:
            return "VirusTotal: Not Found in database."
        else:
            return f"VirusTotal Error: {response.status_code}"
    except Exception as e:
        return f"VT Connection Error: {e}"

def run_abuseipdb(ip):
    clean_ip = smart_extract(ip, type_hint="ip")
    # Skip if not an IP
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_ip):
        return "Skipped AbuseIPDB: Invalid IP format."

    print(f"   [DEBUG] AbuseIPDB Checking: {clean_ip}")
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": clean_ip, "maxAgeInDays": "90"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()['data']
            return f"AbuseIPDB Result: Confidence Score {data['abuseConfidenceScore']}% (100% is Severe). Total Reports: {data['totalReports']}."
        else:
            return f"AbuseIPDB Error: {response.status_code}"
    except Exception as e:
        return f"AbuseIPDB Connection Failed: {e}"

def run_google_search(query):
    print(f"   [DEBUG] Google Searching: {query}")
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query})
    headers = {
        'X-API-KEY': SERPER_API_KEY,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 200:
            results = response.json()
            # Extract first 3 organic results
            summary = ""
            if "organic" in results:
                for item in results["organic"][:3]:
                    summary += f"- {item.get('title')}: {item.get('snippet')}\n"
            return summary if summary else "No relevant Google results found."
        else:
            return f"Google Search Error: {response.status_code}"
    except Exception as e:
        return f"Google Connection Failed: {e}"

# --- 3. EXECUTION LOGIC ---
if len(sys.argv) > 1:
    target_ioc = sys.argv[1]
else:
    target_ioc = '185.220.101.46'

print(f"### Investigating: {target_ioc} ###")

# --- PHASE 1: PYTHON GATHERS ALL DATA ---
print("\n🔍 Phase 1: Gathering Intelligence (Python Mode)...")

# 1. Get VirusTotal
vt_result = run_virustotal(target_ioc)
print("   ✅ VirusTotal Data Acquired")

# 2. Get AbuseIPDB
abuse_result = run_abuseipdb(target_ioc)
print("   ✅ AbuseIPDB Data Acquired")

# 3. Get Google Search (Using Requests, NOT Tool)
google_result = run_google_search(f"{target_ioc} reputation malicious")
print("   ✅ Google Search Data Acquired")

# --- PHASE 2: AI WRITER ---
print("\n🤖 Phase 2: AI Analyst Generating Report...")

my_brain = LLM(model="ollama/llama3.2", base_url="http://localhost:11434")

# Note: tools=[] means the Agent CANNOT loop or get confused.
senior_analyst = Agent(
    role='Lead SOC Investigator',
    goal='Write a final security report based on provided data.',
    backstory='You are a professional security analyst. You receive raw data and write a summary. You do not use tools.',
    llm=my_brain,
    tools=[], # <--- CRITICAL: No tools allowed!
    verbose=True
)

investigation_task = Task(
    description=f'''
    You have been provided with the following intelligence on {target_ioc}:
    
    1. VIRUSTOTAL DATA: 
    {vt_result}
    
    2. ABUSEIPDB DATA: 
    {abuse_result}
    
    3. GOOGLE SEARCH CONTEXT: 
    {google_result}
    
    MISSION:
    Write a clear, professional paragraph summarizing these findings. 
    - Start with "The artifact {target_ioc} is..."
    - Explicitly mention the scores.
    - Give a final verdict (Malicious or Safe).
    ''',
    expected_output='A professional text summary.',
    agent=senior_analyst
)

my_crew = Crew(
    agents=[senior_analyst],
    tasks=[investigation_task],
    process=Process.sequential
)

result = my_crew.kickoff()

# --- DISCORD ALERT ---
def send_discord_alert(message):
    msg_text = str(message)
    msg_text = msg_text.replace("```json", "").replace("```", "")
    
    data = {
        "content": "",
        "embeds": [{
            "title": f"🚨 SOC Alert: {target_ioc}",
            "description": msg_text[:4000],
            "color": 16711680
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=data)
        print("\n✅ Discord Alert Sent!")
    except:
        print("\n❌ Discord Failed")

print("\n\n### FINAL REPORT ###")
print(result)
send_discord_alert(result)
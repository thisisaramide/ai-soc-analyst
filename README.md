
#  AI-Powered SOC Analyst

An automated Security Operations Center (SOC) agent that investigates suspicious IPs using CrewAI. It correlates data from **VirusTotal**, **AbuseIPDB**, and **Google Search** to generate incident reports and sends real-time alerts to **Discord**.

##  Features
- **Automated Investigation:** Triggers on simulated SIEM alerts.
- **Multi-Source Intelligence:** Checks malware signatures, abuse confidence scores, and threat intel.
- **AI Analysis:** Uses Llama 3.2 to write human-readable incident reports.
- **Real-Time Alerts:** Sends formatted alerts to Discord.

##  Tech Stack
- **Python** (Core Logic)
- **CrewAI** (Agent Orchestration)
- **Ollama** (Local LLM)
- **Discord Webhooks**

##  Setup
1. Clone the repo.
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with your API keys.
4. Run `python mock_siem.py` to start the watcher.

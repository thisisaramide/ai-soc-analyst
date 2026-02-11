import time
import json
import os
import subprocess
import sys

# The file we will watch for "Alerts"
WATCH_FILE = "alerts.json"

print(f"👀 MOCK SIEM IS WATCHING: {WATCH_FILE}")
print("Go save a new IOC in that file to trigger the AI!\n")

# Create the file if it's missing (Defaulting to 'ioc' now)
if not os.path.exists(WATCH_FILE):
    with open(WATCH_FILE, 'w') as f:
        json.dump({"ioc": "8.8.8.8"}, f)

last_time = 0

while True:
    time.sleep(1) # Relax for 1 second
    
    try:
        # Check if the file changed
        current_time = os.path.getmtime(WATCH_FILE)
        
        if current_time != last_time:
            last_time = current_time
            
            # Read the new IOC (Indicator of Compromise)
            try:
                with open(WATCH_FILE, 'r') as f:
                    data = json.load(f)
                    # --- CHANGE IS HERE: We look for 'ioc' now ---
                    suspicious_ioc = data.get("ioc")
            except json.JSONDecodeError:
                print("Error: JSON format is wrong. Fix the file!")
                continue
            
            if suspicious_ioc:
                print(f"\n🚨 ALERT DETECTED! Artifact: {suspicious_ioc}")
                print(f"🚀 Launching Universal Investigator...")
                
                # Run main.py and pass the IOC
                subprocess.run([sys.executable, "main.py", suspicious_ioc])
                
                print("------------------------------------------------")
                print("✅ Investigation Complete. Watching for next alert...")

    except Exception as e:
        print(f"Error: {e}")
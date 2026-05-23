import json
from collections import defaultdict

COWRIE_LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_INTEL_PATH = "/home/cowrie/soc-pipeline/threat_intel.json"

def generate_daily_report():
    daily_profiles = defaultdict(list)
    
    try:
        with open(COWRIE_LOG_PATH, "r") as file:
            for line in file:
                if not line.strip():
                    continue
                
                event = json.loads(line.strip())
                
                #Build the JSON structure displaying the command, session, and timestamp for that ip
                if event.get("eventid") == "cowrie.command.input":
                    ip = event.get("src_ip")
                    command_entry = {
                        "timestamp": event.get("timestamp"),
                        "session_id": event.get("session"),
                        "command": event.get("input")
                    }
                    
                    if ip and command_entry:
                        daily_profiles[ip].append(command_entry)


        with open(OUTPUT_INTEL_PATH, "w") as outfile:
            json.dump(daily_profiles, outfile, indent=4)
            
        print(f"Daily analysis complete. Results written to {OUTPUT_INTEL_PATH}")
        
    except FileNotFoundError:
        print(f"Log file not found at {COWRIE_LOG_PATH}")

if __name__ == "__main__":
    generate_daily_report()
"""
honeypot_attack_mapper.py
Takes honeypot output (IPs, commands, timestamps, sessions) and maps
each command to a MITRE ATT&CK technique, then produces:
1. a per-IP behavioral profile
2. an aggregate technique-frequency table
3. an ATT&CK Navigator layer (load at https://mitre-attack.github.io/attack-navigator/)
"""

import json
import re
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# 1. TECHNIQUE LOOKUP TABLE
# Each entry: (compiled regex, technique_id, technique_name, tactic)
# Extending this as new commands are observed in the honeypot.
# ---------------------------------------------------------------------------
ATTACK_PATTERNS = [
    (r"TelegramDesktop/tdata", "T1005", "Data from Local System", "Collection"),
    (r"\bps\b.*\bgrep\s+['\"]?\[?[Mm]\]?iner", "T1057", "Process Discovery", "Discovery"),
    (r"\bifconfig\b|\bip\s+(addr|link|route|a|l|neigh)\b", "T1016", "System Network Configuration Discovery", "Discovery"),
    (r"\blocate\s+\w+", "T1083", "File and Directory Discovery", "Discovery"),
    (r"/(dev/tty(GSM|USB-mod)|var/spool/sms|etc/smsd\.conf)", "T1120", "Peripheral Device Discovery", "Discovery"),
    (r"/proc/cpuinfo|\bip\s+cloud\s+print|\buname\b(?!_)(?:\s+-[armnvpso])?", "T1082", "System Information Discovery", "Discovery")
]

# Pre-compile for speed. Do it once to prevent reparsing of regex expressions
_COMPILED = [(re.compile(pat, re.IGNORECASE), tid, name, tactic) for pat, tid, name, tactic in ATTACK_PATTERNS]

def map_command(command: str):
    """Return a list of (technique_id, name, tactic) for everything a command matches."""
    hits = []
    for regex, tid, name, tactic in _COMPILED:
        if regex.search(command):
            hits.append((tid, name, tactic))
    return hits

# ---------------------------------------------------------------------------
# 2. LOADER
# ---------------------------------------------------------------------------
def load_log_file(path: str) -> dict:
    sessions = defaultdict(list)
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line.strip())
                ip = entry.get("ip")
                
                sessions[ip].append({
                    "timestamp": entry.get("timestamp"),
                    "session_id": entry.get("session_id"),
                    "command": entry.get("command")
                })
            except json.JSONDecodeError:
                continue 
                
    return sessions

# ---------------------------------------------------------------------------
# 3. ANALYZE
# ---------------------------------------------------------------------------
def analyze(sessions: dict):
    per_ip = {}             
    technique_meta = {}     
    technique_counts = Counter()  
    
    for ip, events in sessions.items():
        techniques = set()
        for event in events:
            cmd = event.get("command", "")
            
            if not cmd or ":" in cmd:
                continue
                
            for tid, name, tactic in map_command(cmd):
                techniques.add(tid)
                technique_meta[tid] = (name, tactic)
                technique_counts[tid] += 1
                
        per_ip[ip] = sorted(techniques)
        
    return per_ip, technique_meta, technique_counts

# ---------------------------------------------------------------------------
# 4. ATT&CK NAVIGATOR LAYER
# ---------------------------------------------------------------------------
def build_navigator_layer(technique_counts: Counter, technique_meta: dict) -> dict:
    if technique_counts:
        max_count = max(technique_counts.values())
    else:
        max_count = 1
    
    techniques = []
    for tid, count in technique_counts.items():
        techniques.append({
            "techniqueID": tid,
            "score": count,
            "comment": f"Observed {count}x against honeypot ({technique_meta[tid][0]})",
        })
        
    return {
        "name": "Honeypot Observed TTPs",
        "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "19"},
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK techniques observed from live honeypot capture.",
        "gradient": {"colors": ["#ffe6e6", "#ff0000"], "minValue": 0, "maxValue": max_count},
        "techniques": techniques,
    }

def main():
    infile = sys.argv[1] if len(sys.argv) > 1 else r"C:\Documents\Cowrie-Honeypot\daily-output.json"
    
    try:
        sessions = load_log_file(infile)
        per_ip, meta, counts = analyze(sessions)
        
        print("=== Per-attacker ATT&CK profile ===")
        for ip, techniques in per_ip.items():
            labeled = [f"{t} ({meta[t][0]})" for t in techniques]
            print(f"{ip}: {', '.join(labeled) if labeled else 'no mapped techniques'}")
            
        print("\n=== Aggregate technique frequency ===")
        for tid, count in counts.most_common():
            print(f"{count:>4}x {tid} {meta[tid][0]} [{meta[tid][1]}]")
            
        layer = build_navigator_layer(counts, meta)
        with open("navigator_layer.json", "w") as f:
            json.dump(layer, f, indent=2)
        print("\nWrote navigator_layer.json -> load at https://mitre-attack.github.io/attack-navigator/")
        
    except FileNotFoundError:
        print(f"Error: Target file not found at: {infile}")

if __name__ == "__main__":
    main()

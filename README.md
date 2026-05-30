# Honeypot Threat-Intelligence Pipeline

A small toolchain that turns a live SSH/Telnet honeypot into structured threat
intelligence. It captures real attacker sessions, maps the commands they run to
[MITRE ATT&CK](https://attack.mitre.org/) techniques, and produces per-attacker
behavioral profiles plus an ATT&CK Navigator layer for visualization.

The data is not synthetic, it comes from a personally deployed [Cowrie](https://github.com/cowrie/cowrie)
honeypot via AWS EC2 exposed to the internet, capturing whatever real adversaries type after
they gain a shell.

## What it does

```
   Internet attackers
          │  (SSH / Telnet brute force, then shell commands)
          ▼
   ┌──────────────────┐
   │  Cowrie honeypot │   Logs every session + command as JSON
   │  (Linux host)    │
   └────────┬─────────┘
            │  cowrie-capture.py   (runs nightly on the honeypot host)
            │  → extracts command-input events from the rotated log
            │  → flattens to one JSON object per command (ip, ts, session, command)
            ▼
   daily-output.json    ── transferred to analysis workstation ──┐
                                                                  ▼
                                              honeypot_attacker_mapper.py
                                              → regex-matches each command to an
                                                ATT&CK technique
                                              → builds: per-IP technique profile,
                                                aggregate frequency table,
                                                ATT&CK Navigator layer
                                                                  │
                                                                  ▼
                                                      navigator_layer.json
                                          (load at the ATT&CK Navigator to visualize)
```

## Components

### `cowrie-capture.py` (runs on the honeypot host)
Reads the previous day's rotated Cowrie log, extracts `cowrie.command.input`
events, and appends each as a flat JSON record (`ip`, `timestamp`,
`session_id`, `command`) to a daily output file. Intended to run on a nightly
cron job so the intel file grows continuously.

### `honeypot_attacker_mapper.py` (runs on the analysis workstation)
Loads the captured commands and:
- maps each command to ATT&CK techniques using a table of compiled regex
  patterns (pre-compiled once for speed),
- builds a per-attacker (per-IP) profile of the techniques they used,
- produces an aggregate technique-frequency table,
- emits an ATT&CK Navigator layer (`navigator_layer.json`) scored by frequency.

### `pse.py` — password strength evaluator (standalone utility)
Scores a password on length and entropy, then checks it against the
[Have I Been Pwned](https://haveibeenpwned.com/) breach corpus using the
**k-anonymity** range API — only the first 5 characters of the SHA-1 hash leave
the machine, so the password itself is never sent. Falls back to a local
wordlist check if the API is unreachable.

## Usage

**On the honeypot host (nightly):**
```bash
python3 cowrie-capture.py
# Appends yesterday's captured commands to the daily output file.
```
Paths are set at the top of the script (`COWRIE_LOG_PATH`, `OUTPUT_INTEL_PATH`).

**Transfer** the resulting `daily-output.json` to your analysis machine
(e.g. `scp`), then:

**On the analysis workstation:**
```bash
python3 honeypot_attacker_mapper.py daily-output.json
```
Prints the per-attacker profile and aggregate frequency table to the console,
and writes `navigator_layer.json`. Load that file at the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see a
heatmap of observed adversary techniques.

**Password evaluator (standalone):**
```bash
python3 pse.py
# Prompts for a password; prints a strength/risk score, hashes,
# and HIBP breach status.
```

## Sample output

```
=== Per-attacker ATT&CK profile ===
185.x.x.x: T1082 (System Information Discovery), T1016 (System Network Configuration Discovery)
45.x.x.x:  T1057 (Process Discovery)

=== Aggregate technique frequency ===
  12x T1082 System Information Discovery [Discovery]
   8x T1016 System Network Configuration Discovery [Discovery]
   3x T1057 Process Discovery [Discovery]

Wrote navigator_layer.json -> load at https://mitre-attack.github.io/attack-navigator/
```

## Extending the technique mappings

New attacker commands are observed regularly. To map a newly seen command,
add a row to the `ATTACK_PATTERNS` table in `honeypot_attacker_mapper.py`:

```python
(r"regex for the command", "T1234", "Technique Name", "Tactic")
```

The table is intentionally simple to grow as the honeypot captures new behavior.

## Notes & limitations

- **Regex mapping is heuristic.** A command is matched to a technique by pattern,
  which can miss obfuscated commands or mis-map ambiguous ones. The mapping table
  is a living list, not exhaustive coverage of ATT&CK.
- **The pipeline has a manual transfer step** between the honeypot host and the
  analysis workstation. Automating that (scp on a schedule, or running both
  stages on one host) is a natural next improvement.
- **The honeypot is a live, internet-exposed system.** It is isolated from
  anything sensitive; honeypots attract real attacks and should never share a
  host with production services.

## Why this exists

Built to get hands-on with the full defensive loop: stand up a honeypot, collect
real adversary activity, and turn raw logs into structured, visualized threat
intelligence in the same vocabulary (MITRE ATT&CK) that SOC and detection teams
use.

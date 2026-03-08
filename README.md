
# SOAR Threat Intelligence Automation Lab

A home lab project that builds a lightweight SOAR (Security Orchestration, Automation, and Response) pipeline from scratch using Python. The script ingests a list of Indicators of Compromise (IOCs), enriches them against open-source threat intelligence APIs, scores them by confidence level, and outputs structured results for analyst review all automated via Windows Task Scheduler.

---

## Skills Demonstrated

- Python scripting for security automation
- REST API integration (VirusTotal, AbuseIPDB)
- IOC classification and normalization (IP, domain, URL, hash)
- Threat enrichment and confidence scoring
- Deduplication logic
- Structured output generation (CSV blocklist, Markdown intel brief, audit log)
- Environment variable management with `.env`
- Windows Task Scheduler for automated execution
- Error handling and resilient pipeline design

---

## Tools & Technologies

| Tool / Service | Purpose |
|---|---|
| Python 3 | Core scripting language |
| VirusTotal API | Domain, URL, and hash enrichment |
| AbuseIPDB API | IP reputation and abuse confidence scoring |
| python-dotenv | Secure API key management |
| VMware Workstation | Virtualized lab environment |
| Windows Task Scheduler | Automated scheduled execution |
| PowerShell | Script execution and environment navigation |

---

## Architecture

```
Iocs_seed.txt
      |
      v
 read_seed_iocs()        -- reads raw IOC strings from file
      |
      v
 classify_and_normalize() -- detects type: ip | domain | url | hash | unknown
      |
      v
 filter unknowns
      |
      v
 dedupe_iocs()           -- removes duplicates by (type, normalized) composite key
      |
      v
 enrichment loop
   |-- IP      --> AbuseIPDB API
   |-- domain  --> VirusTotal API
   |-- URL     --> VirusTotal API (base64 encoded)
   |-- hash    --> VirusTotal API (/files/ endpoint)
      |
      v
 score_indicator()       -- malicious x20, suspicious x10, abuse confidence added
      |
      v
 confidence buckets: HIGH (>=60) | MED (>=20) | LOW (<20)
      |
      v
 +-----------------+------------------+----------+
 |                 |                  |          |
 blocklist.csv   intel_brief.md    run.log    (stdout)
 (full results)  (summary view)   (audit trail)
```

---

## Lab Setup

### Step 1 — Create a shared folder (Doesn't actually have to be a shared folder you can do this entire lab on one vm) 

However if you do opt to go shared folder make sure you make it visible from your host to vm. 

 In VMware Workstation go to:

```
VM → Settings → Options → Shared Folders → Always enabled
```

Add your designated folder and enable it. This makes it accessible inside the VM at:

```
\\vmware-host\Shared Folders\SOAR_output
```
---

### Step 2 — Verify host/VM visibility  
*Optional*

Create a test script inside the VM that writes to the shared folder and confirm it appears on the host / vice versa. This validates that your pipeline output will be readable from both environments.

<img width="815" height="452" alt="image" src="https://github.com/user-attachments/assets/1d752872-f24d-49fd-99b2-457a7b35599a" />

---

### Step 3 — Get API keys

Register for free accounts at:

- [VirusTotal](https://www.virustotal.com) — provides domain, URL, and hash reputation data
- [AbuseIPDB](https://www.abuseipdb.com) — provides IP abuse confidence scores and community reports

---

### Step 4 — Create your `.env` file

Inside your shared folder create a file named `.env` containing:

```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

> **Note:** Windows will silently add `.txt` to the filename. Use PowerShell to verify the actual filename with `dir -Force` and rename if needed.
---

### Step 5 — Create your IOC seed file

Create `Iocs_seed.txt` in the shared folder. Add one indicator per line.  

*Note that these are real malicious ips and domains please handle with caution*

```
# known malicious IPs
177.52.87.237
172.184.139.225

# domains
google.com
codeproofs[.]com
verify-lastpass[.]com
google.com          # duplicate -- will be deduplicated automatically
```

<img width="565" height="500" alt="image" src="https://github.com/user-attachments/assets/1f50cae0-3eac-4197-b666-966a0ac5c27a" />

---

### Step 6 — Run the script

Open PowerShell, navigate to your shared folder, and run:

```powershell
cd "\\vmware-host\Shared Folders\SOAR_output"
python soar_script.py
```

Three output files are created automatically:

```
blocklist.csv            -- full enriched IOC results
intel_brief_<date>.md    -- confidence summary for analysts
run.log                  -- timestamped audit trail of the entire run
```

<img width="689" height="503" alt="image" src="https://github.com/user-attachments/assets/7326ead2-3986-4107-a026-cfbb3fa34663" /> 
<img width="744" height="508" alt="image" src="https://github.com/user-attachments/assets/1c59e097-e461-4c03-aa33-307692451b2d" />


---

### Step 7 — Automate with Task Scheduler

Open Windows Task Scheduler and create a basic task:

```
Name:      SOAR Intel Run
Trigger:   Daily 
Action:    Start a program
Program:   script
Arguments: "\\vmware-host\Shared Folders\SOAR_output\soar_script.py"
```

The script will now run automatically on schedule without manual intervention.

<img width="727" height="523" alt="image" src="https://github.com/user-attachments/assets/19a11eb2-b831-410c-9260-c88b31a5fbf7" />
<img width="1049" height="492" alt="image" src="https://github.com/user-attachments/assets/3f6da7f0-d882-4258-9260-26c668e8f9df" />

---

## Sample Output
*if everything goes right*
### blocklist.csv

<img width="1589" height="828" alt="image" src="https://github.com/user-attachments/assets/7fbc6969-506d-4ae2-b97c-28a106053063" />

### intel brief md 

<img width="954" height="592" alt="image" src="https://github.com/user-attachments/assets/c7fa77f8-4c5f-4f86-87ca-0b9c7b3d79d8" />


## Key Findings

Running the script against a small test seed file produced real threat intelligence results:

**`verify-lastpass[.]com` — Score: 300 / HIGH**
Flagged as malicious by 14 VirusTotal engines with 2 additional suspicious detections. This is a known phishing domain impersonating the LastPass password manager — a real-world credential harvesting attack vector.

**`177.52.87.237` — Score: 100 / HIGH**
AbuseIPDB confidence score of 100 with 577 community abuse reports. This IP has been reported as malicious 577 times. Any traffic to or from this address warrants immediate investigation.

**`codeproofs[.]com` — Score: 90 / HIGH**
Flagged by 4 VT engines as malicious with 1 additional suspicious hit.

**`google.com` — Score: 0 / LOW**
No signals returned — expected behavior for a known benign domain. Confirms the scoring engine correctly handles clean indicators without false positives.

---

## Challenges & Lessons Learned

**VMware network isolation**
The VM's network adapter was not configured for outbound internet access. The script's error handling caught every `ConnectionError` gracefully and continued processing rather than crashing — validating the resilience of the `try/except` design. 

<img width="1568" height="644" alt="image" src="https://github.com/user-attachments/assets/da8713dd-7f5b-4405-81ac-04606965eeaf" />


**Z: drive not mapped in PowerShell**
 Script wasn't working in the beginning because powershell couldn't find the Z: drive. To solve this I updated the paths at the top of the file to accurately point to our folder in a way that powershell could find it.

<img width="838" height="726" alt="image" src="https://github.com/user-attachments/assets/22ec49cf-d175-4168-a605-8c8679fad479" />

**Windows hiding file extensions**
Windows silently added `.txt` to the `.env` file making it `.env.txt`. The script couldn't locate the file until the extension was corrected via PowerShell rename. Lesson: always verify actual filenames with `dir -Force` to avoid a minor headache. 


---

## Script Structure

```
soar_script.py
│
├── Constants          OUT_DIR, SEED_FILE, ENV_FILE, timeouts
│
├── Data Models        IOC, Enrichment, ResultRow (dataclasses)
│
├── Utilities          now_utc_iso(), load_keys(), read_seed_iocs(), log_line()
│
├── Classifiers        is_ip(), is_url(), is_hash()
│                      normalize_domain(), normalize_url()
│                      classify_and_normalize(), dedupe_ioc()
│
├── API Headers        vt_headers(), abuse_headers()
│
├── API Lookups        vt_lookup_domain(), vt_lookup_url(),
│                      vt_lookup_hash(), abuse_lookup_ip()
│
├── Scoring            score_indicator()
│
└── main()             Orchestrates the full pipeline end to end
```

---

## Future Improvements
This lab can further be enhanced to look like an actual SOC workflow, a few key changes that come to mind are:

- **Live threat feed integration** — replace the static seed file with an AlienVault OTX or Abuse.ch feed pulled automatically each run
- **SIEM integration** — import `blocklist.csv` into Splunk or Elastic and write detection rules that fire when live traffic matches a HIGH confidence IOC
- **Email alerting** — send an automated summary email when HIGH confidence IOCs are detected

---



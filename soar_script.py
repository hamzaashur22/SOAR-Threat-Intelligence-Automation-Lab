import csv
import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv



OUT_DIR   = Path(r"\\vmware-host\Shared Folders\SOAR_output")
SEED_FILE = Path(r"\\vmware-host\Shared Folders\SOAR_output\Iocs_seed.txt")
ENV_FILE  = Path(r"\\vmware-host\Shared Folders\SOAR_output\.env")

REQUEST_TIMEOUT = 20
USER_AGENT = "SOAR-Lab/1.0"

# --- DATA MODEL ---
@dataclass
class IOC:
    raw: str
    normalized: str
    ioc_type: str  # ip | domain | url | hash | unknown

@dataclass
class Enrichment:
    vt: Optional[Dict] = None
    abuseipdb: Optional[Dict] = None

@dataclass
class ResultRow:
    indicator: str
    ioc_type: str
    score: int
    confidence: str  # HIGH/MED/LOW
    reason: str
    vt_link: str
    abuseipdb_link: str
    source: str
    date_added_utc: str



def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def load_keys() -> Tuple[str, str]:
    load_dotenv(ENV_FILE)
    vt = os.getenv("VT_API_KEY", "").strip()
    ab = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not vt or not ab:
        raise RuntimeError("Missing VT_API_KEY or ABUSEIPDB_API_KEY in .env")
    return vt, ab

def read_seed_iocs(path: Path) -> List[str]:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines
def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
def is_url(s: str) -> bool:
    return bool(re.match(r"^https?://", s, re.IGNORECASE))

def is_hash(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", s))


def normalize_domain(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^(\*\.)", "", s)
    s = s.strip(".")
    return s

def normalize_url(s: str) -> str:
    return s.strip()


def classify_and_normalize(raw: str) -> IOC:
    r = raw.strip()
    if is_ip(r):
        return IOC(raw=r, normalized=r, ioc_type="ip")
    if is_url(r):
        return IOC(raw=r, normalized=normalize_url(r), ioc_type="url")
    if is_hash(r):
        return IOC(raw=r, normalized=r.lower(), ioc_type="hash")
    d = normalize_domain(r)
    if "." in d and " " not in d:
        return IOC(raw=r, normalized=d, ioc_type="domain")
    return IOC(raw=r, normalized=r, ioc_type="unknown")

def dedupe_ioc(iocs: List[IOC]) -> List[IOC]:
    seen = set()
    out = []
    for i in iocs:
        key = (i.ioc_type, i.normalized)
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out
def log_line(log_path: Path, msg: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8") if not log_path.exists() else None
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"[{now_utc_iso()}] {msg}\n")

def vt_headers(vt_key: str) -> Dict[str, str]:
    return {"x-apikey": vt_key, "User-Agent": USER_AGENT}
def abuse_headers(abuse_key: str) -> Dict[str, str]:
    return {"Key": abuse_key, "Accept": "application/json","User-Agent": USER_AGENT}

def vt_lookup_domain(vt_key: str, domain: str) -> Dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    r = requests.get(url, headers=vt_headers(vt_key), timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def vt_lookup_url(vt_key: str, url_value: str) -> Dict:
    import base64
    url_id = base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8").strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    r = requests.get(url, headers=vt_headers(vt_key), timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def vt_lookup_hash(vt_key: str, hash: str) -> Dict:
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    r = requests.get(url, headers=vt_headers(vt_key), timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def abuse_lookup_ip(abuse_key: str, ip: str) -> Dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    r = requests.get(url, headers=abuse_headers(abuse_key), params=params, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def score_indicator(ioc: IOC, enr: Enrichment) -> Tuple[int, str,str,str,str]:
    score = 0
    reasons= []
    vt_link = ""
    abuse_link = ""

    if enr.vt:
        try:
            data = enr.vt.get("data",{})
            attr = data.get("attributes",{})
            stats = attr.get("last_analysis_stats",{})
            malicious = int(stats.get("malicious",0))
            suspicious = int(stats.get("suspicious",0))
            score += malicious * 20
            score += suspicious * 10
            if malicious > 0: reasons.append(f"VT malicious={malicious}")
            if suspicious > 0 : reasons.append(f"VT suspicious={suspicious}")

            if ioc.ioc_type == "domain":
                vt_link = f"https://www.virustotal.com/gui/domain/{ioc.normalized}"
            elif ioc.ioc_type == "url":
                vt_link = f"https://www.virustotal.com/gui/url/{ioc.normalized}"
            elif ioc.ioc_type == "hash":
                vt_link = f"https://www.virustotal.com/gui/file/{ioc.normalized}"
        except Exception:
            reasons.append("vt parse error")

    if enr.abuseipdb and ioc.ioc_type == "ip":
        try:
            data = enr.abuseipdb.get("data", {})
            conf = int(data.get("abuseConfidenceScore", 0))
            reports = int(data.get("totalReports", 0))
            score += conf
            if conf >= 50:    reasons.append(f"AbuseIPDB confidence={conf}")
            if reports > 0:   reasons.append(f"AbuseIPDB reports={reports}")
            abuse_link = f"https://www.abuseipdb.com/check/{ioc.normalized}"
        except Exception:
            reasons.append("AbuseIPDB parse error")

    if score >= 60:
        confidence = "HIGH"
    elif score >= 20:
        confidence = "MED"
    else:
        confidence = "LOW"

    reason = "; ".join(reasons) if reasons else "No strong signals"
    return score, confidence, reason, vt_link, abuse_link

def main() -> None:
    vt_key, abuse_key = load_keys()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    log_path = OUT_DIR / "run.log"
    log_line(log_path, "Starting Soar intel run")

    raw_list = read_seed_iocs(SEED_FILE)
    iocs = [classify_and_normalize(x) for x in raw_list]
    iocs = [i for i in iocs if i.ioc_type != "unknown"]
    iocs = dedupe_ioc(iocs)

    results : List[ResultRow] = []
    brief_lines: List[str] = []



    for ioc in iocs:
        enr = Enrichment()
        try:
            if ioc.ioc_type == "ip":
                enr.abuseipdb = abuse_lookup_ip(abuse_key, ioc.normalized)
            elif ioc.ioc_type == "domain":
                enr.vt = vt_lookup_domain(vt_key, ioc.normalized)
            elif ioc.ioc_type == "url":
                enr.vt = vt_lookup_url(vt_key, ioc.normalized)
            elif ioc.ioc_type == "hash":
                enr.vt = vt_lookup_hash(vt_key, ioc.normalized)

            score, conf, reason, vt_link, abuse_link = score_indicator(ioc, enr)

            row = ResultRow(
                indicator=ioc.normalized,
                ioc_type=ioc.ioc_type,
                score=score,
                confidence=conf,
                reason=reason,
                vt_link=vt_link,
                abuseipdb_link=abuse_link,
                source="seed_file",
                date_added_utc=now_utc_iso(),
            )
            results.append(row)
            log_line(log_path, f"Added {ioc.ioc_type}: {ioc.normalized} -> score={score} conf={conf}")

        except requests.HTTPError as e:
            log_line(log_path, f"HTTPError: on {ioc.normalized}: {e}")
        except Exception as e:
            log_line(log_path, f"Error on {ioc.normalized}: {repr(e)}")

    blocklist_path = OUT_DIR / "blocklist.csv"

    with blocklist_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["indicator","ioc_type","score","confidence","reason","vt_link","abuseipdb_link","source","date_added_utc"])
        for r in results:
            writer.writerow([r.indicator, r.ioc_type, r.score, r.confidence,
                             r.reason, r.vt_link, r.abuseipdb_link, r.source, r.date_added_utc])

    brief_lines.append(" ## summary by confidence")
    def count_conf(c: str) -> int:
        return sum(1 for r in results if r.confidence == c)

    brief_lines.append(f"- HIGH: {count_conf('HIGH')}")
    brief_lines.append(f"- MED: {count_conf('MED')}")
    brief_lines.append(f"- LOW: {count_conf('LOW')}")

    brief_name = f"intel_brief_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    brief_path = OUT_DIR/ brief_name
    brief_path.write_text("\n".join(brief_lines) + "\n", encoding="utf-8")

    log_line(log_path, f"wrote: {blocklist_path}")
    log_line(log_path, f"Wrote: {brief_path}")
    log_line(log_path, "completed SOAR Intel run")

if __name__ == "__main__":
    main()

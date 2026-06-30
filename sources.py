"""Free, real-time-ish public threat feed pollers for the standalone attack map.

Each source is a small fetch function returning a list of RAW event dicts:

    {"ip": "1.2.3.4",        # OR "host": "evil.example" (urlhaus) — app resolves
     "type": "intrusion",    # maps to a colour in the front-end TYPES table
     "source": "feodo",      # feed name (shown in the By-Source panel)
     "label": "Dridex",      # free-text (malware family / threat / note)
     "country": "RU",        # OPTIONAL iso2 or name; geo.locate prefers it
     "weight": 1.0}          # 0..1 confidence -> arc prominence + impact ping

Sources are deliberately feeds-only (no honeypot wiring) and free:
  feodo      abuse.ch Feodo Tracker  active botnet C2 IPs      (no auth, JSON)
  threatfox  abuse.ch ThreatFox      recent malware IOC IPs    (free Auth-Key)
  urlhaus    abuse.ch URLhaus        live malware-hosting URLs (no auth, CSV)
  dshield    SANS ISC / DShield      top attacking source IPs  (no auth, JSON*)
  blocklist  blocklist.de            reported attacker IPs      (no auth, text)
  cins       CINS Army (cinsscore)   bad-guy IPs                (no auth, text)

* DShield requires a contact email in the User-Agent — set CONTACT_EMAIL.

Every fetch is wrapped: any network/parse error returns [] (a dead feed never
takes the map down). Per-feed poll intervals live in the SOURCES registry.
"""
import csv
import io
import ipaddress
import json
import os
import urllib.request

CONTACT = os.getenv("CONTACT_EMAIL", "admin@example.com")
UA = f"socmap/1.0 (+{CONTACT})"
TIMEOUT = float(os.getenv("FEED_TIMEOUT", "25"))

# colour-bucket per feed (front-end TYPES keys: ddos ransomware malware
# bruteforce webattack intrusion recon other)


def _req(url, headers=None, data=None, method=None):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h, data=data, method=method)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def _text(url, headers=None):
    return _req(url, headers).decode("utf-8", "replace")


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _iter_text_ips(blob):
    """Yield every IP from a plaintext list, skipping # comments / blanks."""
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split()[0].split("/")[0]   # tolerate CIDR / trailing cols
        if _is_ip(tok):
            yield tok


# --------------------------------------------------------------------------- #
# abuse.ch Feodo Tracker — active botnet C2 servers (IP + malware + country)
# --------------------------------------------------------------------------- #
def fetch_feodo():
    try:
        rows = json.loads(_text(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    except Exception:
        return []
    out = []
    for r in rows or []:
        ip = r.get("ip_address")
        if not ip or not _is_ip(ip):
            continue
        out.append({"ip": ip, "type": "intrusion", "source": "feodo",
                    "label": r.get("malware") or "botnet C2",
                    "country": r.get("country"), "weight": 1.0})
    return out


# --------------------------------------------------------------------------- #
# abuse.ch ThreatFox — recent malware IOCs (needs free Auth-Key)
# --------------------------------------------------------------------------- #
def fetch_threatfox():
    key = os.getenv("THREATFOX_KEY", "").strip()
    if not key:
        return []   # silently skipped until a key is supplied
    try:
        body = json.dumps({"query": "get_iocs", "days": 1}).encode()
        raw = _req("https://threatfox-api.abuse.ch/api/v1/",
                   headers={"Auth-Key": key, "Content-Type": "application/json"},
                   data=body, method="POST")
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return []
    out = []
    for r in (data.get("data") or []):
        if r.get("ioc_type") not in ("ip:port", "ip"):
            continue
        ip = (r.get("ioc") or "").split(":")[0]
        if not _is_ip(ip):
            continue
        out.append({"ip": ip, "type": "malware", "source": "threatfox",
                    "label": r.get("malware_printable") or "malware IOC",
                    "country": None, "weight": 1.0})
    return out


# --------------------------------------------------------------------------- #
# abuse.ch URLhaus — live malware-distribution URLs (no IP; host resolved by app)
# --------------------------------------------------------------------------- #
def fetch_urlhaus():
    try:
        blob = _text("https://urlhaus.abuse.ch/downloads/csv_online/")
    except Exception:
        return []
    # The whole header (banner AND the column-name row) is '#'-commented, so
    # drop every '#' line and feed explicit fieldnames to DictReader.
    cols = ["id", "dateadded", "url", "url_status", "last_online", "threat",
            "tags", "urlhaus_link", "reporter"]
    body = "\n".join(ln for ln in blob.splitlines()
                     if ln and not ln.startswith("#"))
    out = []
    try:
        for r in csv.DictReader(io.StringIO(body), fieldnames=cols):
            url = (r.get("url") or "").strip()
            if "://" not in url:
                continue
            host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
            if not host:
                continue
            ev = {"type": "malware", "source": "urlhaus",
                  "label": (r.get("threat") or "malware URL").replace("_", " "),
                  "country": None, "weight": 0.9}
            if _is_ip(host):
                ev["ip"] = host
            else:
                ev["host"] = host
            out.append(ev)
    except Exception:
        return []
    return out


# --------------------------------------------------------------------------- #
# SANS ISC / DShield — top attacking source IPs (no auth; UA email required)
# --------------------------------------------------------------------------- #
def fetch_dshield():
    try:
        data = json.loads(_text(
            "https://isc.sans.edu/api/topips/records/0/150?json"))
    except Exception:
        return []
    rows = data if isinstance(data, list) else data.get("topips", [])
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        ip = r.get("ipaddr") or r.get("source") or r.get("ip")
        if not ip or not _is_ip(ip):
            continue
        out.append({"ip": ip, "type": "recon", "source": "dshield",
                    "label": "top attacker", "country": None, "weight": 0.7})
    return out


# --------------------------------------------------------------------------- #
# blocklist.de — IPs reported for ssh/mail/web brute-force & attacks
# --------------------------------------------------------------------------- #
def fetch_blocklist():
    try:
        blob = _text("https://lists.blocklist.de/lists/all.txt")
    except Exception:
        return []
    return [{"ip": ip, "type": "bruteforce", "source": "blocklist.de",
             "label": "reported attacker", "country": None, "weight": 0.6}
            for ip in _iter_text_ips(blob)]


# --------------------------------------------------------------------------- #
# CINS Army (cinsscore.com) — community bad-actor IP list
# --------------------------------------------------------------------------- #
def fetch_cins():
    try:
        blob = _text("https://cinsscore.com/list/ci-badguys.txt")
    except Exception:
        return []
    return [{"ip": ip, "type": "malware", "source": "cins",
             "label": "CINS bad actor", "country": None, "weight": 0.7}
            for ip in _iter_text_ips(blob)]


# --------------------------------------------------------------------------- #
# Extra plaintext blocklists — bigger pool so the map stays busy
# --------------------------------------------------------------------------- #
def fetch_greensnow():
    try:
        blob = _text("https://blocklist.greensnow.co/greensnow.txt")
    except Exception:
        return []
    return [{"ip": ip, "type": "bruteforce", "source": "greensnow",
             "label": "GreenSnow attacker", "country": None, "weight": 0.6}
            for ip in _iter_text_ips(blob)]


def fetch_et_compromised():
    try:
        blob = _text("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
    except Exception:
        return []
    return [{"ip": ip, "type": "intrusion", "source": "et-compromised",
             "label": "ET compromised host", "country": None, "weight": 0.7}
            for ip in _iter_text_ips(blob)]


def fetch_blocklist_ssh():
    try:
        blob = _text("https://lists.blocklist.de/lists/ssh.txt")
    except Exception:
        return []
    return [{"ip": ip, "type": "bruteforce", "source": "blocklist.de-ssh",
             "label": "SSH brute-forcer", "country": None, "weight": 0.6}
            for ip in _iter_text_ips(blob)]


# --------------------------------------------------------------------------- #
# DataPlane.org — real sensor/honeypot-derived attacker IPs (no auth).
# Pipe-delimited:  ASN | ASname | IP | lastseen | category
# --------------------------------------------------------------------------- #
def _iter_dataplane_ips(blob):
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cols = line.split("|")
        if len(cols) < 3:
            continue
        ip = cols[2].strip()
        if _is_ip(ip):
            yield ip


def _dataplane(url, source, typ, label, weight):
    def _fetch():
        try:
            blob = _text(url)
        except Exception:
            return []
        return [{"ip": ip, "type": typ, "source": source,
                 "label": label, "country": None, "weight": weight}
                for ip in _iter_dataplane_ips(blob)]
    return _fetch


fetch_dp_ssh = _dataplane("https://dataplane.org/sshpwauth.txt",
                          "dataplane-ssh", "bruteforce", "honeypot SSH auth", 0.7)
fetch_dp_telnet = _dataplane("https://dataplane.org/telnetlogin.txt",
                             "dataplane-telnet", "bruteforce", "honeypot telnet (IoT)", 0.7)
fetch_dp_vnc = _dataplane("https://dataplane.org/vncrfb.txt",
                          "dataplane-vnc", "intrusion", "honeypot VNC probe", 0.7)
fetch_dp_sip = _dataplane("https://dataplane.org/sipquery.txt",
                          "dataplane-sip", "recon", "honeypot SIP scan", 0.6)


# Registry: (name, fetch_fn, poll_interval_seconds). Intervals respect each
# feed's own refresh cadence — abuse.ch regenerates URLhaus every ~5 min; the
# blocklists move slower. Don't hammer; you'll get blocked.
SOURCES = [
    ("feodo",            fetch_feodo,         30 * 60),
    ("threatfox",        fetch_threatfox,      5 * 60),
    ("urlhaus",          fetch_urlhaus,        5 * 60),
    ("dshield",          fetch_dshield,       60 * 60),
    ("blocklist.de",     fetch_blocklist,     30 * 60),
    ("cins",             fetch_cins,          60 * 60),
    ("greensnow",        fetch_greensnow,     30 * 60),
    ("et-compromised",   fetch_et_compromised, 60 * 60),
    ("blocklist.de-ssh", fetch_blocklist_ssh, 30 * 60),
    ("dataplane-ssh",    fetch_dp_ssh,        60 * 60),
    ("dataplane-telnet", fetch_dp_telnet,     60 * 60),
    ("dataplane-vnc",    fetch_dp_vnc,        60 * 60),
    ("dataplane-sip",    fetch_dp_sip,        60 * 60),
]

# file: extract_iocs_24h.py
from elasticsearch import Elasticsearch
from dateutil.relativedelta import relativedelta
from datetime import datetime, timezone
import pandas as pd
import re

ES_URL = "http://192.168.1.100:64298"
INDEX  = "logstash-*"
HOURS_LOOKBACK = 24

# ----- helpers -----
HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
URL_RE  = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)

def first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

# ----- connect ES -----
es = Elasticsearch([ES_URL])

now = datetime.now(timezone.utc)
start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

query = {
    "size": 5000,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "_source": [
        "@timestamp","src_ip","src_port","dest_ip","dest_port",
        "username","password",
        "md5","sha1","sha256","sha512","hash","hashes","message",
        "url","http.url","http.hostname","domain","dns.rrname"
    ],
    "query": {
        "range": {"@timestamp": {"gte": start}}
    }
}

resp = es.search(index=INDEX, body=query)

# ----- collect IOCs -----
ioc_rows = []

for hit in resp.get("hits", {}).get("hits", []):
    s = hit.get("_source", {})
    ts = first(s.get("@timestamp"))
    src_ip = first(s.get("src_ip"))

    # 1) IP nguồn
    if src_ip:
        ioc_rows.append({
            "timestamp": ts,
            "src_ip": src_ip,
            "ioc_type": "ip",
            "value": src_ip
        })

    # 2) Credentials
    u = first(s.get("username"))
    p = first(s.get("password"))
    if u or p:
        cred_str = f"{u or ''}:{p or ''}"
        ioc_rows.append({
            "timestamp": ts,
            "src_ip": src_ip,
            "ioc_type": "credential",
            "value": cred_str
        })

    # 3) Hashes
    for fld in ["md5","sha1","sha256","sha512","hash"]:
        for val in many(s.get(fld)):
            if val and HASH_RE.fullmatch(str(val)):
                ioc_rows.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "ioc_type": "hash",
                    "value": str(val)
                })
    for fld in ["hashes","message"]:
        for val in many(s.get(fld)):
            if not val: continue
            for m in HASH_RE.findall(str(val)):
                ioc_rows.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "ioc_type": "hash",
                    "value": m
                })

    # 4) URLs & domains
    for fld in ["url","http.url"]:
        for val in many(s.get(fld)):
            if val and isinstance(val, str):
                ioc_rows.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "ioc_type": "url",
                    "value": val
                })
                for m in URL_RE.findall(val):
                    ioc_rows.append({
                        "timestamp": ts,
                        "src_ip": src_ip,
                        "ioc_type": "url",
                        "value": m
                    })
    for fld in ["http.hostname","domain","dns.rrname"]:
        for val in many(s.get(fld)):
            if val and isinstance(val, str) and "." in val and " " not in val:
                ioc_rows.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "ioc_type": "domain",
                    "value": val
                })

# ----- save CSV -----
df = pd.DataFrame(ioc_rows).drop_duplicates()
df.to_csv("ioc_all_24h.csv", index=False)
print(f"[+] Saved {len(df)} IOC rows to ioc_all_24h.csv")

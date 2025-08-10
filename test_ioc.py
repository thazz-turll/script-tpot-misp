#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
All-in-one (ES -> IoC -> MISP) with hardening:
- Tag event: source:t-pot, tlp:amber (configurable)
- Auto disable IDS (to_ids=False) for non-routable/private IPs to reduce warnings
- Normalize domain/URL values
- Compatible with older PyMISP: use dict for add_attribute(...)

ENV you may want:
  ES_URL, ES_INDEX, HOURS_LOOKBACK
  MISP_URL, MISP_KEY, MISP_VERIFY_SSL
  EVENT_MODE=[DAILY|APPEND], MISP_EVENT_ID
  MISP_DISTRIBUTION, MISP_ANALYSIS, MISP_TLP, EVENT_TITLE_PREFIX
  MISP_TAGS="source:t-pot,tlp:amber"
  DISABLE_IDS_FOR_PRIVATE_IP="true"   # default true
  TAG_PRIVATE_IP_ATTR="false"         # set "true" to tag attributes 'scope:internal'
"""

import os
import re
import sys
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta

import pandas as pd
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==== CONFIG (có thể set qua ENV) ====
ES_URL           = os.getenv("ES_URL", "http://192.168.1.100:64298")
ES_INDEX         = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK   = int(os.getenv("HOURS_LOOKBACK", "24"))

MISP_URL         = os.getenv("MISP_URL", "https://192.168.1.101/")
MISP_KEY         = os.getenv("MISP_KEY", "REPLACE_ME")
VERIFY_SSL       = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"

EVENT_MODE       = os.getenv("EVENT_MODE", "DAILY").upper()   # DAILY | APPEND
MISP_EVENT_ID    = os.getenv("MISP_EVENT_ID")

EVENT_DISTRIBUTION = int(os.getenv("MISP_DISTRIBUTION", "0"))  # 0=your org only
EVENT_ANALYSIS     = int(os.getenv("MISP_ANALYSIS", "0"))      # 0 initial
THREAT_LEVEL_ID    = int(os.getenv("MISP_TLP", "2"))           # 1 hi,2 med
EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")

MISP_TAGS_STR      = os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").strip()
MISP_TAGS          = [t.strip() for t in MISP_TAGS_STR.split(",") if t.strip()]

DISABLE_IDS_FOR_PRIVATE = os.getenv("DISABLE_IDS_FOR_PRIVATE_IP", "true").lower() == "true"
TAG_PRIVATE_IP_ATTR     = os.getenv("TAG_PRIVATE_IP_ATTR", "false").lower() == "true"
PRIVATE_IP_TAG          = os.getenv("PRIVATE_IP_TAG", "scope:internal")

# ==== Regex nhận dạng hash ====
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

URL_RE    = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)
HASH_RE   = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

# Map base (non-hash)
MAPPING_BASE = {
    "ip":        ("ip-src", "Network activity", True),   # to_ids có thể bị override nếu là private
    "domain":    ("domain", "Network activity", True),
    "url":       ("url",    "Network activity", True),
    "credential":("text",   "Other",            False),  # không đẩy sang IDS
}

# ---------- Helpers ----------
def first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

def classify_hash(h: str):
    if not isinstance(h, str):
        return None
    v = h.strip()
    if MD5_RE.fullmatch(v): return "md5"
    if SHA1_RE.fullmatch(v): return "sha1"
    if SHA256_RE.fullmatch(v): return "sha256"
    return None

def is_non_routable_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)  # legacy IPv6 site-local
        or getattr(ip_obj, "is_global", None) is False  # includes IPv6 ULA fc00::/7
    )

def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    # drop possible trailing dots
    return d[:-1] if d.endswith(".") else d

def normalize_url(u: str) -> str:
    u = u.strip()
    try:
        p = urlparse(u)
        # rebuild minimal normalized url
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

# ---------- 1) Lấy dữ liệu từ Elasticsearch & trích IoC ----------
from elasticsearch import Elasticsearch
def fetch_iocs_from_es():
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
        "query": {"range": {"@timestamp": {"gte": start}}}
    }

    resp = es.search(index=ES_INDEX, body=query)

    ioc_rows = []
    for hit in resp.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        ts = first(s.get("@timestamp"))
        src_ip = first(s.get("src_ip"))

        # IP nguồn
        if src_ip:
            ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "ip", "value": str(src_ip)})

        # Credentials
        u = first(s.get("username"))
        p = first(s.get("password"))
        if u or p:
            cred_str = f"{u or ''}:{p or ''}"
            ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "credential", "value": cred_str})

        # Hashes: fields đơn trị
        for fld in ["md5","sha1","sha256","sha512","hash"]:
            for val in many(s.get(fld)):
                if not val: continue
                v = str(val)
                if HASH_RE.fullmatch(v):
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "hash", "value": v})

        # Hashes: trong mảng/chuỗi
        for fld in ["hashes","message"]:
            for val in many(s.get(fld)):
                if not val: continue
                for m in HASH_RE.findall(str(val)):
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "hash", "value": m})

        # URLs
        for fld in ["url","http.url"]:
            for val in many(s.get(fld)):
                if not val: continue
                v = normalize_url(str(val))
                ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "url", "value": v})
                for m in URL_RE.findall(v):
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "url", "value": normalize_url(m)})

        # Domains / hostnames
        for fld in ["http.hostname","domain","dns.rrname"]:
            for val in many(s.get(fld)):
                if not val: continue
                v = normalize_domain(str(val))
                if "." in v and " " not in v:
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "domain", "value": v})

    df = pd.DataFrame(ioc_rows)
    if df.empty:
        return df

    # Chuẩn hoá, bỏ trùng theo (ioc_type, value)
    keep_cols = [c for c in ["timestamp","src_ip","ioc_type","value"] if c in df.columns]
    df = df[keep_cols].dropna(subset=["value","ioc_type"]).drop_duplicates(subset=["ioc_type","value"])
    return df

# ---------- 2) Map từng hàng sang attribute MISP ----------
def map_row_to_misp(row):
    ioc_type = str(row.get("ioc_type", "")).strip().lower()
    value    = str(row.get("value", "")).strip()
    if not value:
        return None

    ts   = str(row.get("timestamp", "")).strip()
    src  = str(row.get("src_ip", "")).strip()
    comment_parts = []
    if src: comment_parts.append(f"src_ip={src}")
    if ts:  comment_parts.append(f"ts={ts}")
    comment = "; ".join(comment_parts) if comment_parts else ""

    if ioc_type == "hash":
        htype = classify_hash(value)
        if not htype:
            return None
        return (htype, "Payload delivery", True, value, comment, False)

    if ioc_type == "ip":
        to_ids = True
        is_private = is_non_routable_ip(value)
        if DISABLE_IDS_FOR_PRIVATE and is_private:
            to_ids = False
            if comment:
                comment += "; non-routable"
            else:
                comment = "non-routable"
        return ("ip-src", "Network activity", to_ids, value, comment, is_private)

    if ioc_type in ("domain", "url"):
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    if ioc_type == "credential":
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    return None

# ---------- 3) Tạo hoặc lấy event ----------
def create_daily_event_title():
    d = datetime.now(timezone.utc).date()
    return f"{EVENT_TITLE_PREFIX} - {d}"

def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info            = title
    ev.distribution    = EVENT_DISTRIBUTION
    ev.analysis        = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID

    res = misp.add_event(ev)
    # gắn tag cho event (nếu có)
    if MISP_TAGS:
        try:
            event_id = res["Event"]["id"]
        except Exception:
            event_id = getattr(res, "id", None)
        if event_id:
            for t in MISP_TAGS:
                try:
                    misp.tag(event_id, t)
                except Exception:
                    pass

    try:
        return res["Event"]["id"]
    except Exception:
        return getattr(res, "id", None) or RuntimeError(f"Cannot parse event id from response: {type(res)} {res}")

def get_or_create_event_id(misp: PyMISP):
    if EVENT_MODE == "APPEND":
        if not MISP_EVENT_ID:
            raise ValueError("EVENT_MODE=APPEND nhưng chưa set MISP_EVENT_ID")
        return MISP_EVENT_ID
    # DAILY: tạo mới
    title = create_daily_event_title()
    return create_event(misp, title)

# ---------- 4) Push attributes ----------
def push_iocs_to_misp(misp: PyMISP, event_id: str, df: pd.DataFrame):
    added, skipped = 0, 0

    # Lấy attributes hiện có để chống trùng
    existing_values = set()
    try:
        ev = misp.get_event(event_id, pythonify=True)
        for a in getattr(ev, "attributes", []) or []:
            existing_values.add((a.type, a.value))
    except Exception:
        pass

    for _, row in df.iterrows():
        mapped = map_row_to_misp(row)
        if not mapped:
            skipped += 1
            continue
        misp_type, category, to_ids, value, comment, is_private = mapped

        key = (misp_type, value)
        if key in existing_values:
            skipped += 1
            continue

        attr = {
            "type": misp_type,
            "category": category,
            "value": value,
            "to_ids": to_ids,
            "comment": comment,
        }
        try:
            aobj = misp.add_attribute(event_id, attr, pythonify=True)
            added += 1
            existing_values.add(key)

            # (Tuỳ chọn) gắn tag cho IP private/non‑routable
            if TAG_PRIVATE_IP_ATTR and is_private and getattr(aobj, "uuid", None):
                try:
                    misp.tag(aobj.uuid, PRIVATE_IP_TAG)
                except Exception:
                    pass

        except Exception as e:
            print(f"[!] add_attribute failed for {misp_type}={value}: {e}", file=sys.stderr)
            skipped += 1

    return added, skipped

# ---------- main ----------
def main():
    # 1) Lấy IoC
    df = fetch_iocs_from_es()
    if df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")
        return

    # 2) Kết nối MISP
    if MISP_KEY == "REPLACE_ME":
        print("[!] Chưa cấu hình MISP_KEY. Set env MISP_KEY trước khi chạy.")
        sys.exit(1)
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

    # 3) Lấy/ tạo Event ID
    event_id = get_or_create_event_id(misp)
    print(f"[+] Using Event ID: {event_id}")

    # 4) Đẩy attribute
    added, skipped = push_iocs_to_misp(misp, event_id, df)
    print(f"[+] Done. Added: {added}, Skipped: {skipped}, Total input: {len(df)}")

if __name__ == "__main__":
    main()

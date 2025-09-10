#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import sys
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from dateutil import parser as dtparser

import pandas as pd
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== .env =====
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===== CONFIG (bắt buộc từ ENV, không hardcode URL) =====
ES_URL = os.getenv("ES_URL")                # bắt buộc
MISP_URL = os.getenv("MISP_URL")            # bắt buộc
MISP_KEY = os.getenv("MISP_KEY")            # bắt buộc
EVENT_TITLE_FORMAT = os.getenv("EVENT_TITLE_FORMAT", "%Y-%m-%d %H:%M")
missing = []
if not ES_URL:   missing.append("ES_URL")
if not MISP_URL: missing.append("MISP_URL")
if not MISP_KEY: missing.append("MISP_KEY")
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# Các tham số không nhạy cảm
ES_INDEX       = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "24"))

VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_MODE     = os.getenv("EVENT_MODE", "DAILY").upper()          # DAILY | APPEND
MISP_EVENT_ID  = os.getenv("MISP_EVENT_ID")                        # cần khi APPEND

EVENT_DISTRIBUTION = int(os.getenv("MISP_DISTRIBUTION", "0"))
EVENT_ANALYSIS     = int(os.getenv("MISP_ANALYSIS", "0"))

MISP_TAGS = [t.strip() for t in os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").split(",") if t.strip()]

EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")

DISABLE_IDS_FOR_PRIVATE = os.getenv("DISABLE_IDS_FOR_PRIVATE_IP", "true").lower() == "true"
TAG_PRIVATE_IP_ATTR     = os.getenv("TAG_PRIVATE_IP_ATTR", "false").lower() == "true"
PRIVATE_IP_TAG          = os.getenv("PRIVATE_IP_TAG", "scope:internal")

# ---- NEW: cấu hình phát hiện Nmap-like scan ----
SCAN_TIME_WINDOW_MIN = int(os.getenv("SCAN_TIME_WINDOW_MIN", "10"))     # cửa sổ phát hiện, phút
SCAN_PORTS_THRESHOLD = int(os.getenv("SCAN_PORTS_THRESHOLD", "30"))     # số cổng distinct
SCAN_MIN_HITS        = int(os.getenv("SCAN_MIN_HITS", "0"))             # số log tối thiểu (giảm nhiễu)
NMAP_EVENT_TITLE     = os.getenv("NMAP_EVENT_TITLE", "Nmap Scan Detected")
NMAP_EVENT_MODE      = os.getenv("NMAP_EVENT_MODE", "SEPARATE").upper() # SEPARATE | APPEND

# Logging
LOG_FILE       = os.getenv("LOG_FILE", "ioc_es_to_misp.log")
LOG_MAX_BYTES  = int(os.getenv("LOG_MAX_BYTES", "1048576"))  # 1MB
LOG_BACKUPS    = int(os.getenv("LOG_BACKUPS", "3"))

# ===== Logger =====
logger = logging.getLogger("ioc-es-misp-v4")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ===== Regex/hash/url =====
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")

LABELED_HASH_RE = re.compile(
    r"(?i)\b(md5|sha1|sha256|sha512)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b"
)
BARE_HASH_RE = re.compile(
    r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b"
)
URL_RE          = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)

# Map base (non-hash)
MAPPING_BASE = {
    "ip":        ("ip-src", "Network activity", True),   # to_ids có thể bị override nếu là private
    "domain":    ("domain", "Network activity", True),
    "url":       ("url",    "Network activity", True),
    "credential":("text",   "Other",            False),  # không đẩy IDS
}

# ===== Helpers =====
def to_local_ts_str(ts_str: str) -> str:
    if not ts_str:
        return ""
    try:
        dt = dtparser.isoparse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return ts_str

def to_utc_iso(ts_str: str) -> str:
    try:
        dt = dtparser.isoparse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts_str

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
    if SHA512_RE.fullmatch(v): return "sha512"
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
        or getattr(ip_obj, "is_site_local", False)
        or getattr(ip_obj, "is_global", None) is False
    )

def normalize_domain(d: str) -> str:
    d = str(d or "").strip().lower()
    return d[:-1] if d.endswith(".") else d

def normalize_url(u: str) -> str:
    u = str(u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

# ===== ES fetch (ip/domain/url/hash/credential) =====
ES_SOURCE_FIELDS = [
    "@timestamp",
    # IP/username/password
    "source.ip", "src_ip",
    "user.name", "username", "password",
    # Hash fields & text
    "md5","sha1","sha256","sha512","hash","hashes","message",
    # URL/Domain
    "url","http.url","http.hostname","domain","dns.rrname"
]

def fetch_iocs_from_es():
    es = Elasticsearch([ES_URL])
    esq = es.options(request_timeout=60)

    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    _source = ES_SOURCE_FIELDS
    sort = [
        {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
        {"_id": {"order": "desc"}}
    ]
    query = {"range": {"@timestamp": {"gte": start}}}

    page_size = 5000
    search_after = None
    all_hits = []

    while True:
        resp = esq.search(
            index=ES_INDEX,
            query=query,
            sort=sort,
            _source=_source,
            size=page_size,
            search_after=search_after,
            track_total_hits=False
        )
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break
        all_hits.extend(hits)
        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break

    ioc_rows = []
    for hit in all_hits:
        s = hit.get("_source", {}) or {}
        ts = first(s.get("@timestamp"))

        # IP nguồn
        src_ip = first(s.get("source.ip")) or first(s.get("src_ip"))
        if src_ip:
            src_ip = str(src_ip)
            ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "ip", "value": src_ip})

        # Credentials
        u = first(s.get("user.name")) or first(s.get("username"))
        p = first(s.get("password"))
        if u or p:
            cred = f"{u or ''}:{p or ''}"
            ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "credential", "value": cred})

        # Hash: field chuyên dụng
        for fld in ["md5","sha1","sha256","sha512","hash"]:
            for val in many(s.get(fld)):
                if not val:
                    continue
                v = str(val).strip()
                if classify_hash(v):
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "hash", "value": v})

        # Hash trong text (ưu tiên có nhãn)
        for fld in ["hashes","message"]:
            for val in many(s.get(fld)):
                if not val:
                    continue
                text = str(val) or ""
                labeled_found = False
                for _, h in LABELED_HASH_RE.findall(text):
                    if classify_hash(h):
                        ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "hash", "value": h})
                        labeled_found = True
                if not labeled_found:
                    for h in BARE_HASH_RE.findall(text):
                        if classify_hash(h):
                            ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "hash", "value": h})

        # URL
        for fld in ["url","http.url"]:
            for val in many(s.get(fld)):
                if not val:
                    continue
                v = normalize_url(str(val))
                if v:
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "url", "value": v})

        # Domains / hostnames
        for fld in ["http.hostname","domain","dns.rrname"]:
            for val in many(s.get(fld)):
                if not val:
                    continue
                v = normalize_domain(str(val))
                if "." in v and " " not in v:
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "domain", "value": v})

    df = pd.DataFrame(ioc_rows)
    if df.empty:
        return df

    keep_cols = [c for c in ["timestamp","src_ip","ioc_type","value"] if c in df.columns]
    df = (
        df[keep_cols]
        .dropna(subset=["ioc_type","value"])
        .drop_duplicates(subset=["ioc_type","value"])
        .reset_index(drop=True)
    )
    return df

# ---- NEW: phát hiện IP quét nhiều cổng (Nmap-like) bằng aggregation ----
def detect_port_scanners_from_es():
    """
    Trả về list dict:
      [{"attacker_ip": "...", "ports_count": 123, "hits": 456, "first_seen": "...", "last_seen": "..."}]
    """
    es = Elasticsearch([ES_URL])
    esq = es.options(request_timeout=60)

    query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": f"now-{SCAN_TIME_WINDOW_MIN}m"}}}
            ]
        }
    }

    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "by_src": {
                "terms": {"field": "source.ip", "size": 10000},
                "aggs": {
                    "ports":   {"cardinality": {"field": "destination.port"}},
                    "hits":    {"value_count": {"field": "_id"}},
                    "first_ts":{"min": {"field": "@timestamp"}},
                    "last_ts": {"max": {"field": "@timestamp"}}
                }
            }
        }
    }

    resp = esq.search(index=ES_INDEX, body=body)
    buckets = resp.get("aggregations", {}).get("by_src", {}).get("buckets", []) or []

    scanners = []
    for b in buckets:
        ip_ = b.get("key")
        ports_count = int(b.get("ports", {}).get("value", 0) or 0)
        hits = int(b.get("hits", {}).get("value", 0) or 0)

        if ports_count >= SCAN_PORTS_THRESHOLD and hits >= SCAN_MIN_HITS:
            first_ts = b.get("first_ts", {}).get("value_as_string")
            last_ts  = b.get("last_ts", {}).get("value_as_string")
            scanners.append({
                "attacker_ip": ip_,
                "ports_count": ports_count,
                "hits": hits,
                "first_seen": first_ts,
                "last_seen": last_ts
            })
    return scanners

# ===== MISP mapping / push =====
def map_row_to_misp(row):
    ioc_type = str(row.get("ioc_type", "")).strip().lower()
    value = str(row.get("value", "")).strip()
    if not value:
        return None

    # Chuẩn bị thông tin thời gian & comment an toàn
    ts_str = str(row.get("timestamp", "") or "").strip()
    ts_local_str = ""
    utc_iso = ""
    comment = ""

    try:
        if ts_str:
            ts_local_str = to_local_ts_str(ts_str)
            utc_iso = to_utc_iso(ts_str)
    except Exception as e:
        logger.debug(f"timestamp parse error: {e}")

    src = str(row.get("src_ip", "") or "").strip()
    parts = []
    if src:
        parts.append(f"src_ip={src}")
    if utc_iso:
        parts.append(f"ts_utc={utc_iso}")
    if ts_local_str:
        parts.append(f"ts_local={ts_local_str}")

    comment = "; ".join(parts) if parts else ""

    # ---- NEW: gắn thêm 'note' (ví dụ: ports_distinct, hits, window…) vào comment
    note = str(row.get("note", "") or "").strip()
    if note:
        comment = (comment + ("; " if comment else "")) + note

    # Mapping sang MISP attribute
    if ioc_type == "hash":
        htype = classify_hash(value)
        if not htype:
            return None
        return (htype, "Payload delivery", True, value, comment, False)

    if ioc_type == "ip":
        is_private = is_non_routable_ip(value)
        to_ids = not (DISABLE_IDS_FOR_PRIVATE and is_private)
        if is_private:
            comment = (comment + "; non-routable") if comment else "non-routable"
        return ("ip-src", "Network activity", to_ids, value, comment, is_private)

    if ioc_type in ("domain", "url"):
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    if ioc_type == "credential":
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    return None

def create_daily_event_title():
    ts = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    return f"{EVENT_TITLE_PREFIX} - {ts}"

def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info         = title
    ev.distribution = EVENT_DISTRIBUTION
    ev.analysis     = EVENT_ANALYSIS

    res = misp.add_event(ev, pythonify=True)

    try:
        event_id = str(res.id)
        event_uuid = str(res.uuid)
    except Exception:
        raise RuntimeError(f"Cannot create MISP event (no id/uuid): {type(res)} {res}")

    logger.info(f"MISP_TAGS configured: {MISP_TAGS}")

    for t in MISP_TAGS:
        try:
            logger.info(f"TRY tag {event_uuid} with '{t}'")
            misp.tag(event_uuid, t)
            logger.info(f"TAG event {event_uuid} with '{t}'")
        except Exception as e:
            logger.error(f"Failed to tag event {event_uuid} with '{t}': {e}")

    return event_id

def get_event_id(misp: PyMISP):
    if EVENT_MODE == "APPEND":
        if not MISP_EVENT_ID:
            raise ValueError("EVENT_MODE=APPEND nhưng thiếu MISP_EVENT_ID")
        ev = misp.get_event(MISP_EVENT_ID)
        if not ev or ("Event" not in ev and not getattr(ev, "id", None)):
            raise ValueError(f"MISP_EVENT_ID={MISP_EVENT_ID} không tồn tại/không truy cập được")
        return MISP_EVENT_ID
    return create_event(misp, create_daily_event_title())

def push_iocs_to_misp(misp: PyMISP, event_id: str, df: pd.DataFrame):
    existing = set()
    try:
        ev = misp.get_event(event_id, pythonify=True)
        for a in getattr(ev, "attributes", []) or []:
            existing.add((a.type, a.value))
    except Exception as e:
        logger.warning(f"get_event attributes failed: {e}")

    added, skipped = 0, 0
    for _, row in df.iterrows():
        mapped = map_row_to_misp(row)
        if not mapped:
            skipped += 1
            continue
        misp_type, category, to_ids, value, comment, is_private = mapped
        key = (misp_type, value)
        if key in existing:
            skipped += 1
            continue

        attr = {"type": misp_type, "category": category, "value": value, "to_ids": to_ids, "comment": comment}
        try:
            aobj = misp.add_attribute(event_id, attr, pythonify=True)
            added += 1
            existing.add(key)
            logger.info(f"ADD {misp_type} value={value} to_ids={to_ids} comment='{comment}'")
            if TAG_PRIVATE_IP_ATTR and is_private and getattr(aobj, "uuid", None):
                try:
                    misp.tag(aobj.uuid, PRIVATE_IP_TAG)
                    logger.info(f"TAG attribute {aobj.uuid} with {PRIVATE_IP_TAG}")
                except Exception:
                    pass
        except Exception as e:
            # Fallback cho credential
            if misp_type == "credential":
                try:
                    attr_fallback = dict(attr)
                    attr_fallback["type"] = "text"
                    aobj = misp.add_attribute(event_id, attr_fallback, pythonify=True)
                    added += 1
                    existing.add(("text", value))
                    logger.warning(f"credential not supported, fallback to text. value={value}")
                except Exception as e2:
                    skipped += 1
                    logger.error(f"add_attribute failed (fallback) for credential value={value} err={e2}")
            else:
                skipped += 1
                logger.error(f"add_attribute failed: type={misp_type} value={value} err={e}")

    return added, skipped

# ===== main =====
def main():
    if not VERIFY_SSL:
        logger.warning("MISP SSL verification DISABLED (lab only)")

    # 1) Lấy IoC tổng hợp từ ES
    df = fetch_iocs_from_es()
    total = 0 if df is None or df.empty else len(df)
    logger.info(f"IoC fetched: {total}")
    if df is None or df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")

    # 2) Kết nối MISP
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

    # 3) Lấy hoặc tạo Event tổng hợp
    event_id = get_event_id(misp)
    logger.info(f"Using Event ID: {event_id}")
    print(f"[+] Using Event ID: {event_id}")

    # 4) Đẩy IoC tổng hợp (nếu có)
    if df is not None and not df.empty:
        added, skipped = push_iocs_to_misp(misp, event_id, df)
        logger.info(f"Done. Added={added} Skipped={skipped} TotalInput={total}")
        print(f"[+] IoC push done. Added: {added}, Skipped: {skipped}, Total input: {total}")

    # 5) ---- NEW: Phát hiện Nmap-like scanners và đẩy vào MISP ----
    scanners = detect_port_scanners_from_es()
    if scanners:
        if NMAP_EVENT_MODE == "APPEND":
            nmap_event_id = event_id
        else:
            nmap_event_id = create_event(misp, NMAP_EVENT_TITLE)
            try:
                # gắn thêm tag tool:Nmap cho event scan
                for t in MISP_TAGS + ["tool:Nmap"]:
                    misp.tag(nmap_event_id, t)
            except Exception:
                pass

        rows = []
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for sc in scanners:
            rows.append({
                "timestamp": sc.get("last_seen") or now_iso,
                "src_ip": sc["attacker_ip"],
                "ioc_type": "ip",
                "value": sc["attacker_ip"],
                "note": f"ports_distinct={sc['ports_count']}; hits={sc['hits']}; window={SCAN_TIME_WINDOW_MIN}m; detected_by=T-Pot"
            })
        df_scan = pd.DataFrame(rows)

        added_scan, skipped_scan = push_iocs_to_misp(misp, nmap_event_id, df_scan)
        logger.info(f"NMAP scan IoC pushed. Event={nmap_event_id} Added={added_scan} Skipped={skipped_scan} IPs={len(scanners)}")
        print(f"[+] Nmap scan detected. Event {nmap_event_id}. Added={added_scan}, Skipped={skipped_scan}, IPs={len(scanners)}")
    else:
        print("[i] No port scanners detected in current window.")

if __name__ == "__main__":
    main()

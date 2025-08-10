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
from dateutil import parser

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
EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")
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
THREAT_LEVEL_ID    = int(os.getenv("MISP_THREAT_LEVEL_ID", os.getenv("MISP_TLP", "2")))
EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")
MISP_TAGS          = [t.strip() for t in os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").split(",") if t.strip()]

DISABLE_IDS_FOR_PRIVATE = os.getenv("DISABLE_IDS_FOR_PRIVATE_IP", "true").lower() == "true"
TAG_PRIVATE_IP_ATTR     = os.getenv("TAG_PRIVATE_IP_ATTR", "false").lower() == "true"
PRIVATE_IP_TAG          = os.getenv("PRIVATE_IP_TAG", "scope:internal")

# Logging
LOG_FILE       = os.getenv("LOG_FILE", "ioc_es_to_misp.log")
LOG_MAX_BYTES  = int(os.getenv("LOG_MAX_BYTES", "1048576"))  # 1MB
LOG_BACKUPS    = int(os.getenv("LOG_BACKUPS", "3"))

# ===== Logger =====
logger = logging.getLogger("ioc-es-misp-v3")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ===== Regex/hash/url =====
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")

LABELED_HASH_RE = re.compile(r"(?i)\b(md5|sha1|sha256)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")
BARE_HASH_RE    = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
URL_RE          = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)

# Map base (non-hash)
MAPPING_BASE = {
    "ip":        ("ip-src", "Network activity", True),   # to_ids có thể bị override nếu là private
    "domain":    ("domain", "Network activity", True),
    "url":       ("url",    "Network activity", True),
    "credential":("text",   "Other",            False),  # không đẩy sang IDS
}

# ===== Helpers =====
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
    # Sử dụng options() để đặt request_timeout và tránh cảnh báo deprecation
    esq = es.options(request_timeout=60)
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    base_query = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"range": {"@timestamp": {"gte": start}}}
    }

    page_size = 5000
    search_after = None
    all_hits = []
    while True:
        body = dict(base_query)
        body["size"] = page_size
        if search_after:
            body["search_after"] = search_after
        # Đưa track_total_hits vào body để tránh cảnh báo tham số trùng
        body["track_total_hits"] = False
        resp = esq.search(index=ES_INDEX, body=body)
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
                if not val: continue
                v = str(val).strip()
                if classify_hash(v):
                    ioc_rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": "hash", "value": v})

        # Hash trong text: ưu tiên có nhãn; nếu không có nhãn mới bắt hash trần
        for fld in ["hashes","message"]:
            for val in many(s.get(fld)):
                if not val: continue
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

        # URLs
        for fld in ["url","http.url"]:
            for val in many(s.get(fld)):
                if not val: continue
                v = normalize_url(str(val))
                if v:
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
    keep_cols = [c for c in ["timestamp","src_ip","ioc_type","value"] if c in df.columns]
    df = (
        df[keep_cols]
        .dropna(subset=["ioc_type","value"])\
        .drop_duplicates(subset=["ioc_type","value"])\
        .reset_index(drop=True)
    )
    return df

# ===== MISP mapping / push =====

def map_row_to_misp(row):
    ioc_type = str(row.get("ioc_type", "")).strip().lower()
    value    = str(row.get("value", "")).strip()
    if not value:
        return None

    ts_str = str(row.get("timestamp", "")).strip()
    ts_local_str = ts_str
    if ts_str:
        try:
            # Parse từ dạng ISO (UTC) và đổi sang giờ local của server
            dt_utc = parser.isoparse(ts_str).replace(tzinfo=timezone.utc)
            dt_local = dt_utc.astimezone()  # sẽ lấy timezone của server (VN nếu đã set)
            ts_local_str = dt_local.strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            pass

    src = str(row.get("src_ip", "")).strip()
    comment = "; ".join([x for x in [f"src_ip={src}" if src else "", f"ts={ts_local_str}" if ts_local_str else ""] if x])


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
    # Ví dụ: "T-Pot IoC Collection - 2025-08-09 14:00" nếu format có giờ
    ts = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    return f"{EVENT_TITLE_PREFIX} - {ts}"


def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info            = title
    ev.distribution    = EVENT_DISTRIBUTION
    ev.analysis        = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID

    res = misp.add_event(ev)

    # Lấy event_id đúng cách
    event_id = None
    try:
        event_id = res["Event"]["id"]
    except Exception:
        event_id = getattr(res, "id", None)
    if not event_id:
        raise RuntimeError(f"Cannot create MISP event, unexpected response: {type(res)} {res}")

    # Gắn tag cho event (nếu có)
    for t in MISP_TAGS:
        try:
            misp.tag(event_id, t)
        except Exception:
            pass

    return event_id


def get_event_id(misp: PyMISP):
    if EVENT_MODE == "APPEND":
        if not MISP_EVENT_ID:
            raise ValueError("EVENT_MODE=APPEND nhưng thiếu MISP_EVENT_ID")
        # Kiểm tra event tồn tại/truy cập được
        ev = misp.get_event(MISP_EVENT_ID)
        if not ev or ("Event" not in ev and not getattr(ev, "id", None)):
            raise ValueError(f"MISP_EVENT_ID={MISP_EVENT_ID} không tồn tại/không truy cập được")
        return MISP_EVENT_ID
    # DAILY → tạo mới
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
            skipped += 1
            logger.error(f"add_attribute failed: type={misp_type} value={value} err={e}")

    return added, skipped


# ===== main =====
def main():
    if not VERIFY_SSL:
        logger.warning("MISP SSL verification DISABLED (lab only)")

    # 1) Lấy IoC từ ES
    df = fetch_iocs_from_es()
    total = 0 if df is None or df.empty else len(df)
    logger.info(f"IoC fetched: {total}")
    if df is None or df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")
        return

    # 2) Kết nối MISP
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

    # 3) Lấy hoặc tạo Event
    event_id = get_event_id(misp)
    logger.info(f"Using Event ID: {event_id}")
    print(f"[+] Using Event ID: {event_id}")

    # 4) Đẩy attribute
    added, skipped = push_iocs_to_misp(misp, event_id, df)
    logger.info(f"Done. Added={added} Skipped={skipped} TotalInput={total}")
    print(f"[+] Done. Added: {added}, Skipped: {skipped}, Total input: {total}")


if __name__ == "__main__":
    main()

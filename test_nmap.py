#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect Nmap-like port scans against T-Pot from Elasticsearch logs and push attacker IPs to MISP.
- Follows the structure and env-driven config style of collect_and_push_iocs.py
- Focused only on Kịch bản 1 (Nmap scan). If nothing matches, print a clear message and exit.
"""
import os
import sys
import re
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from dateutil import parser as dtparser
from urllib.parse import urlparse

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

# ===== Required config =====
ES_URL = os.getenv("ES_URL")
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
missing = []
if not ES_URL:   missing.append("ES_URL")
if not MISP_URL: missing.append("MISP_URL")
if not MISP_KEY: missing.append("MISP_KEY")
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# ===== Optional config =====
ES_INDEX       = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "24"))

VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_MODE     = os.getenv("EVENT_MODE", "DAILY").upper()          # DAILY | APPEND
MISP_EVENT_ID  = os.getenv("MISP_EVENT_ID")                          # needed if APPEND

EVENT_DISTRIBUTION = int(os.getenv("MISP_DISTRIBUTION", "0"))
EVENT_ANALYSIS     = int(os.getenv("MISP_ANALYSIS", "0"))

MISP_TAGS = [t.strip() for t in os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").split(",") if t.strip()]

# Default a dedicated title prefix for this scenario; still overridable by env
EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "Nmap Scan Detected")
EVENT_TITLE_FORMAT = os.getenv("EVENT_TITLE_FORMAT", "%Y-%m-%d %H:%M")

# Detection tuning
MIN_UNIQUE_PORTS = int(os.getenv("NMAP_MIN_UNIQUE_PORTS", "8"))  # distinct dest ports threshold
MAX_IPS_PUSH     = int(os.getenv("NMAP_MAX_IPS_PUSH", "200"))     # safety cap

# Private IP handling (same semantics as main script)
DISABLE_IDS_FOR_PRIVATE = os.getenv("DISABLE_IDS_FOR_PRIVATE_IP", "true").lower() == "true"
TAG_PRIVATE_IP_ATTR     = os.getenv("TAG_PRIVATE_IP_ATTR", "false").lower() == "true"
PRIVATE_IP_TAG          = os.getenv("PRIVATE_IP_TAG", "scope:internal")

# Logging
LOG_FILE       = os.getenv("LOG_FILE", "ioc_es_to_misp.log")
LOG_MAX_BYTES  = int(os.getenv("LOG_MAX_BYTES", "1048576"))
LOG_BACKUPS    = int(os.getenv("LOG_BACKUPS", "3"))

logger = logging.getLogger("detect-nmap-scan")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ===== Helpers =====
PORT_FIELDS = [
    "destination.port", "dest_port", "dst_port", "server.port", "tcp.dstport", "dport", "network.destination.port"
]
SRC_IP_FIELDS = ["source.ip", "src_ip", "client.ip", "ip.src", "network.client.ip"]

ES_SOURCE_FIELDS = ["@timestamp"] + list(set(PORT_FIELDS + SRC_IP_FIELDS))

def first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

def to_utc_iso(ts_str: str) -> str:
    try:
        dt = dtparser.isoparse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts_str or ""

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

# ===== ES fetch & detect =====

def fetch_scan_candidates_from_es():
    es = Elasticsearch([ES_URL])
    esq = es.options(request_timeout=60)

    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    query = {"range": {"@timestamp": {"gte": start}}}
    sort = [
        {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
        {"_id": {"order": "desc"}},
    ]

    page_size = 5000
    search_after = None

    # Aggregation state: src_ip -> {ports:set, first_ts:str, last_ts:str}
    agg = {}

    while True:
        resp = esq.search(
            index=ES_INDEX,
            query=query,
            sort=sort,
            _source=ES_SOURCE_FIELDS,
            size=page_size,
            search_after=search_after,
            track_total_hits=False,
        )
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for h in hits:
            s = h.get("_source", {}) or {}
            ts = first(s.get("@timestamp")) or ""

            # src ip
            src_ip = None
            for f in SRC_IP_FIELDS:
                v = first(s.get(f))
                if v:
                    src_ip = str(v)
                    break
            if not src_ip:
                continue

            # dest port (first available)
            dport = None
            for f in PORT_FIELDS:
                v = first(s.get(f))
                if v is None:
                    continue
                try:
                    dport = int(str(v))
                    break
                except Exception:
                    # skip unparsable
                    continue
            if dport is None:
                continue

            st = agg.get(src_ip)
            if not st:
                st = {"ports": set(), "first_ts": ts, "last_ts": ts}
                agg[src_ip] = st
            st["ports"].add(dport)
            # update first/last
            if st["first_ts"] is None or (ts and ts < st["first_ts"]):
                st["first_ts"] = ts
            if st["last_ts"] is None or (ts and ts > st["last_ts"]):
                st["last_ts"] = ts

        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break

    # Convert to DataFrame and filter by threshold
    rows = []
    for ip, st in agg.items():
        ports = sorted(list(st["ports"]))
        rows.append(
            {
                "src_ip": ip,
                "unique_port_count": len(ports),
                "ports": ports,
                "first_ts": st.get("first_ts") or "",
                "last_ts": st.get("last_ts") or "",
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    df = df[df["unique_port_count"] >= MIN_UNIQUE_PORTS].sort_values(
        by=["unique_port_count", "src_ip"], ascending=[False, True]
    )
    if df.shape[0] > MAX_IPS_PUSH:
        df = df.head(MAX_IPS_PUSH)
    return df.reset_index(drop=True)

# ===== MISP helpers =====

def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info = title
    ev.distribution = EVENT_DISTRIBUTION
    ev.analysis = EVENT_ANALYSIS
    res = misp.add_event(ev, pythonify=True)
    try:
        event_id = str(res.id)
        event_uuid = str(res.uuid)
    except Exception as e:
        raise RuntimeError(f"Cannot create MISP event (no id/uuid): {type(res)} {res}")
    for t in MISP_TAGS:
        try:
            misp.tag(event_uuid, t)
        except Exception:
            pass
    return event_id


def get_event_id(misp: PyMISP):
    if EVENT_MODE == "APPEND":
        if not MISP_EVENT_ID:
            raise ValueError("EVENT_MODE=APPEND nhưng thiếu MISP_EVENT_ID")
        ev = misp.get_event(MISP_EVENT_ID)
        if not ev or ("Event" not in ev and not getattr(ev, "id", None)):
            raise ValueError(f"MISP_EVENT_ID={MISP_EVENT_ID} không tồn tại/không truy cập được")
        return MISP_EVENT_ID
    # DAILY → tạo mới
    ts = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    title = f"{EVENT_TITLE_PREFIX} - {ts}"
    return create_event(misp, title)

# ===== Push =====

def push_scan_ips_to_misp(misp: PyMISP, event_id: str, df: pd.DataFrame):
    added, skipped = 0, 0
    for _, row in df.iterrows():
        ip = str(row["src_ip"]) 
        ports = list(row["ports"]) if isinstance(row["ports"], (list, tuple)) else []
        pcount = int(row["unique_port_count"]) if row.get("unique_port_count") is not None else len(ports)
        first_ts = to_utc_iso(str(row.get("first_ts") or ""))
        last_ts  = to_utc_iso(str(row.get("last_ts") or ""))

        comment_parts = [f"port_count={pcount}"]
        if ports:
            # include only first 15 ports to keep comment short
            preview = ports[:15]
            comment_parts.append(f"ports={preview}{'...' if len(ports)>15 else ''}")
        if first_ts or last_ts:
            comment_parts.append(f"window=[{first_ts} .. {last_ts}]")
        comment = "; ".join(comment_parts)

        is_private = is_non_routable_ip(ip)
        to_ids = not (DISABLE_IDS_FOR_PRIVATE and is_private)
        if is_private and not to_ids:
            comment = (comment + "; non-routable") if comment else "non-routable"

        try:
            aobj = misp.add_attribute(
                event_id,
                {"type": "ip-src", "category": "Network activity", "value": ip, "to_ids": to_ids, "comment": comment},
                pythonify=True,
            )
            added += 1
            if TAG_PRIVATE_IP_ATTR and is_private and getattr(aobj, "uuid", None):
                try:
                    misp.tag(aobj.uuid, PRIVATE_IP_TAG)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"add_attribute failed for ip={ip} err={e}")
            skipped += 1
    return added, skipped

# ===== main =====

def main():
    if not VERIFY_SSL:
        logger.warning("MISP SSL verification DISABLED (lab only)")

    df = fetch_scan_candidates_from_es()
    total = 0 if df is None or df.empty else len(df)
    if df is None or df.empty:
        print("[!] Không phát hiện hành vi scan cổng (kiểu Nmap) trong khoảng thời gian yêu cầu.")
        return

    # Connect & ensure event
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)
    event_id = get_event_id(misp)
    logger.info(f"Using Event ID: {event_id}")
    print(f"[+] Using Event ID: {event_id}")

    added, skipped = push_scan_ips_to_misp(misp, event_id, df)
    logger.info(f"Done. Added={added} Skipped={skipped} TotalIPs={total}")
    print(f"[+] Done. Added: {added}, Skipped: {skipped}, Total attacker IPs: {total}")


if __name__ == "__main__":
    main()

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import pandas as pd

# ===== THÔNG TIN KẾT NỐI =====
ELASTIC_HOST = 'http://192.168.1.100:9200'  # <-- IP của T-Pot
ELASTIC_INDEX = 'logstash-*'  # hoặc 'cowrie-*', 'dionaea-*' nếu muốn cụ thể

# ===== KẾT NỐI VÀ TRUY VẤN LOG =====
es = Elasticsearch(ELASTIC_HOST)

# Truy vấn log 24h gần nhất
now = datetime.utcnow()
last_24h = now - timedelta(hours=24)

query_body = {
    "query": {
        "range": {
            "@timestamp": {
                "gte": last_24h.strftime("%Y-%m-%dT%H:%M:%S"),
                "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
            }
        }
    },
    "_source": [
        "src_ip",
        "username",
        "password",
        "sha256_hash",
        "md5_hash",
        "destination_ip",
        "protocol",
        "filename",
        "url"
    ]
}

# ===== TRÍCH XUẤT DỮ LIỆU =====
res = es.search(index=ELASTIC_INDEX, body=query_body, size=1000)

ioc_list = []
for hit in res['hits']['hits']:
    data = hit['_source']
    ioc = {
        "src_ip": data.get("src_ip"),
        "username": data.get("username"),
        "password": data.get("password"),
        "sha256_hash": data.get("sha256_hash"),
        "md5_hash": data.get("md5_hash"),
        "filename": data.get("filename"),
        "url": data.get("url"),
        "protocol": data.get("protocol"),
        "destination_ip": data.get("destination_ip"),
        "timestamp": data.get("@timestamp")
    }
    # Bỏ qua dòng toàn None
    if any(ioc.values()):
        ioc_list.append(ioc)

# ===== HIỂN THỊ HOẶC LƯU FILE =====
df = pd.DataFrame(ioc_list)
print(df)

# (Tùy chọn) Lưu ra file CSV
df.to_csv("ioc_extracted.csv", index=False)
print("[+] Đã lưu ioc_extracted.csv")

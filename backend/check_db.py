import sqlite3
import json
import re
from collections import defaultdict

conn = sqlite3.connect('forensiq.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Check recent files' alerts
for fid in [10, 11, 14, 15, 16, 17, 18]:
    cur.execute("SELECT COUNT(*) as c FROM alerts WHERE file_id = ?", (fid,))
    cnt = cur.fetchone()["c"]
    cur.execute("SELECT filename, tool FROM case_files WHERE id = ?", (fid,))
    row = cur.fetchone()
    if row:
        print(f"File {fid}: {row['filename']} ({row['tool']}) -> {cnt} alerts")
    
    if cnt > 0:
        cur.execute("SELECT tool, severity, title, target, src_ip, dst_ip, timestamp, details, threat_intel FROM alerts WHERE file_id = ? LIMIT 5", (fid,))
        for r in cur.fetchall():
            ti_str = r["threat_intel"]
            ti_summary = ""
            if ti_str:
                try:
                    ti = json.loads(ti_str)
                    if isinstance(ti, list):
                        ti_summary = f" TI:[{len(ti)} entries]"
                except:
                    pass
            print(f"  sev={r['severity']} tool={r['tool']} title={r['title'][:60]} target={r['target'][:40] if r['target'] else 'None'} ts={r['timestamp']}{ti_summary}")
        print()

# Check all unique IPs across all alerts
print("\n=== All unique IPs across ALL alerts ===")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ip_files = defaultdict(set)

cur.execute("SELECT file_id, tool, src_ip, dst_ip, target FROM alerts WHERE file_id IN (10, 11, 14, 15, 16, 17, 18)")
for r in cur.fetchall():
    for f in [r["src_ip"], r["dst_ip"], r["target"]]:
        if f:
            for ip in IP_RE.findall(str(f)):
                ip_files[ip].add((r["file_id"], r["tool"]))

for ip, fids in sorted(ip_files.items(), key=lambda x: -len(x[1])):
    files = set(f[0] for f in fids)
    tools = set(f[1] for f in fids)
    marker = " *** CROSS-FILE ***" if len(files) >= 2 else ""
    print(f"  {ip}: files={files} tools={tools}{marker}")

conn.close()

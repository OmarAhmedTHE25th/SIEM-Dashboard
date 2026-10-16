from parser import parse_line
from database import insert_event, init_db

init_db()

count = 0
with open("OpenSSH_2k.log", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        event = parse_line(line)
        if event:
            insert_event(event)
            count += 1

print(f"[+] Ingested {count} real production events into siem.db!")
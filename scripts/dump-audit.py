import json
import sys

p = sys.argv[1]
for line in open(p, encoding="utf-8", errors="replace"):
    try:
        r = json.loads(line)
        ev = r.get("event")
        d = r.get("data") or {}
        print(ev, "|", str(d)[:180])
    except Exception as e:
        print("SKIP:", str(e)[:40])

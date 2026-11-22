import base64
import sys

src = sys.argv[1]
dst = sys.argv[2]
cmd = open(src, encoding="utf-8").read()
b64 = base64.b64encode(cmd.encode("utf-16le")).decode()
open(dst, "w", encoding="ascii").write(b64)
print("b64 written:", len(b64), "chars")

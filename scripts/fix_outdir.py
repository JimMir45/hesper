import glob

patched = 0
for p in glob.glob(r"C:\Users\jiang\orca\projects\hesper\lab\vagrant\lite-vms\provision\..") and []:
    pass

for p in [
    r"C:\Users\jiang\orca\projects\hesper\actions\endpoint\files\ntdsutil_snapshot.ps1",
    r"C:\Users\jiang\orca\projects\hesper\actions\endpoint\files\ntds_ifm_dump.ps1",
    r"C:\Users\jiang\orca\projects\hesper\actions\endpoint\files\shadowcopy_wmi_delete.ps1",
]:
    s = open(p, encoding="utf-8").read()
    anchor = "$marker = if ($params.marker) { $params.marker } else {"
    if "$outDir) | Out-Null" in s:
        print("already patched:", p.split("\\")[-1])
        continue
    assert anchor in s, "anchor missing in " + p
    s = s.replace(
        anchor,
        "New-Item -ItemType Directory -Force -Path $outDir | Out-Null\n" + anchor,
        1,
    )
    # out_dir is parsed from params BEFORE the marker line; the New-Item must
    # come after $outDir is defined. Move it: place after the out_dir assignment
    od_anchor = '$outDir = if ($params.out_dir) { $params.out_dir } else { "C:\\hesper\\out" }'
    s = s.replace("New-Item -ItemType Directory -Force -Path $outDir | Out-Null\n" + anchor, anchor + "\nNew-Item -ItemType Directory -Force -Path $outDir | Out-Null", 1)
    open(p, "w", encoding="utf-8", newline="\n").write(s)
    patched += 1
    print("patched:", p.split("\\")[-1])
print("done", patched)

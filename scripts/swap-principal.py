p = r"C:\Users\jiang\orca\projects\hesper\lab\vagrant\lite-vms\Vagrantfile"
s = open(p, encoding="utf-8").read()
old = (
    '  elevated_user = "vagrant@hesper.lab"\n'
    '  elevated_password = "vagrant"\n'
    '  if ENV["HESPER_NO_PRIVATE_NET"].nil?\n'
    '    elevated_user = ENV["HESPER_WINRM_USER"] || "vagrant"\n'
    '    elevated_password = ENV["HESPER_WINRM_PASS"] || "vagrant"\n'
    "  end"
)
new = (
    '  elevated_user = "hesper\\\\vagrant"\n'
    '  elevated_password = "vagrant"\n'
    '  if ENV["HESPER_NO_PRIVATE_NET"].nil?\n'
    '    elevated_user = ENV["HESPER_WINRM_USER"] || "vagrant"\n'
    '    elevated_password = ENV["HESPER_WINRM_PASS"] || "vagrant"\n'
    "  end"
)
assert old in s, "block missing"
s = s.replace(old, new, 1)
open(p, "w", encoding="utf-8", newline="\n").write(s)
print("swapped to DOMAIN-user form")

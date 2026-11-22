p = "/mnt/c/Users/jiang/orca/projects/hesper/lab/vagrant/lite-vms/Vagrantfile"
s = open(p, encoding="utf-8").read()
s = s.replace(", elevated_user: elevated_user, elevated_password: elevated_password", "")
open(p, "w", encoding="utf-8", newline="\n").write(s)
print("stripped:", s.count("elevated_user: elevated_user"))

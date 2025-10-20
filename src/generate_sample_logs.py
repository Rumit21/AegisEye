import os, random, pandas as pd, numpy as np
from datetime import datetime, timedelta

os.makedirs('data', exist_ok=True)
now = datetime.now()

# AUTH log
users = ["rumit","alice","bob","svc-backup","john"]
ips = [f"192.168.1.{i}" for i in range(10, 50)] + ["45.83.12.9","103.24.55.8","77.13.5.22"]
rows, t = [], now - timedelta(hours=48)
for i in range(9000):
    t += timedelta(seconds=random.randint(5, 20))
    user = random.choice(users)
    ip = random.choice(ips)
    action = random.choice(["login","logout","sudo","password_change"])
    status = random.choices(["success","failure"], [0.78,0.22])[0]
    if 3000 < i < 3150:
        user="rumit"; action="login"; status="failure"; ip="103.24.55.8"
    rows.append([t.isoformat(timespec='seconds'), user, ip, action, status])
pd.DataFrame(rows, columns=["timestamp","user","src_ip","action","status"]).to_csv("data/auth_log.csv", index=False)

# WEB log
paths = ["/","/login","/admin","/wp-login.php","/api/v1/auth","/search","/dashboard"]
codes = [200,200,200,404,401,403,500]
rows, t = [], now - timedelta(hours=48)
uas = ["Mozilla","curl/7.79","python-requests/2.31","sqlmap/1.7","Go-http-client/1.1"]
for i in range(12000):
    t += timedelta(seconds=random.randint(2, 8))
    ip = random.choice(ips)
    path = random.choice(paths)
    code = random.choice(codes)
    ua = random.choice(uas)
    rows.append([t.isoformat(timespec='seconds'), ip, path, code, ua])
pd.DataFrame(rows, columns=["timestamp","src_ip","path","status_code","user_agent"]).to_csv("data/web_log.csv", index=False)

# FIREWALL log
acts=["ALLOW","DROP","REJECT"]; ports=[22,80,443,3389,445,8080,3306]
rows, t = [], now - timedelta(hours=48)
for i in range(8000):
    t += timedelta(seconds=random.randint(3, 12))
    src = ".".join(map(str,[random.randint(1,255) for _ in range(4)]))
    dst = f"192.168.1.{random.randint(10,40)}"
    port = random.choice(ports)
    action = random.choices(acts,[0.75,0.18,0.07])[0]
    if 6000 < i < 6200:
        src="45.83.12.9"; action="DROP"; port=random.choice(ports)
    rows.append([t.isoformat(timespec='seconds'), src, dst, port, action])
pd.DataFrame(rows, columns=["timestamp","src_ip","dst_ip","dst_port","action"]).to_csv("data/firewall_log.csv", index=False)

print("[+] Sample logs written: data/auth_log.csv, data/web_log.csv, data/firewall_log.csv")

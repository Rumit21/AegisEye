import pandas as pd
from pathlib import Path
from ip_geo import map_ip_to_country


def load_logs(data_dir="data"):
    p = Path(data_dir)
    auth = pd.read_csv(p/"auth_log.csv", parse_dates=["timestamp"])
    web  = pd.read_csv(p/"web_log.csv",  parse_dates=["timestamp"])
    fw   = pd.read_csv(p/"firewall_log.csv", parse_dates=["timestamp"])
    return auth, web, fw

def build_alerts(auth: pd.DataFrame, web: pd.DataFrame, fw: pd.DataFrame) -> pd.DataFrame:
    alerts = []

    # 1) Failed login bursts → brute-force (MED/HIGH)
    auth_logins = auth[(auth['action']=='login')]
    fail = auth_logins[auth_logins['status']=='failure'].copy()
    if not fail.empty:
        g = (fail.set_index('timestamp')
         .groupby(['user','src_ip'])
         .resample('1min', include_groups=False)
         .size()
         .rename('fails')
         .reset_index())

        bf = g[g['fails'] >= 5]
        for _, r in bf.iterrows():
            alerts.append({
                "timestamp": r['timestamp'],
                "type": "Brute Force",
                "severity": "High" if r['fails'] >= 10 else "Medium",
                "src_ip": r['src_ip'],
                "user": r['user'],
                "context": f"Failed logins in 1m: {int(r['fails'])}"
            })

    # 2) Web: sqlmap UA → SQLi probe (MED)
    sqli = web[web['user_agent'].str.contains('sqlmap', case=False, na=False)].copy()
    for _, r in sqli.iterrows():
        alerts.append({
            "timestamp": r['timestamp'],
            "type": "SQLi Probe",
            "severity": "Medium",
            "src_ip": r['src_ip'],
            "user": None,
            "context": f"path={r['path']} ua={r['user_agent']}"
        })

    # 3) Web: 401/403 on login paths → auth abuse (LOW/MED)
    web_auth = web[web['path'].str.contains('login', case=False, na=False)]
    web_errs = web_auth[web_auth['status_code'].isin([401,403])]
    if not web_errs.empty:
        t = (web_errs.groupby(['src_ip'])
                    .size().reset_index(name='hits')
                    .sort_values('hits', ascending=False))
        for _, r in t.iterrows():
            sev = "Medium" if r['hits'] >= 10 else "Low"
            alerts.append({
                "timestamp": web_errs['timestamp'].max(),
                "type": "Auth Abuse",
                "severity": sev,
                "src_ip": r['src_ip'],
                "user": None,
                "context": f"401/403 hits={int(r['hits'])}"
            })

    # 4) Firewall: multi-port hits → scan (MED/HIGH)
    fw_ports = fw.groupby('src_ip')['dst_port'].nunique().reset_index(name='distinct_ports')
    scans = fw_ports[fw_ports['distinct_ports'] >= 6]
    for _, r in scans.iterrows():
        alerts.append({
            "timestamp": fw['timestamp'].max(),
            "type": "Port Scan",
            "severity": "High" if r['distinct_ports'] >= 10 else "Medium",
            "src_ip": r['src_ip'],
            "user": None,
            "context": f"distinct_ports={int(r['distinct_ports'])}"
        })

    df = pd.DataFrame(alerts)
    if df.empty:
        df = pd.DataFrame([{
            "timestamp": pd.Timestamp.now(),
            "type": "No Alerts",
            "severity": "Low",
            "src_ip": "",
            "user": "",
            "context": "No notable events detected."
        }])

    # country columns
    df['country_iso3'], df['country_name'] = zip(*df['src_ip'].fillna("").map(map_ip_to_country))
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values('timestamp')

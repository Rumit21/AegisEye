from ipaddress import ip_address

KNOWN = {
    "45.83.12.9":  ("NLD", "Netherlands"),
    "103.24.55.8": ("IND", "India"),
    "77.13.5.22":  ("DEU", "Germany"),
}

def map_ip_to_country(ip: str):
    try:
        ip_address(ip)
    except Exception:
        return ("UNK", "Unknown")
    if ip in KNOWN:
        return KNOWN[ip]
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return ("INT", "Internal")
    return ("UNK", "Unknown")

import re
import ipaddress
import pandas as pd
from extract_msg import Message


RAW_HEADERS_FILE = "raw_headers.txt"
MSG_FILE = "sample.msg"
OUTPUT_FILE = "analysis.xlsx"


# ================= IP EXTRACTION =================

def extract_public_ips_from_headers(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found_ips = set(re.findall(ip_regex, content))

    public_ips = []

    for ip in found_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_global:   # filters private, loopback, reserved, multicast
                public_ips.append(ip)
        except ValueError:
            pass

    return sorted(public_ips)


# ================= URL EXTRACTION =================

def extract_urls_from_msg(path):
    msg = Message(path)
    body = msg.body or ""

    url_regex = r'https?://[^\s<>"\']+'
    return sorted(set(re.findall(url_regex, body)))


# ================= MAIN =================

def main():
    ips = extract_public_ips_from_headers(RAW_HEADERS_FILE)
    urls = extract_urls_from_msg(MSG_FILE)

    df_ips = pd.DataFrame({"Public IP Addresses": ips})
    df_urls = pd.DataFrame({"URLs": urls})

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:
        df_ips.to_excel(writer, index=False, sheet_name="IPs")
        df_urls.to_excel(writer, index=False, sheet_name="URLs")

    print("[+] Extraction completed")
    print("[+] Private/reserved IPs removed")
    print("[+] Output saved as analysis.xlsx")


if __name__ == "__main__":
    main()

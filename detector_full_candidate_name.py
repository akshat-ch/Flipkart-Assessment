import csv
import json
import re

def fix_json(json_str):
    return json_str.replace('""', '"')

def mask_phone(val):
    s = str(val)
    return f"{s[:2]}XXXXX{s[-3:]}" if len(s) == 10 else "[REDACTED_PII]"

def mask_aadhar(val):
    s = str(val)
    return f"{s[:4]}XXXXXX{s[-2:]}" if len(s) == 12 and s.isdigit() else "[REDACTED_PII]"

def mask_passport(val):
    s = str(val)
    return f"{s[0]}XXXXXXX" if len(s) in (8,9) and s[0].isalpha() else "[REDACTED_PII]"

def mask_upi(val):
    return "[REDACTED_PII]"

def mask_email(val):
    parts = val.split("@")
    local = parts[0]
    domain = parts[1]
    masked_local = local[0] + "XXX" + (local[-1] if len(local)>4 else "")
    return f"{masked_local}@{domain}"

def mask_name(val):
    parts = val.split(" ")
    out = []
    for p in parts:
        if len(p) > 3:
            out.append(p[0] + "XXX" + (p[-1] if len(p)>4 else ""))
        else:
            out.append(p[0] + "XX")
    return " ".join(out)

def mask_address(val):
    return "[REDACTED_PII]"

def mask_ip(ip):
    return "[REDACTED_PII]"

def mask_device_id(dev):
    return "[REDACTED_PII]"

def mask_value(key, val):
    # Standalone PII rules
    if key == "phone" and re.match(r"^[6-9]\d{9}$", str(val)):
        return mask_phone(val), True
    if key == "aadhar" and re.match(r"^\d{12}$", str(val)):
        return mask_aadhar(val), True
    if key == "passport" and re.match(r"^[A-Z][0-9]{7}$", str(val)):
        return mask_passport(val), True
    if key == "upi_id" and re.match(r".+@.+", str(val)):
        return mask_upi(val), True
    return val, False

def is_combinatorial(keys):
    combo = {'name', 'email', 'address', 'device_id', 'ip_address'}
    return len(set(keys) & combo) >= 2

def mask_combo(key, val):
    if key == "name": return mask_name(val)
    if key == "address": return mask_address(val)
    if key == "email": return mask_email(val)
    if key == "ip_address": return mask_ip(val)
    if key == "device_id": return mask_device_id(val)
    return val

input_file = "/Users/akshatchaudhary/Downloads/Project/Flipkart Assessment/iscp_pii_dataset_-_Sheet1.csv"
output_file = "redacted_output_candidate_full_name.csv"

with open(input_file, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    out_data = []
    for row in reader:
        rid = row["record_id"]
        try:
            data = json.loads(fix_json(row["data_json"]))
        except Exception:
            continue
        result = {}
        found_standalone = False
        for k, v in data.items():
            masked, found = mask_value(k, v)
            if found:
                found_standalone = True
                result[k] = masked
            else:
                result[k] = v
        keys = [k for k in data if k in {"name", "address", "email", "device_id", "ip_address"}]
        found_combo = is_combinatorial(keys)
        is_pii = found_standalone or found_combo
        if found_combo:
            for k in keys:
                result[k] = mask_combo(k, data[k])
        out_data.append({
            "record_id": rid,
            "redacted_data_json": json.dumps(result, ensure_ascii=False),
            "is_pii": str(is_pii)
        })

with open(output_file, "w", encoding="utf-8", newline="") as wf:
    writer = csv.DictWriter(wf, fieldnames=["record_id", "redacted_data_json", "is_pii"])
    writer.writeheader()
    writer.writerows(out_data)


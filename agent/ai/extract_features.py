# agent/ai/extract_features.py
import pandas as pd
import numpy as np
from pathlib import Path
import hashlib

# ===== Paths =====
in_csv = Path('data/sysmon_raw.csv')
out_csv = Path('data/features.csv')

# ===== Load data safely =====
try:
    df = pd.read_csv(in_csv, encoding='utf-8', on_bad_lines='skip')
except UnicodeDecodeError:
    df = pd.read_csv(in_csv, encoding='utf-16', on_bad_lines='skip')

print(f"[+] Loaded {len(df)} rows from {in_csv}")

# ===== Safe column creation =====
for col in ['CommandLine', 'Image', 'ParentImage', 'DestinationIp']:
    if col not in df.columns:
        df[col] = ''
    df[col] = df[col].fillna('')

# ===== Hash bucket for parent process =====
def parent_bucket(val, buckets=64):
    if pd.isna(val) or val == '':
        return 0
    h = int(hashlib.md5(str(val).encode('utf-8')).hexdigest()[:8], 16)
    return h % buckets

# ===== Feature extraction =====
df['cmd_len'] = df['CommandLine'].str.len().fillna(0)

df['has_powershell'] = (
    df['CommandLine'].str.contains('powershell', case=False, na=False) |
    df['Image'].str.contains('powershell', case=False, na=False)
).astype(int)

df['in_temp'] = (
    df['Image'].str.lower().str.contains(r'\\temp\\', na=False) |
    df['Image'].str.lower().str.contains(r'appdata\\local\\temp', na=False)
).astype(int)

if 'DestinationIp' in df.columns:
    df['has_network'] = (~df['DestinationIp'].isna()) & (df['DestinationIp'] != '')
else:
    df['has_network'] = 0
df['has_network'] = df['has_network'].astype(int)

df['parent_bucket'] = df['ParentImage'].apply(parent_bucket)

# ===== Time feature =====
if 'time' in df.columns:
    ts_col = 'time'
elif 'Time' in df.columns:
    ts_col = 'Time'
else:
    ts_col = None

if ts_col:
    try:
        df['ts'] = pd.to_datetime(df[ts_col], errors='coerce')
        df['hour'] = df['ts'].dt.hour.fillna(0).astype(int)
    except Exception as e:
        print("[-] Time parsing error:", e)
        df['hour'] = 0
else:
    df['hour'] = 0

# ===== Select final features =====
feature_cols = ['cmd_len', 'has_powershell', 'in_temp', 'has_network', 'parent_bucket', 'hour']
feat_df = df[feature_cols].fillna(0).astype(float)

# ===== Save features =====
out_csv.parent.mkdir(parents=True, exist_ok=True)
feat_df.to_csv(out_csv, index=False)
print(f"[+] Saved {len(feat_df)} feature rows to {out_csv}")

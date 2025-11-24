import pandas as pd

# CAU HINH
LOG_FILE = "/home/minhbui/DATN_Quy/xdp_project/data/traffic_log.csv"
TARGET_IP = "192.168.10.103" # IP trong log cua ban
TARGET_PORT = 22             # Port SSH

print(f"🚀 Dang doc file: {LOG_FILE}...")
try:
    df = pd.read_csv(LOG_FILE, low_memory=False)
except FileNotFoundError:
    print("❌ Loi: Khong tim thay file!"); exit()

# Tim ten cot
label_col = df.columns[-1]
# Cot port dich (thuong la cot thu 5, index 4)
dst_port_col = df.columns[4] 
# Cot ip nguon (thuong la cot thu 2, index 1)
src_ip_col = df.columns[1]

print(f"🔍 Dang tim traffic SSH tu IP {TARGET_IP}...")

# Tao bo loc: Dung IP do va Dung Port 22
mask = (
    (df[src_ip_col] == TARGET_IP) & 
    (df[dst_port_col] == TARGET_PORT)
)

count = mask.sum()

if count > 0:
    print(f"😈 Tim thay {count} dong SSH 'sach'. Dang dau doc thanh 'ATTACK'...")
    
    # Sua nhan thanh ATTACK
    df.loc[mask, label_col] = "ATTACK"
    
    # Luu lai
    df.to_csv(LOG_FILE, index=False)
    print("✅ XONG! AI bay gio se nghi SSH la hanh vi nguy hiem.")
else:
    print("ℹ️ Khong tim thay dong nao khop yeu cau.")
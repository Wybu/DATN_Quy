import csv
import time
import random

# DUONG DAN FILE (Nho chinh lai neu can)
OUTPUT_FILE = "/home/quyna/Downloads/DATN_Quy/xdp_project/data/traffic_log.csv"
START_TIME_NS = int(time.time() * 1e9)
DURATION_PER_PHASE = 60 # 60 giay moi pha

def generate_row(timestamp, mode="NORMAL"):
    src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    dst_ip = "192.168.5.134"
    src_port = random.randint(1024, 65535)
    
    # --- KICH BAN HOAN TOAN TRUNG LAP ---
    
    if mode == "HEAVY_USER": 
        # Nguoi dung that dang tai file/xem phim
        # PPS: 500 - 1000
        # Flags: ACK
        dst_port = 443
        protocol = 6
        flags = 16 # ACK
        flag_desc = "ACK"
        length = random.randint(500, 1500)
        label = "NORMAL"

    elif mode == "MIMICRY_ATTACK": 
        # Hacker gia mao y het nguoi dung
        # PPS: 500 - 1000 (Giong het!)
        # Flags: ACK (Giong het!)
        dst_port = 443
        protocol = 6
        flags = 16 # ACK
        flag_desc = "ACK"
        length = random.randint(500, 1500) # Giong het!
        label = "ATTACK" # Nhan la Attack nhung hanh vi thi nhu Normal

    return [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, flag_desc, label]

print(f"🚀 Dang tao du lieu 'CHAOS MODE' (Trung lap hoan toan)...")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label'])
    current_time = START_TIME_NS

    # 1. NORMAL (HEAVY USER)
    print("Phase 1: Heavy Normal Users (PPS 500-1000)...")
    for _ in range(DURATION_PER_PHASE):
        # Random PPS trong khoang 500-1000
        for _ in range(random.randint(500, 1000)):
            writer.writerow(generate_row(current_time, "HEAVY_USER"))
        current_time += 1_000_000_000

    # 2. ATTACK (MIMICRY)
    print("Phase 2: Mimicry Attack (PPS 500-1000)...")
    for _ in range(DURATION_PER_PHASE):
        # Random PPS CUNG trong khoang 500-1000 -> Trung lap hoan toan
        for _ in range(random.randint(500, 1000)):
            writer.writerow(generate_row(current_time, "MIMICRY_ATTACK"))
        current_time += 1_000_000_000

print("✅ Xong! Du lieu nay AI se phai doan mo.")
print("👉 Chay dataprep.py va model.py di, dam bao Accuracy se tut!")
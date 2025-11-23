import csv
import time
import random

# DUONG DAN FILE
OUTPUT_FILE = "/home/quyna/Downloads/DATN_Quy/xdp_project/data/traffic_log.csv"

START_TIME_NS = int(time.time() * 1e9)
DURATION_PER_PHASE = 50 # 50 giay cho moi loai

def generate_row(timestamp, mode="NORMAL"):
    src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    dst_ip = "192.168.5.134"
    src_port = random.randint(1024, 65535)
    
    if mode == "NORMAL":
        dst_port = random.choice([80, 443, 53, 22])
        protocol = 6
        flags = random.choice([16, 24, 18]) # ACK, PSH-ACK...
        flag_desc = "ACK"
        length = random.randint(64, 1500)
        label = "NORMAL"
        
    elif mode == "HEAVY_NORMAL": # Nguoi dung xem Youtube 4K (Normal nhung PPS cao)
        dst_port = 443
        protocol = 6
        flags = 16 # ACK
        flag_desc = "ACK"
        length = 1400 # Goi tin to
        label = "NORMAL"

    elif mode == "LOW_ATTACK": # Tan cong cham (Attack nhung PPS thap)
        dst_port = 80
        protocol = 6
        flags = 2 # SYN
        flag_desc = "SYN"
        length = 64
        label = "ATTACK"
        
    return [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, flag_desc, label]

print(f"🚀 Dang tao du lieu 'Hard Mode' tai: {OUTPUT_FILE}")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label'])

    current_time = START_TIME_NS

    # 1. NORMAL THUONG (PPS: 10-50)
    print("... Phase 1: Normal (Low traffic)...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(10, 50)):
            writer.writerow(generate_row(current_time, "NORMAL"))
        current_time += 1_000_000_000

    # 2. HEAVY NORMAL (PPS: 300-500) -> Gay nhieu cho Model
    print("... Phase 2: Heavy Normal (High traffic - Video Streaming)...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(300, 500)):
            writer.writerow(generate_row(current_time, "HEAVY_NORMAL"))
        current_time += 1_000_000_000

    # 3. LOW RATE ATTACK (PPS: 200-400) -> Lan lon voi Heavy Normal
    print("... Phase 3: Low Rate Attack (Stealthy DDoS)...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(200, 400)):
            writer.writerow(generate_row(current_time, "LOW_ATTACK"))
        current_time += 1_000_000_000
    
    # 4. FLOOD ATTACK (PPS: 2000) -> De phat hien
    print("... Phase 4: Standard Flood Attack...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(2000, 2500)):
            writer.writerow(generate_row(current_time, "LOW_ATTACK")) # Reuse ham nhung tang so luong vong lap
        current_time += 1_000_000_000

print("✅ Xong! Du lieu nay se lam Accuracy giam xuong.")
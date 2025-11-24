import csv
import time
import random
import ipaddress
import numpy as np

# CAU HINH
OUTPUT_FILE = "/home/minhbui/DATN_Quy/xdp_project/data/traffic_log1.csv"
START_TIME = int(time.time()) - 86400
CURRENT_TIME_NS = START_TIME * 1_000_000_000

def generate_row(timestamp, mode="NORMAL"):
    src_ip = f"192.168.1.{random.randint(1, 254)}"
    dst_ip = "192.168.5.134"
    src_port = random.randint(1024, 65535)
    
    # --- KICH BAN HOAN TOAN TRUNG LAP (Impossible to distinguish) ---
    
    if mode == "NORMAL_IPERF": 
        # Nguoi dung test mang (iPerf)
        # PPS: 2000, Len: 1400-1500, ACK
        dst_port = 5201 # Port iPerf
        protocol = 6
        flags = 16 # ACK
        flag_desc = "ACK"
        length = random.randint(1400, 1500) # Goi to
        label = "NORMAL"

    elif mode == "ATTACK_MIMIC": 
        # Hacker gia mao iPerf (Attack giong het Normal)
        # PPS: 2000, Len: 1400-1500, ACK
        dst_port = 443 # Tan cong vao web server
        protocol = 6
        flags = 16 # ACK
        flag_desc = "ACK"
        length = random.randint(1400, 1500) # Goi to y het!
        label = "ATTACK"

    return [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, flag_desc, label]

print(f"🚀 Dang tao Dataset 'IMPOSSIBLE'...")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label'])
    
    # 1. NORMAL (IPERF) - 300s
    print("Phase 1: Normal iPerf Users...")
    for _ in range(300):
        for _ in range(2000): # PPS 2000
            writer.writerow(generate_row(CURRENT_TIME_NS, "NORMAL_IPERF"))
        CURRENT_TIME_NS += 1_000_000_000

    # 2. ATTACK (MIMIC) - 300s
    # Chi khac moi cai Port dich (nhung Random Forest it khi dua vao port cu the neu khong duoc day ky)
    print("Phase 2: Mimicry Attack (Big Packets)...")
    for _ in range(300):
        for _ in range(2000): # PPS 2000
            writer.writerow(generate_row(CURRENT_TIME_NS, "ATTACK_MIMIC"))
        CURRENT_TIME_NS += 1_000_000_000

print("✅ XONG! Chay dataprep va model di, Accuracy se giam!")
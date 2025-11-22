import csv
import time
import random

# CẤU HÌNH ĐƯỜNG DẪN (Trỏ đúng vào file data của bạn)
OUTPUT_FILE = "/home/quyna/Desktop/DATN_Quy/xdp_project/data/traffic_log.csv"

# Cấu hình giả lập
NORMAL_DURATION = 30  # Giả lập 30 giây bình thường
ATTACK_DURATION = 30  # Giả lập 30 giây tấn công
START_TIME_NS = int(time.time() * 1e9) # Thời gian bắt đầu (nanosecond)

def generate_row(timestamp, is_attack=False):
    """Hàm tạo ra 1 dòng log giả"""
    src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    dst_ip = "192.168.5.134" # IP máy nạn nhân
    src_port = random.randint(1024, 65535)
    
    if not is_attack:
        # --- TRAFFIC BÌNH THƯỜNG ---
        dst_port = random.choice([80, 443, 53, 22])
        protocol = 6 # TCP
        # Normal traffic thường là ACK (16) hoặc PSH|ACK (24)
        flags = random.choice([16, 24, 18]) 
        flag_desc = "ACK" if flags==16 else "PSH|ACK"
        length = random.randint(64, 1500) # Kích thước ngẫu nhiên
        label = "NORMAL"
    else:
        # --- TRAFFIC TẤN CÔNG (SYN FLOOD) ---
        dst_port = 80 # Tấn công tập trung vào 1 cổng
        protocol = 6
        flags = 2 # Chỉ có SYN
        flag_desc = "SYN"
        length = 64 # Gói tin nhỏ để spam nhanh
        label = "SYN_FLOOD_ATTACK"
        
    return [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, flag_desc, label]

print(f"🚀 Đang tạo dữ liệu giả tại: {OUTPUT_FILE}")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    # Ghi Header chuẩn
    writer.writerow(['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label'])

    current_time = START_TIME_NS

    # 1. GIAI ĐOẠN BÌNH THƯỜNG (30s)
    print("... Đang tạo 30s traffic bình thường (Normal)...")
    for _ in range(NORMAL_DURATION):
        # Mỗi giây chỉ có khoảng 10-50 gói tin (Traffic thấp)
        packets_per_sec = random.randint(10, 50)
        for _ in range(packets_per_sec):
            row = generate_row(current_time, is_attack=False)
            writer.writerow(row)
        current_time += 1_000_000_000 # Tăng 1 giây

    # 2. GIAI ĐOẠN TẤN CÔNG (30s)
    print("... Đang tạo 30s traffic tấn công (DDoS SYN Flood)...")
    for _ in range(ATTACK_DURATION):
        # Mỗi giây có 2000-3000 gói tin (Traffic cực cao -> DDoS)
        packets_per_sec = random.randint(2000, 3000)
        for _ in range(packets_per_sec):
            row = generate_row(current_time, is_attack=True)
            writer.writerow(row)
        current_time += 1_000_000_000 # Tăng 1 giây

print("✅ Đã xong! File log bây giờ đã có cả Normal và Attack.")
print("👉 Hãy chạy lại dataprep.py và model.py ngay!")
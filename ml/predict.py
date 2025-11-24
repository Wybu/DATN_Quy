import time
import joblib
import pandas as pd
import os
import sys
from collections import Counter

# --- CAU HINH ---
LOG_FILE = "/home/minhbui/DATN_Quy/xdp_project/data/traffic_log.csv"
MODEL_FILE = "rf_model.pkl"

FEATURE_COLS = ['pps', 'bps', 'avg_len', 'syn_count', 'unique_dst_ports', 'syn_rate']

def load_model():
    print(f"Dang load model tu {MODEL_FILE}...")
    try:
        return joblib.load(MODEL_FILE)
    except:
        print("Loi: Khong tim thay model!"); sys.exit(1)

def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def extract_features(window_packets):
    """Tinh feature cho AI"""
    count = len(window_packets)
    if count == 0: return None
    total_len = 0
    syn_count = 0
    dst_ports = set()
    
    for pkt in window_packets:
        try:
            parts = pkt.strip().split(',')
            total_len += int(parts[6]) # length
            dst_ports.add(parts[4])    # dst_port
            if int(parts[7]) == 2:     # flags == SYN
                syn_count += 1
        except: continue

    df = pd.DataFrame([[count, total_len, total_len/count, syn_count, len(dst_ports), syn_count/count]], 
                      columns=FEATURE_COLS)
    return df

def analyze_attacker(window_packets, features_df):
    """
    PHAN LOAI TAN CONG LAYER 3 & 4 CHUYEN SAU
    """
    src_ips = []
    dst_ports = set()
    
    # Counter cho cac giao thuc
    proto_counts = {1: 0, 6: 0, 17: 0} # 1:ICMP, 6:TCP, 17:UDP
    
    # Counter cho TCP Flags
    flag_counts = {'SYN': 0, 'ACK': 0, 'RST': 0, 'FIN': 0, 'OTHER': 0}
    
    total_packets = len(window_packets)
    if total_packets == 0: return "Unknown"

    for pkt in window_packets:
        try:
            parts = pkt.strip().split(',')
            # Format: ts, src, dst, sport, dport, proto, len, flags, ...
            src_ip = parts[1]
            dst_port = parts[4]
            proto = int(parts[5])
            flags = int(parts[7])
            
            src_ips.append(src_ip)
            dst_ports.add(dst_port)
            
            # Dem Protocol
            if proto in proto_counts:
                proto_counts[proto] += 1
            
            # Dem TCP Flags (Chi xet neu la TCP)
            if proto == 6:
                if flags == 2: flag_counts['SYN'] += 1
                elif flags == 16: flag_counts['ACK'] += 1
                elif flags & 4: flag_counts['RST'] += 1 # RST (4)
                elif flags & 1: flag_counts['FIN'] += 1 # FIN (1)
                else: flag_counts['OTHER'] += 1
                
        except: continue
    
    # --- 1. TIM THU PHAM (IP) ---
    from collections import Counter
    if src_ips:
        top_ip, count = Counter(src_ips).most_common(1)[0]
        # Neu IP nay chiem > 90% traffic -> DDoS don le
        # Neu khong -> DDoS Botnet (Nhieu IP)
        attacker_label = top_ip
        if count < total_packets * 0.5:
            attacker_label = "Botnet/Spoofed IPs"
    else:
        attacker_label = "Unknown"

    # --- 2. PHAN LOAI TAN CONG (DECISION TREE LOGIC) ---
    attack_type = "Unknown Anomaly"
    
    # Ty le phan tram
    icmp_rate = proto_counts[1] / total_packets
    udp_rate = proto_counts[17] / total_packets
    tcp_rate = proto_counts[6] / total_packets
    unique_ports = len(dst_ports)

    # --- LAYER 3 ATTACKS ---
    if icmp_rate > 0.5:
        attack_type = "L3: ICMP Flood"
    
    # --- LAYER 4 ATTACKS ---
    elif udp_rate > 0.5:
        attack_type = "L4: UDP Volumetric Flood"
        
    elif unique_ports > 8:
        # Quet cong thuong dung TCP hoac UDP, nhung dac diem chinh la nhieu cong
        attack_type = "L4: Port Scanning"
        
    elif tcp_rate > 0.5:
        # Di sau vao TCP Flags
        syn_r = flag_counts['SYN'] / proto_counts[6]
        ack_r = flag_counts['ACK'] / proto_counts[6]
        rst_r = flag_counts['RST'] / proto_counts[6]
        fin_r = flag_counts['FIN'] / proto_counts[6]
        
        if syn_r > 0.5:
            attack_type = "L4: TCP SYN Flood"
        elif ack_r > 0.5:
            attack_type = "L4: TCP ACK Flood"
        elif rst_r > 0.5 or fin_r > 0.5:
            attack_type = "L4: TCP RST/FIN Flood"
        else:
            attack_type = "L4: TCP Malformed Flood"

    return f"{attacker_label} -> {attack_type}"

def main():
    model = load_model()
    print(f"Dang giam sat: {LOG_FILE}")
    print("-" * 75)
    print(f"{'THOI GIAN':<10} | {'PPS':<5} | {'SYN%':<5} | {'TRANG THAI':<15} | {'THU PHAM (IP)'}")
    print("-" * 75)

    logfile = open(LOG_FILE, "r")
    current_window = []
    last_second = None
    BATCH_LIMIT = 1000 #doc duoc 1000 goi la phai in ra ngay, giup giam sat muot hon

    for line in follow(logfile):
        try:
            parts = line.split(',')
            if not parts[0].isdigit(): continue
            
            ts_ns = int(parts[0])
            current_second = ts_ns // 1_000_000_000
            
            if last_second is None: last_second = current_second

            is_new_second = (current_second != last_second)
            is_buffer_full = (len(current_window) >= BATCH_LIMIT)

            if is_new_second or is_buffer_full:
                if current_window:
                    # 1. Trich xuat feature
                    feats = extract_features(current_window)
                    
                    if feats is not None:
                        # 2. Du doan
                        pred = model.predict(feats)[0]
                        
                        # Hien thi
                        pps = feats['pps'][0]
                        syn_rate = feats['syn_rate'][0]
                        
                        # Neu buffer day thi danh dau (*) ben canh PPS de biet day la so lieu 1 phan
                        note = "*" if is_buffer_full else "" 
                        
                        if pred == 1:
                            culprit = analyze_attacker(current_window, feats)
                            status = "!!! TAN CONG !!!"
                            print(f"\033[91m{last_second} | {pps:<5.0f}{note} | {syn_rate:.2f} | {status:<15} | {culprit}\033[0m")
                        else:
                            # In binh thuong
                            print(f"{last_second} | {pps:<5.0f}{note} | {syn_rate:.2f} | {'Binh Thuong':<15} | -")

                # Reset buffer
                current_window = []
                
                # Chi cap nhat thoi gian neu thuc su da sang giay moi
                if is_new_second:
                    last_second = current_second
            
            # Them dong hien tai vao buffer
            current_window.append(line)

        except Exception: continue
if __name__ == "__main__":
    main()
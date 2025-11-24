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

def analyze_attacker(window_packets):
    """
    quet lai log de tim IP thu pham.
    """
    src_ips = []
    syn_ips = []
    
    for pkt in window_packets:
        try:
            parts = pkt.strip().split(',')
            src_ip = parts[1]
            flags = int(parts[7])
            
            src_ips.append(src_ip)
            if flags == 2: # SYN
                syn_ips.append(src_ip)
        except: continue
    
    if not src_ips: return "Khong xac dinh"

    # 1. Tim IP gui nhieu goi nhat (Top Talker)
    top_ip, count = Counter(src_ips).most_common(1)[0]
    
    # 2. Tim IP gui nhieu SYN nhat (Neu co)
    reason = "Flood Volume"
    if syn_ips:
        top_syn_ip, syn_c = Counter(syn_ips).most_common(1)[0]
        if syn_c > count * 0.5: # Neu SYN chiem qua ban
            top_ip = top_syn_ip
            reason = "SYN Flood"
            
    return f"{top_ip} ({reason})"

def main():
    model = load_model()
    print(f"Dang giam sat: {LOG_FILE}")
    print("-" * 75)
    print(f"{'THOI GIAN':<10} | {'PPS':<5} | {'SYN%':<5} | {'TRANG THAI':<15} | {'THU PHAM (IP)'}")
    print("-" * 75)

    logfile = open(LOG_FILE, "r")
    current_window = []
    last_second = None

    for line in follow(logfile):
        try:
            parts = line.split(',')
            if not parts[0].isdigit(): continue
            
            ts_ns = int(parts[0])
            current_second = ts_ns // 1_000_000_000
            
            if last_second is None: last_second = current_second

            if current_second == last_second:
                current_window.append(line)
            else:
                if current_window:
                    feats = extract_features(current_window)
                    if feats is not None:
                        # DU DOAN
                        pred = model.predict(feats)[0]
                        
                        pps = feats['pps'][0]
                        syn_rate = feats['syn_rate'][0]
                        
                        if pred == 1:
                            # --- NEU LA TAN CONG -> GOI CONAN DIEU TRA NGAY ---
                            culprit = analyze_attacker(current_window)
                            status = "!!! TAN CONG !!!"
                            # In mau do
                            print(f"\033[91m{last_second} | {pps:<5} | {syn_rate:.2f} | {status:<15} | {culprit}\033[0m")
                        else:
                            # In binh thuong
                            print(f"{last_second} | {pps:<5} | {syn_rate:.2f} | {'Binh Thuong':<15} | -")

                current_window = [line]
                last_second = current_second

        except Exception: continue

if __name__ == "__main__":
    main()
# machinelearning/dataprep.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# CẤU HÌNH ĐƯỜNG DẪN
RAW_LOG_PATH = "../xdp_project/data/traffic_log.csv"
OUTPUT_TRAIN = "train_data.csv"
OUTPUT_TEST = "test_data.csv"

def load_and_process_data(filepath):
    print(f"Dang doc du lieu tu {filepath}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print("Loi: Khong tim thay file log. Hay chay collector.py truoc!")
        return None

    # --- ĐOẠN CODE MỚI THÊM ĐỂ FIX LỖI ---
    # 1. Xóa khoảng trắng thừa ở tên cột (VD: " timestamp" -> "timestamp")
    df.columns = df.columns.str.strip()
    
    # 2. In ra các cột đang có để kiểm tra
    print(f"🔍 Cac cot tim thay trong file CSV: {df.columns.tolist()}")

    # 3. Tự động đổi tên cột về chuẩn 'timestamp_ns'
    # Nếu cột tên là 'ts' hoặc 'timestamp' -> đổi thành 'timestamp_ns'
    if 'ts' in df.columns:
        print("⚠️ Phat hien cot 'ts', dang doi ten thanh 'timestamp_ns'...")
        df.rename(columns={'ts': 'timestamp_ns'}, inplace=True)
    elif 'timestamp' in df.columns:
        print("⚠️ Phat hien cot 'timestamp', dang doi ten thanh 'timestamp_ns'...")
        df.rename(columns={'timestamp': 'timestamp_ns'}, inplace=True)
        
    # Kiểm tra lần cuối
    if 'timestamp_ns' not in df.columns:
        print("❌ LOI NGHIEM TRONG: Khong tim thay cot thoi gian!")
        print("Hay xoa file traffic_log.csv va chay lai collector.py")
        return None
    # -------------------------------------

    # 4. Chuyen timestamp tu nanoseconds sang datetime
    try:
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='ns')
    except Exception as e:
        # Fallback: Nếu unit='ns' lỗi (do số quá nhỏ), thử unit='s'
        print("⚠️ Timestamp co the dang o dang giay (seconds), dang thu convert lai...")
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='s')
        
    df = df.set_index('datetime')

    print("Dang trich xuat dac trung (Feature Engineering)...")
    
    # ... (Phần còn lại giữ nguyên) ...
    # Gom nhom theo tung giay (1 Second Window)
    df_resampled = df.resample('1S').agg({
        'length': ['count', 'sum', 'mean'],     
        'tcp_flags_raw': lambda x: (x == 2).sum(), 
        'dst_port': 'nunique'                   
    })

    # Lam phang MultiIndex columns
    df_resampled.columns = ['pps', 'bps', 'avg_len', 'syn_count', 'unique_dst_ports']
    
    # Loai bo cac giay khong co traffic
    df_resampled = df_resampled[df_resampled['pps'] > 0].copy()

    # Tao them Feature phai sinh
    df_resampled['syn_rate'] = df_resampled['syn_count'] / df_resampled['pps']

    return df_resampled

if __name__ == "__main__":
    # Chạy quy trình
    df_features = load_and_process_data(RAW_LOG_PATH)
    
    if df_features is not None:
        df_labeled = auto_label_data(df_features)
        
        # Chia train/test (80% train, 20% test)
        X = df_labeled.drop('label', axis=1)
        y = df_labeled['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Gộp lại để lưu file CSV
        train_set = pd.concat([X_train, y_train], axis=1)
        test_set = pd.concat([X_test, y_test], axis=1)
        
        train_set.to_csv(OUTPUT_TRAIN, index=False)
        test_set.to_csv(OUTPUT_TEST, index=False)
        
        print(f"✅ Đã xong! Dữ liệu lưu tại {OUTPUT_TRAIN} và {OUTPUT_TEST}")
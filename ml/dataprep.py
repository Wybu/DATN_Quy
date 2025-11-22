import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# CAU HINH DUONG DAN
# Dung duong dan tuyet doi de khong bao gio loi
RAW_LOG_PATH = "/home/quyna/Desktop/DATN_Quy/xdp_project/data/traffic_log.csv"
OUTPUT_TRAIN = "train_data.csv"
OUTPUT_TEST = "test_data.csv"

def load_and_process_data(filepath):
    print(f"Dang doc du lieu tu {filepath}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print("Loi: Khong tim thay file log!")
        return None

    # --- 1. CHUAN HOA TEN COT (Mapping) ---
    # Xu ly bat chap ten cot la cu hay moi
    df.columns = df.columns.str.strip().str.lower() # Xoa khoang trang, viet thuong het
    
    rename_map = {
        'ts': 'timestamp_ns',
        'timestamp': 'timestamp_ns',
        'len': 'length',           # Fix loi KeyError: 'length'
        'pkt_len': 'length',
        'flags': 'tcp_flags_raw',  # Fix loi KeyError: 'tcp_flags_raw'
        'tcp_flags': 'tcp_flags_raw',
        'proto': 'protocol',
        'src': 'src_ip',
        'dst': 'dst_ip'
    }
    df.rename(columns=rename_map, inplace=True)
    
    print(f"🔍 Cac cot sau khi chuan hoa: {df.columns.tolist()}")

    # --- 2. XU LY LABEL TU FILE CSV (Neu co) ---
    # Neu trong file CSV da co cot 'label' (vd: NORMAL, SYN_SCAN...)
    # Chung ta se chuyen no thanh so: 0 (Binh thuong), 1 (Tan cong)
    if 'label' in df.columns:
        print("⚠️ Phat hien cot Label co san trong CSV. Dang chuan hoa...")
        # Chuyen cac nhan text thanh so
        # NORMAL -> 0, moi thu khac -> 1
        df['label_is_attack'] = df['label'].apply(lambda x: 0 if str(x).strip().upper() == 'NORMAL' else 1)
    else:
        df['label_is_attack'] = 0 # Mac dinh la 0 neu chua co

    # --- 3. XU LY THOI GIAN ---
    try:
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='ns')
    except:
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='s')
    
    df = df.set_index('datetime')

    print("Dang trich xuat dac trung (Feature Engineering)...")
    
    # --- 4. GOM NHOM THEO GIAY (RESAMPLE) ---
    # Dictionary quy dinh cach gom nhom
    agg_dict = {
        'length': ['count', 'sum', 'mean'],     # PPS, BPS, Avg Len
        'tcp_flags_raw': lambda x: (x == 2).sum(), # Dem so goi SYN
        'dst_port': 'nunique',                  # Dem so port
        'label_is_attack': 'max'                # Lay max label (neu trong 1 giay co 1 goi attack -> ca giay la attack)
    }

    # Chi gom nhom cac cot thuc su ton tai de tranh loi
    agg_rules = {k: v for k, v in agg_dict.items() if k in df.columns}

    df_resampled = df.resample('1S').agg(agg_rules)

    # Doi ten cot cho dep
    new_columns = []
    if 'length' in df.columns:
        new_columns.extend(['pps', 'bps', 'avg_len'])
    if 'tcp_flags_raw' in df.columns:
        new_columns.append('syn_count')
    if 'dst_port' in df.columns:
        new_columns.append('unique_dst_ports')
    if 'label_is_attack' in df.columns:
        new_columns.append('label') # Cot nay se dung lam nhan huan luyen

    df_resampled.columns = new_columns
    
    # Loai bo giay khong co traffic
    if 'pps' in df_resampled.columns:
        df_resampled = df_resampled[df_resampled['pps'] > 0].copy()
        
        # Tao them Feature: SYN Rate
        if 'syn_count' in df_resampled.columns:
            df_resampled['syn_rate'] = df_resampled['syn_count'] / df_resampled['pps']
            # Fill NaN bang 0 (truong hop pps=0)
            df_resampled['syn_rate'] = df_resampled['syn_rate'].fillna(0)

    return df_resampled

if __name__ == "__main__":
    df_features = load_and_process_data(RAW_LOG_PATH)
    
    if df_features is not None:
        print(f"📊 So luong mau sau khi xu ly: {len(df_features)}")
        
        # Kiem tra xem co cot label khong
        if 'label' not in df_features.columns:
            print("⚠️ KHONG tim thay thong tin Label tu file CSV.")
            print("-> Se su dung quy tac tu dong (Auto-labeling) thay the.")
            # ... Code auto label du phong o day neu can ...
            conditions = [
                (df_features['pps'] > 1000) | 
                ((df_features.get('syn_rate', 0) > 0.9) & (df_features['pps'] > 100))
            ]
            df_features['label'] = np.select(conditions, [1], default=0)

        # Thong ke Label
        print(f"   + So mau Normal (0): {len(df_features[df_features['label']==0])}")
        print(f"   + So mau Attack (1): {len(df_features[df_features['label']==1])}")

        # Chia train/test
        X = df_features.drop('label', axis=1)
        y = df_features['label']
        
        # Fill NaN neu co de tranh loi Model
        X = X.fillna(0)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        train_set = pd.concat([X_train, y_train], axis=1)
        test_set = pd.concat([X_test, y_test], axis=1)
        
        train_set.to_csv(OUTPUT_TRAIN, index=False)
        test_set.to_csv(OUTPUT_TEST, index=False)
        
        print(f"✅ XONG! Da tao file {OUTPUT_TRAIN} va {OUTPUT_TEST}")
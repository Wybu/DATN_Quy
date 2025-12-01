import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os

# CAU HINH DUONG DAN
RAW_LOG_PATH = "/home/minhbui/DATN_Quy/xdp_project/data/traffic_log2.csv"
OUTPUT_TRAIN = "train_data.csv"
OUTPUT_TEST = "test_data.csv"

def load_and_process_data(filepath):
    print(f"Dang doc du lieu tu {filepath}...")
    
    # 1. FIX LOI DtypeWarning 
    # low_memory=False giup pandas doc file tot hon voi cac cot lon xon
    try:
        df = pd.read_csv(filepath, low_memory=False)
    except FileNotFoundError:
        print("Loi: Khong tim thay file log!")
        return None

    # 2. CHUAN HOA TEN COT VA THEM HEADER
    # Xu ly truong hop file thieu header
    if str(df.columns[0]).isdigit():
        print("Thieu Header. Dang tu dong gan ten cot...")
        expected_cols = ['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                         'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label']
        # Chi lay so luong cot tuong ung
        df.columns = expected_cols[:len(df.columns)]
    else:
        # Chuan hoa ten cot ve chu thuong, xoa khoang trang
        df.columns = df.columns.str.strip().str.lower()
        rename_map = {
            'ts': 'timestamp_ns', 'timestamp': 'timestamp_ns',
            'len': 'length', 'pkt_len': 'length',
            'flags': 'tcp_flags_raw', 'tcp_flags': 'tcp_flags_raw',
            'proto': 'protocol', 'src': 'src_ip', 'dst': 'dst_ip'
        }
        df.rename(columns=rename_map, inplace=True)

    print(f"🔍 Cac cot tim thay: {df.columns.tolist()}")

    # 3. XU LY LABEL 
    if 'label' in df.columns:
        # Chuyen het ve string roi moi so sanh de tranh loi
        df['label'] = df['label'].astype(str).str.strip().str.upper()
        df['label_is_attack'] = df['label'].apply(lambda x: 0 if x == 'NORMAL' else 1)
    else:
        df['label_is_attack'] = 0

    # 4. XU LY THOI GIAN VA LOC DU LIEU
    # Chuyen timestamp ve datetime
    try:
        # Ep kieu ve so
        df['timestamp_ns'] = pd.to_numeric(df['timestamp_ns'], errors='coerce')
        df = df.dropna(subset=['timestamp_ns']) # Xoa dong loi
        
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='ns')
    except:
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='s')
    
   
   
    current_year = pd.Timestamp.now().year
    # Loc bo nhung dong co nam < (Nam hien tai - 1)
    df = df[df['datetime'].dt.year >= (current_year - 1)]
    
    if df.empty:
        print("Khong co du lieu nao hop le!")
        return None
        
    print(f"So luong du lieu sach: {len(df)}")
    # -----------------------------------------------------------

    df = df.set_index('datetime')

    print("Dang trich xuat dac trung (Resampling)...")
    
    # 5. GOM NHOM (RESAMPLE)
    agg_rules = {}
    if 'length' in df.columns: agg_rules['length'] = ['count', 'sum', 'mean']
    if 'tcp_flags_raw' in df.columns: agg_rules['tcp_flags_raw'] = lambda x: (x == 2).sum()
    if 'dst_port' in df.columns: agg_rules['dst_port'] = 'nunique'
    if 'label_is_attack' in df.columns: agg_rules['label_is_attack'] = 'max'

    if not agg_rules: 
        print("Khong tim thay cac cot can thiet de feature engineering")
        return None

    df_resampled = df.resample('1S').agg(agg_rules)

    # Doi ten cot
    new_columns = []
    if 'length' in df.columns: new_columns.extend(['pps', 'bps', 'avg_len'])
    if 'tcp_flags_raw' in df.columns: new_columns.append('syn_count')
    if 'dst_port' in df.columns: new_columns.append('unique_dst_ports')
    if 'label_is_attack' in df.columns: new_columns.append('label')

    df_resampled.columns = new_columns
    
    # Loai bo giay khong co traffic
    if 'pps' in df_resampled.columns:
        df_resampled = df_resampled[df_resampled['pps'] > 0].copy()
        
        # Tinh SYN Rate
        if 'syn_count' in df_resampled.columns:
            df_resampled['syn_rate'] = df_resampled['syn_count'] / df_resampled['pps']
            df_resampled['syn_rate'] = df_resampled['syn_rate'].fillna(0)

    return df_resampled

if __name__ == "__main__":
    df_features = load_and_process_data(RAW_LOG_PATH)
    
    if df_features is not None:
        print(f"So luong mau sau khi xu ly: {len(df_features)}")
        
        # Auto-label neu chua co label
        if 'label' not in df_features.columns:
            conditions = [
                (df_features['pps'] > 1000) | 
                ((df_features.get('syn_rate', 0) > 0.9) & (df_features['pps'] > 100))
            ]
            df_features['label'] = np.select(conditions, [1], default=0)

        print(f"   + Normal (0): {len(df_features[df_features['label']==0])}")
        print(f"   + Attack (1): {len(df_features[df_features['label']==1])}")

        # Chia train/test
        X = df_features.drop('label', axis=1)
        y = df_features['label']
        X = X.fillna(0)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        train_set = pd.concat([X_train, y_train], axis=1)
        test_set = pd.concat([X_test, y_test], axis=1)
        
        train_set.to_csv(OUTPUT_TRAIN, index=False)
        test_set.to_csv(OUTPUT_TEST, index=False)
        
        print(f" Da tao file {OUTPUT_TRAIN} va {OUTPUT_TEST}")
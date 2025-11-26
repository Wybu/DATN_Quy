import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os

# CAU HINH
RAW_LOG_PATH = "/home/minhbui/DATN_Quy/xdp_project/data/traffic_log2.csv"
OUTPUT_TRAIN = "train_data.csv"
OUTPUT_TEST = "test_data.csv"

def load_and_process_data(filepath):
    print(f"Dang doc du lieu tu {filepath}...")
    try:
        df = pd.read_csv(filepath, low_memory=False)
    except FileNotFoundError:
        print("Loi: Khong tim thay file log!")
        return None

    # 1. CHUAN HOA TEN COT
    if str(df.columns[0]).isdigit(): # Xu ly truong hop file khong co header
        expected_cols = ['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label']
        df.columns = expected_cols[:len(df.columns)]
    else:
        df.columns = df.columns.str.strip().str.lower()
        rename_map = {'ts': 'timestamp_ns', 'len': 'length', 'flags': 'tcp_flags_raw', 'proto': 'protocol'}
        df.rename(columns=rename_map, inplace=True)

    # 2. XU LY LABEL & CLEANING
    if 'label' in df.columns:
        df['label'] = df['label'].astype(str).str.strip().str.upper()
        df['label_is_attack'] = df['label'].apply(lambda x: 0 if x == 'NORMAL' else 1)
    else:
        df['label_is_attack'] = 0

    # 3. XU LY THOI GIAN (Loc rac nam 1970)
    try:
        df['timestamp_ns'] = pd.to_numeric(df['timestamp_ns'], errors='coerce')
        df = df.dropna(subset=['timestamp_ns']) 
        df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='ns')
    except:
        return None
    
    current_year = pd.Timestamp.now().year
    df = df[df['datetime'].dt.year >= (current_year - 1)]
    if df.empty: return None
        
    print(f"Da loc bo du lieu rac. So luong dong sach: {len(df)}")
    df = df.set_index('datetime')

    # 4. GOM NHOM (RESAMPLE - Vectorization)
    print("Dang trich xuat dac trung (Resampling)...")
    
    agg_rules = {}
    if 'length' in df.columns: agg_rules['length'] = ['count', 'sum', 'mean']
    if 'tcp_flags_raw' in df.columns: agg_rules['tcp_flags_raw'] = lambda x: (x == 2).sum() # Dem SYN
    if 'dst_port' in df.columns: agg_rules['dst_port'] = 'nunique'
    if 'label_is_attack' in df.columns: agg_rules['label_is_attack'] = 'max'

    if not agg_rules: return None

    df_resampled = df.resample('1s').agg(agg_rules) # Chú ý: dùng 's' thay vì 'S'
    
    # 5. DOI TEN COT
    new_columns = ['pps', 'bps', 'avg_len', 'syn_count', 'unique_dst_ports', 'label']
    df_resampled.columns = new_columns
    
    if 'pps' in df_resampled.columns:
        df_resampled = df_resampled[df_resampled['pps'] > 0].copy()
        if 'syn_count' in df_resampled.columns:
            df_resampled['syn_rate'] = df_resampled['syn_count'] / df_resampled['pps']

    return df_resampled

if __name__ == "__main__":
    df_features = load_and_process_data(RAW_LOG_PATH)
    
    if df_features is not None:
        X = df_features.drop('label', axis=1).fillna(0)
        y = df_features['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        train_set = pd.concat([X_train, y_train], axis=1)
        test_set = pd.concat([X_test, y_test], axis=1)
        
        train_set.to_csv(OUTPUT_TRAIN, index=False)
        test_set.to_csv(OUTPUT_TEST, index=False)
        
        print(f"XONG! Da tao file {OUTPUT_TRAIN} va {OUTPUT_TEST}")
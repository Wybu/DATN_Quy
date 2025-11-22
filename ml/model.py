import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# --- CAU HINH ---
TRAIN_DATA = "train_data.csv"
TEST_DATA = "test_data.csv"
MODEL_FILE = "rf_model.pkl"

def train_random_forest():
    print("Bat dau huan luyen Random Forest...")
    
    # 1. Load du lieu
    try:
        train_df = pd.read_csv(TRAIN_DATA)
        test_df = pd.read_csv(TEST_DATA)
    except FileNotFoundError:
        print("Loi: Khong tim thay du lieu train. Hay chay dataprep.py truoc!")
        return

    # Tach Features (X) va Label (y)
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    print(f"Du lieu train: {X_train.shape}")
    print(f"Du lieu test:  {X_test.shape}")

    # 2. Khoi tao va Train mo hinh
    # n_estimators=100: Tao ra 100 cay quyet dinh
    # n_jobs=-1: Dung tat ca nhan CPU
    print("Dang training...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)

    # 3. Danh gia mo hinh
    print("Dang danh gia tren tap Test...")
    y_pred = rf_model.predict(X_test)

    print("\n--- KET QUA DANH GIA ---")
    print(f"Do chinh xac (Accuracy): {accuracy_score(y_test, y_pred):.4f}")
    print("\nConfusion Matrix (Ma tran nham lan):")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # 4. PHAN TICH DAC TRUNG QUAN TRONG (Feature Importance)
    print("\n--- DAC TRUNG QUAN TRONG ---")
    importances = rf_model.feature_importances_
    feature_names = X_train.columns
    
    # Sap xep theo do quan trong giam dan
    indices = np.argsort(importances)[::-1]

    for i in range(X_train.shape[1]):
        print(f"{i+1}. {feature_names[indices[i]]:<20} : {importances[indices[i]]:.4f}")

    # 5. Luu model
    joblib.dump(rf_model, MODEL_FILE)
    print(f"\nModel da duoc luu tai: {MODEL_FILE}")
    print("Done!")

if __name__ == "__main__":
    train_random_forest()
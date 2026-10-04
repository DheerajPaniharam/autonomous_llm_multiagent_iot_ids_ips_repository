import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
import lightgbm as lgb


def load_and_preprocess_data(filepath="data/mock_iot_traffic.csv"):
    print(f"Loading data from {filepath}...")
    df = pd.read_csv(filepath)
    
    # Feature Engineering / Selection
    features = ['src_port', 'dst_port', 'protocol', 'packet_rate', 'byte_rate', 
                'flow_duration', 'tcp_flags', 'connection_errors']
    
    X = df[features].copy()
    y = df['attack_type'] # We will train a multi-class model
    
    # Label Encoding for categorical features
    print("Encoding categorical features...")
    le_protocol = LabelEncoder()
    X['protocol'] = le_protocol.fit_transform(X['protocol'])
    
    le_flags = LabelEncoder()
    X['tcp_flags'] = le_flags.fit_transform(X['tcp_flags'])

    # Encode target labels for model
    le_labels = LabelEncoder()
    y_enc = le_labels.fit_transform(y)
    
    # Split data
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)
    
    # Scale features
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save preprocessors for later use
    os.makedirs('models', exist_ok=True)
    joblib.dump(scaler, 'models/scaler_optimized.joblib')
    joblib.dump(le_protocol, 'models/le_protocol.joblib')
    joblib.dump(le_flags, 'models/le_flags.joblib')
    joblib.dump(le_labels, 'models/label_encoder.joblib')
    
    return X_train_scaled, X_test_scaled, y_train, y_test, le_labels


def train_lightgbm():
    X_train, X_test, y_train, y_test, le_labels = load_and_preprocess_data()
    
    print("Training LightGBM Classifier (Detection Agent)...")
    clf = lgb.LGBMClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    print("Evaluating Model...")
    y_pred = clf.predict(X_test)
    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=le_labels.classes_))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
    
    # Save the model
    model_path = 'models/lgb_model_optimized.joblib'
    joblib.dump(clf, model_path)
    print(f"\nModel saved successfully to {model_path}")


if __name__ == "__main__":
    train_lightgbm()

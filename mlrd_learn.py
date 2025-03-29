import pandas as pd
import numpy as np
import xgboost as xgb
import lightgbm as lgb
from sklearn import model_selection
from sklearn.metrics import f1_score, accuracy_score
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel

def main():
    print('\n[+] Upgrading MLRD Machine Learning Model...')

    # 데이터셋 로드 (예외 처리 추가)
    try:
        df = pd.read_csv('data_file.csv', sep=',')
    except FileNotFoundError:
        print("❌ Error: 'data_file.csv' 파일을 찾을 수 없습니다. 데이터셋을 준비하세요.")
        return

    # 데이터셋 분포 확인 (추가된 코드)
    print("\n[+] Dataset Overview:")
    print(df['Benign'].value_counts())

    # 특징 선택 및 데이터 분할
    X = df.drop(['FileName', 'md5Hash', 'Benign'], axis=1).values
    y = df['Benign'].values
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)

    print("\n[*] Training samples:", len(X_train))
    print("[*] Testing samples:", len(X_test))

    # 모델 1: 랜덤 포레스트 (데이터 불균형 해결 추가)
    rf_clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    rf_clf.fit(X_train, y_train)
    rf_score = accuracy_score(y_test, rf_clf.predict(X_test))
    rf_f1 = f1_score(y_test, rf_clf.predict(X_test))

    # 모델 2: XGBoost
    xgb_clf = xgb.XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42)
    xgb_clf.fit(X_train, y_train)
    xgb_score = accuracy_score(y_test, xgb_clf.predict(X_test))
    xgb_f1 = f1_score(y_test, xgb_clf.predict(X_test))

    # 모델 3: LightGBM
    lgb_clf = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42)
    lgb_clf.fit(X_train, y_train)
    lgb_score = accuracy_score(y_test, lgb_clf.predict(X_test))
    lgb_f1 = f1_score(y_test, lgb_clf.predict(X_test))

    print("\n[*] Model Performance:")
    print(f"  - RandomForest Accuracy: {rf_score*100:.2f}%, F1-score: {rf_f1:.2f}")
    print(f"  - XGBoost Accuracy: {xgb_score*100:.2f}%, F1-score: {xgb_f1:.2f}")
    print(f"  - LightGBM Accuracy: {lgb_score*100:.2f}%, F1-score: {lgb_f1:.2f}")

    # 🔹 최적 모델 자동 선택
    best_model = max(
        [(rf_f1, rf_clf), (xgb_f1, xgb_clf), (lgb_f1, lgb_clf)], key=lambda x: x[0]
    )[1]

    print("\n[+] Selecting best model...")
    joblib.dump(best_model, 'classifier/best_model.pkl')
    print("[*] Model saved successfully.")

    # 🔹 특징 선택 수행 (Feature Selection)
    print("\n[+] Performing feature selection...")
    feature_selector = SelectFromModel(best_model, threshold="median", prefit=True)
    X_selected = feature_selector.transform(X)

    print(f"[*] Reduced features from {X.shape[1]} to {X_selected.shape[1]}.")

if __name__ == '__main__':
    main()

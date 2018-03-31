import pandas as pd
import numpy as np
import pickle
from sklearn import model_selection
import sklearn.ensemble as ske
import sklearn.metrics
from sklearn.metrics import f1_score
from sklearn.externals import joblib


def main():
    print('\n[+] Training MLRD using Random Forest Algorithm...')
    df = pd.read_csv('data_file.csv', sep=',')
    X = df.drop(['FileName', 'md5Hash', 'Benign'], axis=1).values
    y = df['Benign'].values

    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)

    clf = ske.RandomForestClassifier(n_estimators=50)
    clf.fit(X_train, y_train)

    score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    y_train_pred = model_selection.cross_val_predict(clf, X_train, y_train, cv=3)
    f = f1_score(y_train, y_train_pred)
    print("\t[*] F1 Score: ", round(f*100, 2), '%')

    all_features = X.shape[1]
    features = []

    for feature in range(all_features):
        features.append(df.columns[2+feature])

    try:
        print("\n[+] Saving algorithm and feature list in classifier directory...")
        joblib.dump(clf, 'classifier/classifier.pkl')
        open('classifier/features.pkl', 'wb').write(pickle.dumps(features))
        print("\n[*] Saved.")
    except:
        print('\n[-] Error: Algorithm and feature list not saved correctly.\n')

if __name__ == '__main__':
    main()
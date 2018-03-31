'''
    File name: mlrd_learn.py
    Author: Callum Lock
    Date created: 31/03/2018
    Date last modified: 31/03/2018
    Python Version: 3.6
'''
import pandas as pd
import numpy as np
import pickle
from sklearn import model_selection
import sklearn.ensemble as ske
import sklearn.metrics
from sklearn.metrics import f1_score
from sklearn.externals import joblib

# Main code function that trains the random forest algorithm on dataset.
def main():
    print('\n[+] Training MLRD using Random Forest Algorithm...')

    # Creates pandas dataframe and reads in csv file.
    df = pd.read_csv('data_file.csv', sep=',')

    # Drops FileName, md5Hash and Label from data.
    X = df.drop(['FileName', 'md5Hash', 'Benign'], axis=1).values

    # Assigns y to label
    y = df['Benign'].values

    # Splitting data into training and test data
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42)

    # Print the number of training and testing samples.
    print("\n\t[*] Training samples: ", len(X_train))
    print("\t[*] Testing samples: ", len(X_test))

    # Train Random forest algorithm on training dataset.
    clf = ske.RandomForestClassifier(n_estimators=50)
    clf.fit(X_train, y_train)

    # Perform cross validation and print out accuracy.
    score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    # Calculate f1 score.
    y_train_pred = model_selection.cross_val_predict(clf, X_train, y_train, cv=3)
    f = f1_score(y_train, y_train_pred)
    print("\t[*] F1 Score: ", round(f*100, 2), '%')

    # Save the configuration of the classifier and features as a pickle file.
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

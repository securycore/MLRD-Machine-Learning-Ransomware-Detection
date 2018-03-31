import os
import numpy as np
import shutil
import re
import math
import numpy
import pandas as pd
import csv
import math
import string
import sys
import fileinput
import json
import urllib
import urllib3
import requests
import zipfile
import time
import argparse
import pickle
from termcolor import colored, cprint
import colorama
import webbrowser
import base64
from collections import Counter
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.utils import shuffle
import sklearn.ensemble as ske
from sklearn.preprocessing import StandardScaler
from sklearn import model_selection
from sklearn.externals import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, confusion_matrix, f1_score
from sklearn.model_selection import cross_val_predict

# Class Entropy to calculate URL entropy.
# Entropy is often described as a measure of randomness. Malicious URLs 
# will typically have a higher entropy and randomness.
# Entropy is calculated using Shannon Entropy - 
# https://en.wiktionary.org/wiki/Shannon_entropy
# http://pythonfiddle.com/shannon-entropy-calculation/

class Entropy():
    def __init__(self, data):
        self.data = data

    def range_bytes(): return range(256)

    def range_printable(): return (ord(c) for c in string.printable)

    def H(self, data, iterator=range_bytes):
        if not data:
            return 0
        entropy = 0
        for x in iterator():
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

# Class URLFeatures extracts specific features from URLs.
class URLFeatures():

    # Bag Of Words method is used for text analysis.
    # Here URLs are described by word occurrences while completely 
    # ignoring the relative position information of the words in 
    # the document.
    def bag_of_words(self, url):
        vectorizer = CountVectorizer()
        content = re.split('\W+', url)
        X = vectorizer.fit_transform(content)
        num_sample, num_features = X.shape
        return num_features
    
    # Contains IP method to check the occurence of an IP
    # address within a URL.
    def contains_IP(self, url):
        check = url.split('/')
        reg = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
        result = 0
        for item in check:
            if re.search(reg, item):
                result = 1
        return result
    
    # URL Length method to calculate the URL length.
    # Malicious URLs can often be very long in comparrison to
    # benign URLs.
    def url_length(self, url):
        return len(url)

    # Special Characters method to check for specific special 
    # chars. Sometimes Malicious URLs contain a higher number of
    # special characters.
    # In this method, a counter is used to count the number of 
    # special characters that are found within a URL.
    def special_chars(self, url):
        counter = 0
        if '*' in url:
            counter += 1
        if ';' in url:
            counter += 1
        if '%' in url:
            counter += 1
        if '!' in url:
            counter += 1
        if '&' in url:
            counter += 1
        if ':' in url:
            counter += 1

        return counter

    # Suspicious Strings method to check for suspicious strings within
    # the URLs. A higher number of suspicious strings would indicate a 
    # possibly malicious URL. 
    def suspicious_strings(self, url):
        counter = 0
        
        # Malicious URLs may contain the string '.exe' in reference to
        # downloading a possibly malicious executable.
        if '.exe' in url:
            counter += 1
        # Malicious URLs may use base64 encoding to encode and 
        # possibly obfuscate information.
        if 'base64' in url:
            counter += 1
        # The occurence of '/../' may possibly indicate file
        # file inclusion.
        if '/../' in url:
            counter += 1
        if '.pdf' in url:
            counter += 1
        # Phishing can use social engineering to lure victims to
        # click on malicious links. The use of the word free may
        # be included within URLs to trick users in visiting 
        # malicious websites.
        if 'free' in url:
            counter += 1
        if 'Free' in url:
            counter += 1
        if 'FREE' in url:
            counter += 1
        # .onion and .tor references the use of tor. Such domains
        # are suspicious and according to RFC 7686 should be kept
        # off public internet.
        if '.onion' in url:
            counter += 1
        if '.tor' in url:
            counter += 1
        # Suspicious domains.
        if '.top' in url:
            counter += 1
        if '.bid' in url:
            counter += 1
        if '.ml' in url:
            counter += 1
        # Bitcoin references.
        if 'bitcoin' in url:
            counter += 1
        if '.bit' in url:
            counter += 1
        if '.php?email=' in url:
            counter += 1
        # Possible command execution.
        if 'cmd=' in url:
            counter += 1

        return counter

    # Number Of Digits method returns the number of digits
    # contained within a URL. Malicious URLs often have higher
    # entropy and can contain lots of numbers.
    def num_digits(self, url):
        numbers = sum(i.isdigit() for i in url)
        return numbers

    # Popularity method checks the url popularity
    # against the top 1 million urls contained within the
    # umbrella dataset.
    # Sites contained within this dataset are not malicious.
    def popularity(self, url):
        result = 0
        domain = url.split('/', 1)[-1]

        with open('benign_urls/top1m_rank.csv', 'rt') as f:
            reader = csv.reader(f, delimiter='|')
            for row in reader:
                if domain == row[1]:
                    result = row[0]
                    
        return int(result)

# Class Retrive Data retrieves fresh URL data from online websites.
# This is to prevent the use of stale data within the program.
# Google Safebrowsing API restricts only 10k requests per day.
# To preserve Safebrowsing feature only 5000 malicious and 5000
# benign URLs are being used.


class RetrieveData():
    def __init__(self):
        # Ransomware domain blocklist. 
        self.dombl = 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'
        # Ransomware URL domain blocklist. 
        self.urlbl = 'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt'
        # Openphish malicious URL data. 
        self.openphish = 'https://openphish.com/feed.txt'
        # Cisco umbrella top 1 million URLs dataset.
        self.umbrella = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'

    # Get Malicious URLs method retrieves the datasets and writes them
    # to the file malicious_urls/malicious_urls.csv
    def get_malicious_urls(self):
        rw_dombl = self.dombl
        # Retreives ransomware domain blocklist.
        urllib.request.urlretrieve(rw_dombl, 'malicious_urls/rw_dombl.txt')
        
        # Opens the file and writes the domains to the txt file after line 7
        # of the blocklist. All domains are contained within the blocklist after
        # line 7.
        lines = open('malicious_urls/rw_dombl.txt').readlines()
        open('malicious_urls/rw_dombl.txt', 'w').writelines(lines[7:])

        # Creates a panda dataframe and reads in the ransomware domain
        # blocklist.
        df_dombl = pd.read_csv('malicious_urls/rw_dombl.txt', header=None)
        
        # Assigns dataframe to the top 1000 domains in the list.
        df_dombl = df_dombl.iloc[0:1000]

        rw_urlbl = self.urlbl
        # Retrives ransomware url blacklist. 
        urllib.request.urlretrieve(rw_urlbl, 'malicious_urls/rw_urlbl.txt')
        
        # Opens the file and writes the URLs to the txt file after line 7
        # of the blocklist. All URLs are contained within the blocklist after
        # line 7.
        lines = open('malicious_urls/rw_urlbl.txt').readlines()
        open('malicious_urls/rw_urlbl.txt', 'w').writelines(lines[7:])
        
        # Creates a panda dataframe and reads in the ransomware URL
        # blocklist.
        df_urlbl = pd.read_csv('urldata/rw_urlbl.txt', header=None)

        # Assigns dataframe to the top 1000 URLs in the list.
        df_urlbl = df_urlbl.iloc[0:1000]

        open_phish = self.openphish

        # Retrives openphish malicious URLs.
        urllib.request.urlretrieve(open_phish, 'malicious_urls/openphish.txt')

        # Creates a panda dataframe 
        df_op = pd.read_csv('malicious_urls/openphish.txt', sep='\n', header=None)
        df_op = df_op.iloc[0:3000]

        # Merges all three datasets into a single dataset.
        df = df_op.append(df_urlbl)
        df = df.append(df_dombl)

        # Assigns the column within the dataframe that contains the URLS as URL.
        df.columns = ['URL']
        
        # Writes the dataframe containing all malicious URLs to a csv file.
        df.to_csv('malicious_urls/malicious_urls.csv', sep='\n', index=False)
        
    # Get benign URLs method retrieves the benign URLs.
    def get_benign_urls(self):  
        try:
            umbrella = self.umbrella
            # Downloads cisco umbrella top 1 million urls
            urllib.request.urlretrieve(umbrella, 'benign_urls/top1m.csv.zip')
            
            print("[+] Unzipping Benign URL data...\n")

            # Unzips the top1m zipfile to the benign_urls/ directory.
            with zipfile.ZipFile("benign_urls/top1m.csv.zip") as zip_ref:
                zip_ref.extractall('benign_urls/')
            
            # Creates a pandas dataframe and reads in the umbrella dataset.
            df = pd.read_csv('benign_urls/top-1m.csv', header=None)

            # Assigns both the column names in the dataset as Rank and URL.
            df.columns = ['Rank', 'URL']
            
            # Writes the umbrella dataset to a CSV file with the new column names.
            df.to_csv('benign_urls/top1m_rank.csv', sep='|', index=False)

            # Drops the Rank column from the dataset and assigns dataframe to only
            # include the top 2000 URLS.
            df = df.drop('Rank', axis=1)
            df = df.iloc[0:2000]

            # Writes dataframe with dropped Rank column and top 2000 URLs to a new
            # csv file called top.csv.
            df.to_csv('benign_urls/top.csv', sep='|', index=False)
            
            # Reads in an additional dataset from Kaggle - https://www.kaggle.com/antonyj453/urldataset.
            # Data preprocessing has removed all malicious URLs so only
            # benign URLs remain.
            df_kag = pd.read_csv('benign_urls/kaggle_urls.csv', sep='|')

            # Shuffles the dataset to ensure there is a good mix of URLs.
            df_kag = shuffle(df_kag)

            # Assigns the dataframe to only include the top 3000 URLs
            # of the new shuffled dataset.
            df_kag = df_kag.iloc[0:3000]

            # Merges the umbrella and kaggle datasets together.
            df = df.append(df_kag)

            # Writes the merged dataset of benign URLs to a CSV file named
            # benign_urls.csv.
            df.to_csv('benign_urls/benign_urls.csv', sep='|', index=False)
        except:
            print("[-] Unable to retrieve an updated URL list.\n")

# Class safebrowse integrates the Google Safebrowse API to check if Google
# classes the URLs as safe. Any URLs classed as not safe may be malicious.
# Although blacklists and resources such as Google safebrowsing cannot predict
# malicious URLs, the appearance of a URL in these lists is a powerful feature. 
class SafeBrowse():
    def __init__(self, apikey):
        self.safe_base = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s' % (apikey)
        self.platform_types = ['ANY_PLATFORM']
        self.threat_types = ['THREAT_TYPE_UNSPECIFIED',
                             'MALWARE', 
                             'SOCIAL_ENGINEERING', 
                             'UNWANTED_SOFTWARE', 
                             'POTENTIALLY_HARMFUL_APPLICATION']
        self.threat_entry_types = ['URL']

    def set_threat_types(self, threats):

        self.threat_types = threats

    def set_platform_types(self, platforms): 
        
        self.platform_types = platforms

    def threat_matches_find(self, *urls): 
        try:
            threat_entries = []
            results = {}

            for url_ in urls: 
                url = {'url': url_} 
                threat_entries.append(url)

            request_body = {
                'client': {
                    'clientId': 'MLURL_CLIENT',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': self.threat_types,
                    'platformTypes': self.platform_types,
                    'threatEntryTypes': self.threat_entry_types,
                    'threatEntries': threat_entries
                }
            }
            
            headers = {'Content-Type': 'application/json'}
            r = requests.post(self.safe_base, 
                            data=json.dumps(request_body), 
                            headers=headers, timeout=2)

            jdata = r.json()
            #print(jdata['matches'][0]['threatEntryType'])
            
            # If the threatEntryType matches the string URL, the parsed URL
            # has been classified as not safe by Google. In this case a 1
            # is returned and otherwise a 0 is returned.
            if jdata['matches'][0]['threatEntryType'] == 'URL':
                return 1
            else:
                return 0
        except:
            return 0 
# Extract features function extracts all features from URLs and stores it in a
# feature list. This list can then be returned and writen to a csv file.
def extract_features(url):
    features = []
    
    # Parses input URL to remove http:// or https://.
    # The umbrella dataset does not contain this and thus,
    # is not required for certain feature extractions.
    parsed_url = parse_url(url)
    
    # Appends URL to features list.
    features.append(url)

    # Retrieve URL entropy and append to feature list.
    getEntropy = Entropy(parsed_url)
    entropy = getEntropy.H(parsed_url)
    features.append(entropy)

    # Creates feature object of class URL features.
    feature = URLFeatures()

    # Append Bag Of Words to feature list.  
    features.append(feature.bag_of_words(parsed_url))
    
    # Append Contains IP address to feature list.
    features.append(feature.contains_IP(parsed_url))

    # Append URL length to feature list.
    features.append(feature.url_length(parsed_url))

    # Append amount of special characters to feature list.
    features.append(feature.special_chars(parsed_url))

    # Append number of suspicious strings to feature list.
    features.append(feature.suspicious_strings(url))

    # Append number of digits within the URL to feature list.
    features.append(feature.num_digits(parsed_url))

    # Append site popularity to feature list.
    features.append(feature.popularity(parsed_url))

    # Appends Google Safebrowsing verdict to features list.
    apikey = base64.b64decode('QUl6YVN5Qzl0c3gzcFlmQXhPN25PSGE5UWtNdjR6VW1QNk90UmQw')
    apikey = apikey.decode('utf-8')
    safe = SafeBrowse(apikey)
    response = safe.threat_matches_find(url) 
    features.append(response)

    # Returns extracted features from features list.
    return features

# Parse URL function strips http:// and https:// from
# URLs. Umbrella dataset does not contain this and thus,
# is not required for certain feature extractions.
def parse_url(url):

    if 'http://' in url:
        url_http = url.split('http://', 1)[-1]
        return url_http
    elif 'https://' in url:
        url_https = url.split('https://', 1)[-1]
        return url_https
    else:
        return url

# Create dataset function creates a CSV file and writes all the URL
# features to it.
def create_dataset():
    output_file = "data_urls.csv"
    csv_delimeter = '|'
    csv_columns = [
        "URL",
        "Entropy",
        "BagOfWords",
        "ContainsIP",
        "LengthURL",
        "SpecialChars",
        "SuspiciousStrings",
        "NumberOfDigits",
        "Popularity",
        "Safebrowsing",
        "Malicious", 
    ]

    # Opens file that features will be written to for reading.
    feature_file = open(output_file, 'a')
    
    # Writes the feature column names to csv file. 
    feature_file.write(csv_delimeter.join(csv_columns) + "\n")

    # Opens the malicious URLs file for reading and creates a list
    # that contains all the rows (URLs) from the file.
    with open('malicious_urls/malicious_urls.csv', 'r') as f:
        reader = csv.DictReader(f, delimiter='\n')
        rows = list(reader)

    # For every row or URL in the malicious URL file, extract all
    # the features.
    for row in rows:
        print('\n[+] Extracting features from ', row['URL'])
        try:
            e = extract_features(row['URL'])

            # Appends a binary value of 1 to the feature file to represent
            # a malicious URL label.
            e.append(1)

            # Writes features to feature file.
            feature_file.write(csv_delimeter.join(map(lambda x: str(x), e)) + "\n")
            print(colored('\n[*] ', 'green') + "Features extracted successfully.\n")
        except:
            print("[-] Error: Unable to extract features.\n")
    
    # The above is then repeated below for the benign URLs.

    with open('benign_urls/benign_urls.csv', 'r') as f:
        reader = csv.DictReader(f, delimiter=',')
        rows = list(reader)

    for row in rows:
        print('\n[+] Extracting features from ', row['URL'])
        try:
            e = extract_features(row['URL'])
            e.append(0)
            feature_file.write(csv_delimeter.join(map(lambda x: str(x), e)) + "\n")
            print(colored('\n[*] ', 'green') + "Features extracted successfully.\n")
        except:
            print("[-] Error: Unable to extract features.\n")

    feature_file.close()

# Train model function trains a Logistic Regression classifier
# on the URL dataset and saves the configuration in the form of
# a pickle file.
def train_model():
    # Creates a pandas dataframe and reads in the URL dataset with
    # extracted features. 
    df = pd.read_csv('data_urls.csv', sep='|')

    # Assigns X to features. Drops URL name and label.
    X = df.drop(['URL', 'Malicious'], axis=1).values
    
    # Assigns y to labels.
    y = df['Malicious'].values

    # Split data into training and test datasets.
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42) 

    # Print the number of training and testing samples.
    print("\t[*] Training samples: ", len(X_train))
    print("\t[*] Testing samples: ", len(X_test))
    
    #s = StandardScaler()
    #X_train_scale = s.fit_transform(X_train)
    #X_test_scale = s.fit_transform(X_test)

    # Train Logisitic Regression algorithm on training dataset.
    clf = ske.RandomForestClassifier(n_estimators=50)   
    clf.fit(X_train, y_train)

    # Perform cross validation and print out accuracy.
    score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    # Calculate f1 score.
    y_train_pred = cross_val_predict(clf, X_train, y_train, cv=3)
    f = f1_score(y_train, y_train_pred)
    print("\t[*] F1 Score: ", round(f*100, 2), '%')

    # Save the configuration of the classifier and features as a pickle file.
    
    all_features = X.shape[1]
    features = []

    for feature in range(all_features):
        features.append(df.columns[1+feature])

    try:
        print("\n[+] Saving algorithm and feature list in classifier directory...")
        joblib.dump(clf, 'classifier/classifier.pkl')
        open('classifier/features.pkl', 'wb').write(pickle.dumps(features))
        print(colored('\n[*] ', 'green') + " Saved.")
    except:
        print('\n[-] Error: Algorithm and feature list not saved correctly.\n')

# Get URL information function extracts features from a user supplied
# URL. The function extracts all features similarly to extract_features()
# but instead saves the extracted features in the form of a dictionary. 
def get_url_info(url):
    # Creates a dictionary for features to be stored in.
    features = {}
    
    # Parses input URL to remove http:// or https://.
    # The umbrella dataset does not contain this and thus,
    # is not required for certain feature extractions.
    parsed_url = parse_url(url)

    # Retrieve URL entropy and store in dictionary.
    getEntropy = Entropy(parsed_url)
    entropy = getEntropy.H(parsed_url)
    features['Entropy'] = entropy

    feature = URLFeatures()

    # Store Bag Of Words in dictionary.  
    features['BagOfWords'] = feature.bag_of_words(parsed_url)
    
    # Store Contains IP address in dictionary.
    features['ContainsIP'] = feature.contains_IP(parsed_url)

    # Store URL length in dictionary.
    features['LengthURL'] = feature.url_length(parsed_url)

    # Store amount of special characters in dictionary.
    features['SpecialChars'] = feature.special_chars(parsed_url)

    # Store amount of suspicious strings in dictionary.
    features['SuspiciousStrings'] = feature.suspicious_strings(url)

    # Store number of digits within the URL in dictionary.
    features['NumberOfDigits'] = feature.num_digits(parsed_url)

    # Store site popularity in dictionary.
    features['Popularity'] = feature.popularity(parsed_url)

    # Store Google Safebrowsing verdict in dictionary.
    apikey = base64.b64decode('QUl6YVN5QV9XbU53MHRyZTEybWtMOE1qYUExY0c3Smd4SnRuU0lv')
    apikey = apikey.decode('utf-8')
    safe = SafeBrowse(apikey)
    features['Safebrowsing'] = safe.threat_matches_find(url) 

    # Return features dictionary.
    return features

# Classify URL function passes in the input URL and classifies
# it as malicious or benign. 
def classify_url(url):

    # Loads classifier and feature configurations.
    clf = joblib.load(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'classifier/classifier.pkl'))

    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'rb').read())
    
    # Extracts features from input URL.
    data = get_url_info(url)
    feature_list = list(map(lambda x:data[x], features))

    # Classifies input URL as malicious or benign.
    result = clf.predict([feature_list])[0]

    if result == 0:
        print(colored('\n[*] ', 'green') + "MLURL has classified URL %s as " % url + colored("benign", 'green') + '.')
    else: 
        print(colored('\n[*] ', 'green') + "MLURL has classified URL %s as " % url + colored("malicious", 'red') + '.')
    
    return result

# Virus total function checks the result of the classifier against
# virus total to ensure that it is making the correct decision.
def virus_total(result, url):
    
    base_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    apikey = base64.b64decode('M2FlNzgwMDU5MTE3ZThkYzdmNjA5YjVlOWU1Y2JmOTRkMGJkNTA3NTAyNzI3NWJiOTM3YTg0NGEwYTYzNDNlYQ==')
    apikey = apikey.decode('utf-8')
    params = {'apikey': apikey , 'resource':url}

    print('\n[+] Running Virus Total reputation check...')

    # Retrieves virus total report for info URL.
    response = requests.get(base_url, params=params)
    
    # If response code is 200, the request has been accepted by Virus Total. 
    if response.status_code == 200:          
        data = response.json()
        if data['response_code'] == 0:
            print(colored('\n[-] ', 'red') + "The URL %s was not found in Virus Total" % url)
        else:
            print("\n\t[*] Results for %s :" % url)
            if data['positives'] == 0:
                print("\n\t[*] Detected by: ", colored(str(data['positives']), 'green'), '/', data['total'])
                print('\n\t[*] Virus total has found that the URL is benign.')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print("\n\t[*] Detected by: ", colored(str(data['positives']), 'red'), '/', data['total'])
                print('\n\t[*] Virus total has found the URL to have malicious properties.')
            elif data['positives'] > 25:
                print("\n\t[*] Detected by: ", colored(str(data['positives']), 'red'), '/', data['total'])
                print('\n\t[*] Virus total has found that the URL is malicious.')
            
            # Checks to check if the classifier made the correct decision.
            if result == 0 and data['positives'] != 0:
                print(colored("\n[-] ", 'red') + "MLURL has incorrectly classified the URL %s as malicious." % url)
            elif result == 1 and data['positives'] == 0:
                print(colored("\n[-] ", 'red') + "MLURL has incorrectly classified the URL %s as benign." % url)
            else:
                print(colored("\n[*] ", 'green') + "MLURL has correctly classified the URL %s." % url)
    
    if response.status_code == 204:
        print(colored("\n[-] ", 'red') + "Error: Request rate limit exceeded. You are making more requests than allowed.")
    elif response.status_code == 400:
        print(colored("\n[-] ", 'red') + "Error: Bad request. This can be caused by missing arguments or arguments with wrong values.")
    elif response.status_code == 403:
        print(colored("\n[-] ", 'red') + "Error: Request forbidden")

# Open up survey to evaluate program.
def survey_mail():
    print('\n[*] Opening up survey in browser.')
    webbrowser.open('https://www.surveymonkey.de/r/GNYBKM6', new=2)

# Check valid URL function checks whether or not the input
# URL to classify is in a valid format.
# https://www.regextester.com/93652

def check_valid_url(url):
    print("\n[+] Validating URL format...")
    reg = re.compile('^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$')
    
    if re.match(reg, str(url)):
        print(colored("\n[*] ", 'green') + "URL is valid.")
    else:
        print(colored("\n[-] ", 'red') + "Error: URL is not valid. Please input a valid URL format. ")
        sys.exit(0)

def main():
    # Creates a command line parser.
    parser = argparse.ArgumentParser(epilog='MLURL uses machine learning to detect malicious URLs.',
        description="Machine Learning malicious URL classifier (MLURL)")
    parser.add_argument('-c', '--classify', dest='classify', help='Classify a new URL as malicious or benign.')    
    parser.add_argument('-b', '--benign_update', nargs='*', help='Update benign URL data.')
    parser.add_argument('-m', '--malicious_update', nargs='*', help='Update malicious URL data.')
    parser.add_argument('-g', '--generate_data', nargs='*', help='Generate the URL dataset.')
    parser.add_argument('-t', '--train', nargs='*', help='Train Logistic Regression Algorithm.')
    parser.add_argument('-v', '--virustotal', nargs='*', help='Check prediction using Virus Total.')
    parser.add_argument('-s', '--survey', nargs='*', help='Evaluate Program using Survey.')

    args = parser.parse_args()
    colorama.init()

    # Updates the benign dataset.
    if args.benign_update is not None:
        try: 
            getData = RetrieveData()
            getData.get_benign_urls()
            print(colored('\n[*] ', 'green') + "Benign URLs successfully downloaded.\n")
        except:
            print(colored('[-] ', 'red') + "Error: Benign URL downloaded unsuccessful. \n")
    
    # Updates the malicious dataset.
    if args.malicious_update is not None:
        print("\n[+] Downloading Malicious URL data...\n")
        try:
            getData = RetrieveData()
            getData.get_malicious_urls()
            print(colored('\n[*] ', 'green') + "Malicious URLs successfully downloaded.\n")
        except:
            print(colored('\n[-] ', 'red') + "Error: Malicious URL downloaded unsuccessful.\n")

    # Generates URL dataset.
    if args.generate_data is not None:
        print("\n[+] Generating URL data...")
        try:
            print("\n[+] Beginning feature extraction...")
            if os.path.exists('data_urls.csv'):
                os.remove('data_urls.csv')
                create_dataset()
            else:
                create_dataset()
            (colored("\n[*] ", 'green') + "Feature extraction successful.\n")
        except:
            print(colored("\n[-] ", 'red') + "Error: Feature extraction unsuccessful.\n")
    
    # Trains Logistic Regression algorithm on URL dataset.
    if args.train is not None:
        print('\n[+] Training Logistic Regresson model...\n')
        try:    
            train_model()
            print(colored("\n[*] ", 'green') + "Model successfully trained.")
        except:
            print(colored("\n[-] ", 'red') + "Error: Model unsuccessfully trained .")
    
    # Classifies input URL and checks using Virus Total API.
    if args.classify and args.virustotal is not None:
        print('\n[+] Running Classifier...')
        check_valid_url(args.classify)
        result = classify_url(args.classify)
        virus_total(result, args.classify)
    elif args.classify:
        print('\n[+] Running Classifier...')
        check_valid_url(args.classify)
        classify_url(args.classify)

    if args.survey is not None:
        survey_mail()
        
if __name__ == '__main__':
    main()
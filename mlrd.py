import os
import sys
import argparse
import array
import math
import pickle
import pefile
import hashlib
import yara
import pandas as pd
import numpy as np
from sklearn.externals import joblib
import urllib
import urllib3
import json
import requests
from requests.auth import HTTPBasicAuth
from termcolor import colored, cprint
import colorama
import base64
import webbrowser


# Class to extract features from input file.
class ExtractFeatures():
    
    # Defining init method taking parameter file.
    def __init__(self, file):
        self.file = file

    # Method for extracting the MD5 hash of a file.
    # It is not always possible to fit the entire file into memory so chunks of
    # 4096 bytes are read and sequentially fed into the function.
    def get_md5(self, file):
        md5 = hashlib.md5()
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
            return md5.hexdigest()
    
    # Method for compiling the yara rule for searching files for
    # signs of bitcoin addresses. 
    def compile_bitcoin(self):
        if not os.path.isdir("rules_compiled/Bitcoin"):
            os.makedirs("rules_compiled/Bitcoin")
            print("success")

        for n in os.listdir("rules/Bitcoin"):
            rule = yara.compile("rules/Bitcoin/" + n)
            rule.save("rules_compiled/Bitcoin/" + n)
    
    # Method for checking the input file for any signs of embedded bitcoin
    # addresses. If the file does contain a bitcoin address a 1 is returned. 
    # Otherwise a 0 is returned.
    def check_bitcoin(self, file):
        for n in os.listdir("rules/Bitcoin"):
            rule = yara.load("rules_compiled/Bitcoin/" + n)
            m = rule.match(file)
            if m:
                return 1
            else:
                return 0
    
    # Method for extracting all features from an input file.
    def get_fileinfo(self, file):
        # Creates a dictionary that will hold feature names as keys and 
        # their feature values as values.
        features = {}

        # Assigns pe to the input file. fast_load loads all directory 
        # information.
        pe = pefile.PE(file, fast_load=True)

        # CPU that the file is intended for.
        features['Machine'] = pe.FILE_HEADER.Machine

        # DebugSize is the size of the debug directory table. Clean files
        # typically have a debug directory and thus, will have a non-zero
        # values.
        features['DebugSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size

        # Debug Relative Virtual Address (RVA). 
        features['DebugRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].\
            VirtualAddress

        # MajorImageVersion is the version of the file. This is user defined
        # and for clean programs is often populated. Malware often has a
        # value of 0 for this.
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion

        # MajorOSVersion is the major operating system required to run exe.
        features['MajorOSVersion'] = pe.OPTIONAL_HEADER.\
            MajorOperatingSystemVersion

        # Export Relative Virtual Address (VRA).
        features['ExportRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].\
            VirtualAddress

        # ExportSize is the size of the export table. Usually non-zero for
        # clean files.
        features['ExportSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size

        # IatRVA is the relative virtual address of import address
        # table. Clean files typically have 4096 for this where as malware
        # often has 0 or a very large number.
        features['IatVRA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].\
            VirtualAddress

        # ResourcesSize is the size of resources section of PE header. 
        # Malware sometimes has 0 resources.
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.\
            MajorLinkerVersion

        # MinorLinkerVersion is the minor version linker that produced the
        # file.
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion

        # NumberOfSections is the number of sections in file.
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections 

        # SizeOfStackReserve denotes the amount of virtual memory to reserve
        # for the initial thread's stack.
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve

        # DllCharacteristics is a set of flags indicating under which
        # circumstances a DLL's initialization function will be called.
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics

        # ResourceSize denotes the size of the resources section.
        # Malware may often have no resources but clean files will.
        features['ResourceSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size

        # Creates an object of Extract features and passes in the input
        # file. The object get_bitcoin accesses the check_bitcoin method
        # for which a 1 or 0 is returned and added as a value in the
        # dictionary.
        get_bitcoin = ExtractFeatures(file)
        bitcoin_check = get_bitcoin.check_bitcoin(file)
        features['BitcoinAddresses'] = bitcoin_check

        # Returns features for the given input file.
        return features

# Class to search third party reputation checkers and malware analysis
# websites to cross check if the tool is making correct decisions.
class RepChecker():

    # Init method to initalise api keys and base urls.
    def __init__(self):
        # Virus Total api key
        vtapi = base64.b64decode('M2FlNzgwMDU5MTE3ZThkYzdmNjA5YjVlOWU1Y2JmOTRkMGJkNTA3NTAyNzI3NWJiOTM3YTg0NGEwYTYzNDNlYQ==')
        self.vtapi = vtapi.decode('utf-8')
        # Virus Total base URL
        self.vtbase = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.http = urllib3.PoolManager()
        # Threat Crowd base URL.
        self.tcbase = 'http://www.threatcrowd.org/searchApi/v2/file/report/?resource='
        # Hybrid Analysis api key.
        hapi = base64.b64decode('OGtzMDhrc3NrOGNja3Nnd3dnY2NnZzRzOG8wczA0Y2tzODA4c2NjYzAwZ2s0a2trZzRnc2s4Zzg0OGc4b2NvNA==')
        self.hapi = hapi.decode('utf-8')
        # Hybrid Analysis secret key.
        hsecret = base64.b64decode('MTFhYjc1OTMxZGYzOWFjMmVjYmI3ZGNhNmI1MzYxMmE3YmU4ZjM3MTM5YTAwY2Nm')
        self.hsecret = hsecret.decode('utf-8')
        # Hybrid Analysis base URL.
        self.hbase = 'https://www.hybrid-analysis.com/api/scan/'
    
    # Method for authenticating to Virus Total API and file information
    # in JSON. 
    def get_virus_total(self, md5):
        params = {'apikey': self.vtapi, 'resource':md5}
        data = urllib.parse.urlencode(params).encode("utf-8")
        r = requests.get(self.vtbase, params=params)
        return r.json()

    # Method for returning file information in JSON from
    # Threat Crowd.
    def get_threatcrowd(self, md5):
        r = requests.get(self.tcbase)
        return r.json()

    # Method for authenticating to Hybrid Analysis API and
    # returning file information in JSON.
    def get_hybrid(self, md5):
        headers = {'User-Agent': 'Falcon'}
        query = self.hbase + md5    
        r = requests.get(query, headers=headers, auth=HTTPBasicAuth(self.hapi, self.hsecret))
        return r.json()

# Open up survey to evaluate program.
def survey_mail():
    print('\n[*] Opening up survey in browser.\n')
    webbrowser.open('https://www.surveymonkey.de/r/N289B82', new=2)

# Function to parse user input. Takes in input file, extracted features,
# and parsed options.
def parse(file, features, display, virustotal, threatcrowd, hybridanalysis):
    # Creates an object of RepChecker to return third party about 
    # input file.
    get_data = RepChecker()
    # Creates an object of ExtractFeatures to return information about the
    # input file. 
    md5 = ExtractFeatures(file)
    md5_hash = md5.get_md5(file)
   
    # If display option is selected, the extracted features are printed
    # to the screen. 
    if display:
        print("[*] Printing extracted file features...")
        print("\n\tMD5: ", md5_hash)
        print("\tDebug Size: ", features[0])
        print("\tDebug RVA: ", features[1])
        print("\tMajor Image Version:", features[2])
        print("\tMajor OS Version:", features[3])
        print("\tExport RVA:", features[4])
        print("\tExport Size:", features[5])
        print("\tIat RVA: ", features[6])
        print("\tMajor Linker Version: ", features[7])
        print("\tMinor Linker Version", features[8])
        print("\tNumber Of Sections: ", features[9])
        print("\tSize Of Stack Reserve: ", features[10])
        print("\tDll Characteristics: ", features[11])
        if features[12] == 1:
            print("\tBitcoin Addresses: Yes\n")
        else: 
            print("\tBitcoin Addresses: No\n")

    # If Virus Total option is selected, file information from Virus
    # total is returned.
    if virustotal:
        print("[+] Running Virus Total reputation check...\n")
        # Retrieves data from virus total. Searches by passing in
        # md5 hash of input file.
        data = get_data.get_virus_total(md5_hash)

        # If the response code is 0, error message is returned indicating 
        # that the md5 hash is not in virus total. Otherwise, the number
        # of AV companies that detected the file as malicious is returned
        # If 0, output is in green. 
        # Between 0 and 25, output is yellow.
        # Over 25, output is red.
        if data['response_code'] == 0:
            print("[-] The file %s with MD5 hash %s was not found in Virus Total" % (os.path.basename(file), md5_hash))
        else:
            print("\tResults for file %s with MD5 %s:" % (os.path.basename(file), md5_hash))
            if data['positives'] == 0:
                print("\n\tDetected by: ", colored(str(data['positives']), 'green'), '/', data['total'], '\n')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print("\n\tDetected by: ", colored(str(data['positives']), 'yellow'), '/', data['total'], '\n')
            else:
                print("\n\tDetected by: ", colored(str(data['positives']), 'red'), '/', data['total'], '\n')

            # Creates two lists to store the AV companies who detected the file
            # as malicious and to store corresponding malware names.
            av_firms = []
            malware_names = []
            fmt = '%-4s%-23s%s'

            # If any AV company indicated that the file is malicious, it is
            # printed to the screen. 
            if data['positives'] > 0:  
                for scan in data['scans']:
                    if data['scans'][scan]['detected'] == True:
                        av_firms.append(scan)
                        malware_names.append(data['scans'][scan]['result'])

                print('\t', fmt % ('', 'AV Firm', 'Malware Name'))
                for i, (l1, l2) in enumerate(zip(av_firms, malware_names)):
                    print('\t', fmt % (i, l1, l2))
                if data['permalink']:
                    print("\n\tVirus Total Report: ", data['permalink'], '\n') 

            # Prints if Virus Total has found the file to be malicious.
            if data['positives'] == 0:
                print(colored('[*] ', 'green') + "Virus Total has found the file %s " % os.path.basename(file) + colored("not malicious.", 'green'))        
                if data['permalink']:
                    print("\n\tVirus Total Report: ", data['permalink'], '\n')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print(colored('[*] ', 'red') + "Virus Total has found the file %s " % os.path.basename(file) + colored("has malicious properties.\n", 'yellow'))       
            else:
                print(colored('[*] ', 'red') + "Virus Total has found the file %s " % os.path.basename(file) + colored("is malicious.\n", 'red'))       

    # If threat crowd option is selected, file information is returned.            
    if threatcrowd:
        fmt = '%-4s%-23s'
        print("[+] Retrieving information from Threat Crowd...\n")
        data = get_data.get_threatcrowd(md5_hash)            
        
        # If response code is 0, an error message is thrown to indicate
        # the file is not in Threat Crowd. Otherwise, the SHA1 Hash,
        # domain names, and malware names given by AV companies for
        # the file is printed to the screen.
        if data['response_code'] == "0":
            print("[-] The file %s with MD5 hash %s was not found in Threat Crowd.\n" % (os.path.basename(file), md5_hash))
        else:
            print("\n\tSHA1: ", data['sha1'])
            if data['ips']:
                print('\n\t', fmt % ('', 'IPs'))
                for i, ip in enumerate((data['ips'])):
                    print('\t', fmt % (i+1, ip))

            if data['domains']:
                print('\n\t', fmt % ('', 'Domains'))
                for i, domain in enumerate((data['domains'])):
                    print('\t', fmt % (i+1, domain))
                    
            if data['scans']:
                if data['scans'][1:]:
                    print('\n\t', fmt % ('', 'Antivirus'))
                    for i, scan in enumerate(data['scans'][1:]):
                        print('\t', fmt % (i+1, scan))
            
            print('\n\tThreat Crowd Report: ', data['permalink'], '\n')

    # If hybrid analysis option is selected, file information is returned.
    if hybridanalysis:
        # Searches hybrid analysis with md5 hash of file and attempts
        # to return its information in JSON format.
        data = get_data.get_hybrid(md5_hash)  
        fmt = '%-4s%-23s'

        print("[+] Retrieving information from Hybrid Analysis...\n")

        # If no response, error message is thrown to indicate that the file
        # is not in Hybrid Analysis. Otherwise, SHA256, SHA1, Threat Level,
        # Threat Score, Verdict (malicious / not malicious), malware family,
        # and network information is returned
        if not data['response']:
            print("[-] The file %s with MD5 hash %s was not found in Hybrid Analysis." % (os.path.basename(file), md5_hash), '\n')
        else:
            try:
                print('\t', data['response'][0]['submitname'])
            except:
                pass

            print('\tSHA256:', data['response'][0]['sha256'])
            print('\tSHA1: ', data['response'][0]['sha1'])
            print('\tThreat Level: ', data['response'][0]['threatlevel'])
            print('\tThreat Score: ', data['response'][0]['threatscore'])
            print('\tVerdict: ', data['response'][0]['verdict'])
            
            try:
                print('\tFamily: ', data['response'][0]['vxfamily'])
            except:
                pass
            try:
                if data['response'][0]['classification_tags']:
                    print('\n\t', fmt % ('', 'Class Tags'))
                    for i, tag in enumerate(data['response'][0]['classification_tags']):
                        print('\t', fmt % (i+1, tag))
                else:
                    print("\tClass Tags: No Classification Tags.")
            except:
                pass            
            try:
                if data['response'][0]['compromised_hosts']:
                    print('\n\t', fmt % ('', 'Compromised Hosts'))
                    for i, host in enumerate(data['response'][0]['compromised_hosts']):
                        print('\t', fmt % (i+1, host))
                else: 
                    print('\t\nCompromised Hosts: No Compromised Hosts.')
            except:
                pass
            try:
                if data['response'][0]['domains']:
                    print('\n\t', fmt % ('', 'Domains'))
                    for i, domain in enumerate(data['response'][0]['domains']):
                        print('\t', fmt % (i+1, domain))
                else:
                    print('\tDomains: No Domains.')
            except:
                pass
            try:
                if data['response'][0]['total_network_connections']:
                    print('\tNetwork Connections: ', data['response'][0]['total_network_connections'])
                else:
                    print('\n\tNetwork Connections: No Network Connections')
            except:
                pass
            try:
                if data['response'][0]['families']:
                    print('\tFamilies: ', data['response'][0]['families'])
            except:
                pass

            # Verdict is printed to screen.
            # Malicious = red.
            # Benign = green.
            if data['response'][0]['verdict'] == "malicious":
                print(colored('\n[*] ', 'red') + "Hybrid Analysis has found that the file %s " % os.path.basename(file) + colored("is malicious.\n", 'red'))       
            else:
                print(colored('\n[*] ', 'green') + "Hybrid Analysis has found that the file %s " % os.path.basename(file) + colored("is not malicious.\n", 'green'))       


def main():
    parser = argparse.ArgumentParser(epilog="MLRD uses machine learning to detect ransomware\n\
        . Supply a file to determine whether or not it is ransomware. Virus Total\
        , Threat Crowd and Hybrid Analysis can be queried for verification.", 
            description="Machine Learning Ransowmare Detector (MLRD)")

    parser.add_argument('file', nargs='?', help="File To Parse", )
    parser.add_argument('-d', '--displayfeatures', action='store_true', dest='display', help='Display extracted file features.')
    parser.add_argument('-v', "--virustotal", action='store_true', dest='virustotal', help="Run with Virus Total check.")
    parser.add_argument('-t', '--threatcrowd', action='store_true', dest='threatcrowd', help="Run with Threat Crowd check.")
    parser.add_argument('-z', '--hybridanalysis', action='store_true', dest='hybridanalysis', help="Run Hybrid Analysis check.")
    parser.add_argument('-s', '--survey', nargs='*', help='Evaluate Program using Survey.')

    args = parser.parse_args()
    
    colorama.init()

    if args.survey is not None:
        survey_mail()
        sys.exit(0)
        
    # Loads classifier
    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'))
        
    # Loads saved features
    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'rb').read())

    # Creates an object of ExtractFeatures and passes in input file.
    get_features = ExtractFeatures(args.file)

    # Assigns data to extracted features 
    data = get_features.get_fileinfo(args.file)

    feature_list = list(map(lambda x:data[x], features))

    print("\n[+] Running analyzer...\n")
    
    # Asssings result as the prediction of the input file based on its given features.
    result = clf.predict([feature_list])[0]

    # If result is 1, the file is benign.
    # Otherwise, the file is malicious.
    if result == 1:
        print(colored('[*] ', 'green') + "The file %s has been identified as " % os.path.basename(sys.argv[1]) + colored('benign.\n', 'green'))
    else:
        print(colored('[*] ', 'red') + "The file %s has been identified as " % os.path.basename(sys.argv[1]) + colored('malicious.\n', 'red'))

    # Passes command line arguments to parse function for parsing.
    if args.display or args.virustotal or args.threatcrowd or args.hybridanalysis:
        parse(args.file, feature_list, args.display, args.virustotal, args.threatcrowd, args.hybridanalysis)

if __name__ == '__main__':
    main()

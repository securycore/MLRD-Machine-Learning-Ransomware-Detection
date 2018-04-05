'''
    File name: create_benign_dataset.py
    Author: Callum Lock
    Date created: 31/03/2018
    Date last modified: 31/03/2018
    Python Version: 3.6
'''

import os
import hashlib
import math
import array
import pefile
import yara
from termcolor import colored


# Function get md5 calculates the md5 hash of a given file.
def get_md5(file):
    
    # Note that sometimes you won't be able to fit the whole file in memory.
    # In that case, you'll have to read chunks of 4096 bytes
    # sequentially and feed them to the Md5 function:
    # https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
    
    md5 = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
        return md5.hexdigest()

# Function compile bitcoin compiles the yara rule for detecting
# bitcoin addresses within ransomware files. The rule is then
# saved in a directory to later be used.
def compile_bitcoin():
    if not os.path.isdir("rules_compiled/Bitcoin"):
        os.makedirs("rules_compiled/Bitcoin")
        print("success")

    for n in os.listdir("rules/Bitcoin"):
        rule = yara.compile("rules/Bitcoin/" + n)
        rule.save("rules_compiled/Bitcoin/" + n)

# Function check bitcoin loads the bitcoin yara rule
# and checks a file for any signs of bitcoin addresses.
# If a bitcoin address is found a binary 1 is returned.
def check_bitcoin(filepath):
    for n in os.listdir("rules/Bitcoin"):
        rule = yara.load("rules_compiled/Bitcoin/" + n)
        m = rule.match(filepath)
        if m:
            return 1
        else:
            return 0

# Function extract features extracts all features from the input file.
# Features are stored in a list and then returned to later be written to
# a csv file. 
def extract_features(file):
    # Creates an empty list for which features can later be appended into.
    features = []

    # Name of file
    features.append(os.path.basename(file))

    # MD5 hash
    features.append(get_md5(file))

    # Assigns pe to the input file. fast_load loads all directory information.
    pe = pefile.PE(file, fast_load=True)

    # CPU that the file is intended for.
    features.append(pe.FILE_HEADER.Machine)

    # DebugSize is the size of the debug directory table. Clean files typically have a debug directory
    # and thus, will have a non-zero values.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size)

    # DebugRVA
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress)

    # MajorImageVersion is the version of the file. This is user defined and for clean programs is often
    # populated. Malware often has a value of 0 for this.
    features.append(pe.OPTIONAL_HEADER.MajorImageVersion)

    # MajorOSVersion is the major operating system required to run exe.
    features.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)

    # ExportRVA.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress)

    # ExportSize is the size of the export table. Usually non-zero for clean files.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size)

    # IatRVA is the relative virtual address of import address table. Most clean files have 4096 for this
    # where as malware often has 0 or a very large number.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress)

    # Version of linker that produced file.
    features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    features.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)

    # NumberOfSections is the number of sections in file.
    features.append(pe.FILE_HEADER.NumberOfSections)

    # SizeOfStackReserve denotes the amount of virtual memory to reserve for the initial thread's stack.
    features.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)

    # DllCharacteristics is a set of flags indicating under which circumstances a DLL's initialization
    # function will be called.
    features.append(pe.OPTIONAL_HEADER.DllCharacteristics)

    # MinResourcesSize is the size of resources section of PE header. Malware sometimes has 0 resources.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)

    # Calls the bitcoin_check function to check if the file contains a bitcoin address.
    bitcoin_check = check_bitcoin(file)
    features.append(bitcoin_check)

    # Returns the feature list.
    return features


if __name__ == '__main__':
    output_file = "data_benign.csv"
    csv_delimeter = ','
    csv_columns = [
        "FileName",
        "md5Hash",
        "Machine",
        "DebugSize",
        "DebugRVA",
        "MajorImageVersion",
        "MajorOSVersion",
        "ExportRVA",
        "ExportSize",
        "IatVRA",
        "MajorLinkerVersion",
        "MinorLinkerVersion",
        "NumberOfSections",
        "SizeOfStackReserve",
        "DllCharacteristics",
        "ResourceSize",
        "BitcoinAddresses",
        "Benign",
    ]

    # Compiles the yara rule for bitcoin address detection.
    compile_bitcoin()

    # Opens file so features can be written too.
    feature_file = open(output_file, 'a')
    
    # Writes column headers to feature file.
    feature_file.write(csv_delimeter.join(csv_columns) + "\n")

    colorama.init()

    # Extracts features from benign files and writes to CSV.
    for f in os.listdir('benign/'):
        print("\n[+] Extracting features from ", f)
        try:
            features = extract_features(os.path.join('benign/', f))
            features.append(1)
            feature_file.write(csv_delimeter.join(map(lambda x: str(x), features)) + "\n")
            print(colored("[*] Features extracted successfully.\n", 'green'))
        except:
            print(colored("[-] Error: Unable to extract features.\n", 'red'))

    feature_file.close()

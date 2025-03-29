# MLRD Machine Learning Ransomware Detection
MLRD is a machine learning based malware analyser written in Python 3 that can be used to detect ransomware.

## Evaluate using survey here:
https://www.surveymonkey.de/r/N289B82

## Features:
* Analyses and Extracts features from PE file headers to determine if a file is malicious or not.
* Features include: Debug Size, Debug RVA, Major Image Version, Major OS Version, Export Size, IAT RVA, Major Linker Version, Minor Linker Version, Number Of Sections, Size Of Stack Reserve, Dll Characteristics, and Bitcoin Addresses.
* Checks if a file contains a Bitcoin Address using YARA rules.
* Correlate results with Virus Total, Threat Crowd, and Hybrid Analysis.

## Upgrades:
* Train 3 model, and select the best model. (based on Accuracy and F1-score)
* When you train the model, this program choose major features in 15 features. It makes AI model more efficient.
* Chrome extension based on MLRD. (expected)

## Install:
```
git clone https://github.com/callumlock/MLRD-Machine-Learning-Ransomware-Detection.git

cd MLRD-Machine-Learning-Ransomware-Detection

sudo pip3 install -r requirements.txt
```
## Usage

### Train model:
```
python3 mlrd_learn.py
```

### Basic Usage:
```
python3 mlrd.py 'FILE TO ANALYSE'
```
### Usage with Reputation Checking:
```
python3 mlrd.py 'FILE TO ANALYSE' -v

python3 mlrd.py 'FILE TO ANALYSE ' -t

python3 mlrd.py 'FILE TO ANALYSE' -z

python3 mlrd.py 'FILE TO ANALYSE' -vtz
```
### Display Extracted Features for Input File:
```
python3 mlrd.py 'FILE TO ANALYSE' -d
```
### Open Survey:
```
python3 mlrd.py -s
```
### Display Help Information:
```
python3 mlrd.py -h
```

## Test Data:
* Malicious and Benign test files for use with the program can be found in the Test Data directory.
* In this directory you will find benign windows PE files and ransomware files within a ZIP file.

## WARNING:
* Malicious programs are contained within this directory and thus, should be handled with care.
* The ransomware distributed inside the test virual machine have been gathered for research purposes and are only for use within the scope of this project.
* Using these programs with malicious intent is strictly prohibited.

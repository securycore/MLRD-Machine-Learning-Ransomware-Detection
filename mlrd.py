import os
import pefile
import hashlib
import string

class ExtractFeatures():
    def __init__(self, file):
        self.file = os.path.abspath(file)  # 절대 경로 변환
        if not os.path.exists(self.file):
            raise FileNotFoundError(f"❌ 파일 '{self.file}'을 찾을 수 없습니다.")

    def get_md5(self):
        """ 파일의 MD5 해시를 계산 """
        md5 = hashlib.md5()
        with open(self.file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    def get_fileinfo(self):
        """ PE 파일의 특징을 추출 """
        try:
            pe = pefile.PE(self.file, fast_load=True)
        except pefile.PEFormatError:
            print(f"❌ Error: '{self.file}'은(는) 유효한 PE 파일이 아닙니다.")
            return None

        features = {}

        # PE 헤더 기반 정보
        features['Machine'] = pe.FILE_HEADER.Machine
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['ResourceSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size

        # API 호출 분석 (IAT - Import Address Table)
        api_calls = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode(errors='ignore')
                        api_calls.append(api_name)

        features['API_Calls'] = len(api_calls)

        # 섹션별 엔트로피 분석
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            features[f"{name}_Size"] = section.SizeOfRawData
            features[f"{name}_Entropy"] = section.get_entropy()

        # 문자열 분석 (랜섬웨어 관련 키워드 탐지)
        features['Suspicious_Strings'] = self.check_malware_strings()

        return features

    def check_malware_strings(self):
        """ 파일 내부의 문자열에서 랜섬웨어 관련 키워드 탐지 """
        suspicious_keywords = ["ransom", "decrypt", "bitcoin", "AES", "locker", "hacker"]
        strings = self.extract_strings()

        # 🔹 keyword 변수를 사용하지 않고 올바르게 수정
        return any(k in s.lower() for s in strings for k in suspicious_keywords)

    def extract_strings(self, min_length=4):
        """ PE 파일에서 ASCII 문자열 추출 """
        with open(self.file, "rb") as f:
            data = f.read()

        result = []
        printable_chars = set(bytes(string.printable, 'ascii'))
        temp = []
        for byte in data:
            if byte in printable_chars:
                temp.append(chr(byte))
            else:
                if len(temp) >= min_length:
                    result.append("".join(temp))
                temp = []

        return result

def analyze_pe_file(file_path):
    """ PE 파일을 분석하여 랜섬웨어 가능성을 판별 """
    file_path = os.path.abspath(file_path)  # 절대 경로 변환

    if not os.path.exists(file_path):
        print(f"❌ Error: 파일 '{file_path}'이 존재하지 않습니다.")
        return

    print(f"🔍 Analyzing {file_path} ...")
    
    extractor = ExtractFeatures(file_path)
    features = extractor.get_fileinfo()
    
    if features is None:
        return
    
    print("\n=== 📊 PE File Analysis Result ===")
    for key, value in features.items():
        print(f"  {key}: {value}")

    if features["Suspicious_Strings"]:
        print("\n⚠️ 악성 문자열이 포함되어 있음! 랜섬웨어 가능성이 높음!")
    else:
        print("\n✅ 악성 문자열이 발견되지 않음.")

# 실행 예제
file_path = r"Test Data\Benign Test Data\setup_wm.exe"
analyze_pe_file(file_path)

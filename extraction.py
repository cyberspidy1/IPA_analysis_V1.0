import zipfile
import logging
from pathlib import Path

class IPAExtractor:
    def __init__(self, ipa_file: str, extracted_path: str):
        self.ipa_file = ipa_file
        self.extracted_path = Path(extracted_path)

    def extract_ipa(self) -> bool:
        try:
            if not Path(self.ipa_file).exists():
                raise FileNotFoundError(f"IPA file not found: {self.ipa_file}")
            with zipfile.ZipFile(self.ipa_file, 'r') as ipa_zip:
                ipa_zip.extractall(self.extracted_path)
            logging.info(f"Extraction completed successfully: {self.extracted_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to extract IPA file: {e}")
            return False


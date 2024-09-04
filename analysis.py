import os
import re
import logging
from pathlib import Path
import frida

class IPAAnalyzer:
    def __init__(self, extracted_path: str, report_file: str):
        self.extracted_path = Path(extracted_path)
        self.report_file = Path(report_file)
        self.report_content = []

    def analyze(self):
        if not self.extracted_path.exists():
            logging.error(f"Extracted path does not exist: {self.extracted_path}")
            return
        self.check_sensitive_data()
        self.check_jailbreak_indicators_on_device()
        self.check_insecure_apis()
        self.check_trackers()
        self.check_critical_permissions()
        self.generate_report()

    def check_sensitive_data(self):
        sensitive_data_patterns = [
            re.compile(rb"password", re.IGNORECASE),
            re.compile(rb"token", re.IGNORECASE),
            re.compile(rb"secret", re.IGNORECASE),
            re.compile(rb"private_key", re.IGNORECASE),
            re.compile(rb"api_key", re.IGNORECASE)
        ]
        generic_terms = {b"Token", b"password", b"token", b"secret"}  # Add common generic terms to filter out

        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = Path(root) / file
                with open(file_path, 'rb') as f:
                    content = f.read()
                    for pattern in sensitive_data_patterns:
                        matches = pattern.findall(content)  # Get all matches
                        for match in matches:
                            if match not in generic_terms and len(match) > 3:  # Filter out generic terms and short matches
                                self.report_content.append(f"Sensitive data found in {file_path}: {pattern.pattern.decode()} - Data: {match.decode(errors='ignore')}")
                                logging.warning(f"Sensitive data found in {file_path}: {pattern.pattern.decode()} - Data: {match.decode(errors='ignore')}")

    def check_jailbreak_indicators_on_device(self):
        # Frida-based check for jailbreak indicators on the connected iOS device
        try:
            device = frida.get_usb_device()  # Get connected device
            session = device.attach("SpringBoard")  # Attach to a system app like SpringBoard
            script = session.create_script(open("jailbreak_check.js").read())  # Load the Frida script
            script.load()

            # Call the checkjailbreak function from the Frida script
            jailbreak_result = script.exports.checkjailbreak()

            if jailbreak_result:
                for indicator in jailbreak_result:
                    self.report_content.append(f"Jailbreak indicator found on device: {indicator}")
                    logging.warning(f"Jailbreak indicator found on device: {indicator}")
            else:
                logging.info("No jailbreak indicators found on the connected device.")

        except Exception as e:
            logging.error(f"Failed to check jailbreak indicators on the device: {str(e)}")

    def check_insecure_apis(self):
        insecure_apis = [
            re.compile(rb"_fopen", re.IGNORECASE),
            re.compile(rb"_memcpy", re.IGNORECASE),
            re.compile(rb"_printf", re.IGNORECASE),
            re.compile(rb"_sscanf", re.IGNORECASE),
        ]
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = Path(root) / file
                with open(file_path, 'rb') as f:
                    content = f.read()
                    for pattern in insecure_apis:
                        if pattern.search(content):
                            self.report_content.append(f"Insecure API found in {file_path}: {pattern.pattern.decode()}")
                            logging.warning(f"Insecure API found in {file_path}: {pattern.pattern.decode()}")

    def check_trackers(self):
        trackers = [
            b"GoogleAnalytics",
            b"firebase",
            b"Appsflyer",
            b"Adjust",
            b"FacebookSDK",
            b"Crashlytics",
        ]
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = Path(root) / file
                with open(file_path, 'rb') as f:
                    content = f.read()
                    for tracker in trackers:
                        if tracker in content:
                            self.report_content.append(f"Tracker found in {file_path}: {tracker.decode()}")
                            logging.warning(f"Tracker found in {file_path}: {tracker.decode()}")

    def check_critical_permissions(self):
        critical_permissions = [
            "NSLocationAlwaysUsageDescription",
            "NSLocationWhenInUseUsageDescription",
            "NSCameraUsageDescription",
            "NSMicrophoneUsageDescription",
            "NSPhotoLibraryUsageDescription",
            "NSContactsUsageDescription"
        ]
        info_plist = self.extracted_path / "Info.plist"
        if info_plist.exists():
            with open(info_plist, 'rb') as f:
                plist_content = f.read().decode('utf-8', errors='ignore')
                for permission in critical_permissions:
                    if permission in plist_content:
                        self.report_content.append(f"Critical permission found in Info.plist: {permission}")
                        logging.warning(f"Critical permission found in Info.plist: {permission}")

    def generate_report(self):
        with open(self.report_file, 'w') as report:
            # Write a title and section for sensitive data
            report.write("=== Sensitive Data Found ===\n\n")
            for line in self.report_content:
                if "Sensitive data" in line:
                    report.write(line + "\n")
            
            # Write a section for insecure APIs
            report.write("\n=== Insecure APIs Found ===\n\n")
            for line in self.report_content:
                if "Insecure API" in line:
                    report.write(line + "\n")

            # Write a section for trackers
            report.write("\n=== Trackers Found ===\n\n")
            for line in self.report_content:
                if "Tracker found" in line:
                    report.write(line + "\n")

            # Write a section for jailbreak indicators
            report.write("\n=== Jailbreak Indicators Found ===\n\n")
            for line in self.report_content:
                if "Jailbreak indicator" in line:
                    report.write(line + "\n")

        logging.info(f"Structured report generated: {self.report_file}")


import logging
from extraction import IPAExtractor
from analysis import IPAAnalyzer
from download import download_ipa_from_device

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Define constants
EXTRACTED_PATH = "extracted_app"
REPORT_FILE = "analysis_report.txt"
DEFAULT_IPA_NAME = "downloaded_app.ipa"  # Define the default IPA file name

def main_menu():
    dump_script_path = input("Enter the full path to dump.py (or leave empty if it's in the current directory): ").strip() or "dump.py"
    
    while True:
        print("""
        1. Extract and Analyze IPA (Manual Path)
        2. Download IPA from Connected Device and Analyze
        3. Exit
        """)
        choice = input("Enter your choice: ")

        if choice == '1':
            ipa_file = input("Enter the path to the IPA file: ")
            extractor = IPAExtractor(ipa_file, EXTRACTED_PATH)
            if extractor.extract_ipa():
                analyzer = IPAAnalyzer(EXTRACTED_PATH, REPORT_FILE)
                analyzer.analyze()
        elif choice == '2':
            ssh_host = input("Enter the SSH host (or leave empty for default): ").strip() or None
            ssh_port = input("Enter the SSH port (or leave empty for default): ").strip() or None
            ssh_user = input("Enter the SSH username (or leave empty for default): ").strip() or None
            ssh_password = input("Enter the SSH password (or leave empty for default): ").strip() or None
            output_ipa_name = input(f"Enter the output IPA file name (or leave empty for default '{DEFAULT_IPA_NAME}'): ").strip() or DEFAULT_IPA_NAME
            
            app_bundle_id = input("Enter the app bundle identifier: ")
            downloaded_ipa_path = download_ipa_from_device(
                app_bundle_id, dump_script_path,
                ssh_host=ssh_host, ssh_port=ssh_port,
                ssh_user=ssh_user, ssh_password=ssh_password,
                output_ipa_name=output_ipa_name
            )
            if downloaded_ipa_path:
                extractor = IPAExtractor(downloaded_ipa_path, EXTRACTED_PATH)
                if extractor.extract_ipa():
                    analyzer = IPAAnalyzer(EXTRACTED_PATH, REPORT_FILE)
                    analyzer.analyze()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()


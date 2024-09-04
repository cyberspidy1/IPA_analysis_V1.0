import subprocess
import logging
from pathlib import Path

DEFAULT_IPA_NAME = "downloaded_app.ipa"

def download_ipa_from_device(app_bundle_id, dump_script_path="dump.py", ssh_host=None, ssh_port=None, ssh_user=None, ssh_password=None, output_ipa_name=DEFAULT_IPA_NAME):
    try:
        cmd = ['python3', dump_script_path, '-o', output_ipa_name, app_bundle_id]
        
        if ssh_host:
            cmd += ['-H', ssh_host]
        if ssh_port:
            cmd += ['-p', str(ssh_port)]
        if ssh_user:
            cmd += ['-u', ssh_user]
        if ssh_password:
            cmd += ['-P', ssh_password]

        logging.info(f"Running dump.py with command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info(f"IPA downloaded successfully: {output_ipa_name}")
            logging.debug(result.stdout)
            if Path(output_ipa_name).exists():
                return output_ipa_name
            else:
                logging.error(f"Expected IPA file not found: {output_ipa_name}")
                return None
        else:
            logging.error(f"Failed to download IPA: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Failed to download IPA: {e}")
        return None


import os
import re

ESET_LOG_DIR = r"C:\ProgramData\ESET\ESET Security\Logs"
OUTPUT_FILE = "eset_logs_extracted.txt"

def extract_text_from_dat(dat_file):
    with open(dat_file, "rb") as f:
        raw = f.read()
    # Extract readable ASCII/UTF-8 strings (min length 4)
    strings = re.findall(rb"[ -~]{4,}", raw)
    return [s.decode(errors="ignore") for s in strings]

def export_all_logs(log_dir, output_file):
    with open(output_file, "w", encoding="utf-8") as out:
        for file in os.listdir(log_dir):
            if file.endswith(".dat"):
                file_path = os.path.join(log_dir, file)
                out.write(f"\n--- {file} ---\n")
                logs = extract_text_from_dat(file_path)
                out.write("\n".join(logs))
                out.write("\n")
    print(f"[✔] Logs extracted to {output_file}")

if __name__ == "__main__":
    export_all_logs(ESET_LOG_DIR, OUTPUT_FILE)

"""
Dataset acquisition utility for CIC-IDS2017.

Downloads a manageable representative CSV file from the documented public mirror
into data/raw/ and creates a stratified sample for fast local testing and EDA.
"""

import sys
import urllib.request
from pathlib import Path
import pandas as pd
from intrusion_xai.config import DATA_RAW_DIR, RANDOM_SEED

DATASET_URL = (
    "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/"
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)
RAW_FILE_NAME = "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
SAMPLE_FILE_NAME = "cicids2017_sample.csv"

def download_dataset(target_dir: Path = DATA_RAW_DIR, sample_size: int = 10000) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    raw_path = target_dir / RAW_FILE_NAME
    sample_path = target_dir / SAMPLE_FILE_NAME

    if not raw_path.exists():
        print(f"[INFO] Downloading official CIC-IDS2017 flow file from:\n  {DATASET_URL}")
        print(f"[INFO] Saving to:\n  {raw_path}")
        
        def reporthook(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                percent = min(100.0, downloaded * 100.0 / total_size)
                mb = downloaded / (1024 * 1024)
                total_mb = total_size / (1024 * 1024)
                sys.stdout.write(f"\r  Downloading: {mb:.1f} MB / {total_mb:.1f} MB ({percent:.1f}%)")
                sys.stdout.flush()

        urllib.request.urlretrieve(DATASET_URL, raw_path, reporthook=reporthook)
        print("\n[SUCCESS] Download completed successfully.")
    else:
        print(f"[INFO] Raw dataset already exists at {raw_path}")

    # Generate stratified sample ensuring all columns and target labels are strictly preserved
    print(f"[INFO] Generating stratified sample of {sample_size} records...")
    df = pd.read_csv(raw_path, low_memory=False)
    # Strip header whitespace to access label column safely
    df.columns = df.columns.str.strip()
    label_col = "Label" if "Label" in df.columns else df.columns[-1]

    class_counts = df[label_col].value_counts()
    print(f"[INFO] Raw Class Distribution:\n{class_counts}")
    
    sampled_dfs = []
    for _, group in df.groupby(label_col):
        n = int(round(sample_size * len(group) / len(df)))
        sampled_dfs.append(group.sample(n=n, random_state=RANDOM_SEED))

    sampled_df = (
        pd.concat(sampled_dfs)
        .sample(frac=1.0, random_state=RANDOM_SEED)
        .reset_index(drop=True)
    )
    sampled_df.to_csv(sample_path, index=False)
    print(f"[SUCCESS] Sample saved to {sample_path} ({len(sampled_df)} rows, {sampled_df.shape[1]} columns).")

if __name__ == "__main__":
    download_dataset()

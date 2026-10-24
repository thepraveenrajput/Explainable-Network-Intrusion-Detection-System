# Dataset Card: CIC-IDS2017

## 1. Overview & Provenance
- **Dataset Name**: Canadian Institute for Cybersecurity Intrusion Detection System 2017 (CIC-IDS2017)
- **Publishing Institution**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB), Canada
- **Authors**: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani (2018)
- **Official URL**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Citation**: Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 108–116.

## 2. Capture Environment & Methodology
The dataset captures 5 days of bidirectional network traffic generated in an emulated enterprise testbed:
- **Duration**: Monday, July 3, 2017 to Friday, July 7, 2017.
- **Traffic Nature**: Natural human-like background traffic generated using the B-Profile system (abstracting browsing, email, FTP, SSH patterns) combined with contemporary cyber attack execution profiles (M-Profiles).
- **Flow Extraction**: Raw packet captures (`.pcap`) were converted into bidirectional network flow statistics using the open-source **CICFlowMeter** tool.

## 3. Class Distribution & Attack Taxonomy
The dataset contains normal traffic (`BENIGN`) alongside 14 distinct attack categories executed across different days:

| Attack Category | Execution Window | Characteristics |
| :--- | :--- | :--- |
| **BENIGN** | Mon–Fri (Continuous) | Normal HTTP, HTTPS, SSH, FTP, DNS background traffic |
| **DDoS (LOIC)** | Friday Afternoon | Distributed high-volume packet flooding |
| **PortScan** | Friday Afternoon | Systematic port sweeping probing for open services |
| **DoS Hulk / GoldenEye** | Wednesday | HTTP/HTTPS application-layer request exhaustion |
| **DoS slowloris / Slowhttptest** | Wednesday | Low-and-slow incomplete HTTP request holding |
| **FTP-Patator / SSH-Patator** | Tuesday | Dictionary brute-force authentication attacks |
| **Web Attacks (Brute/XSS/SQLi)**| Thursday Morning | Application-layer exploits targeting web vulnerabilities |
| **Botnet (ARES)** | Thursday Afternoon | Command-and-Control (C2) infected endpoint activity |
| **Infiltration & Heartbleed** | Wednesday / Thursday | Privilege escalation and OpenSSL buffer over-read |

## 4. Known Data Quality Quirks & Cleaning Requirements
Extensive exploratory data analysis of the raw CSVs reveals several critical quirks that must be handled during preprocessing:
1. **Leading/Trailing Whitespace in Headers**: Several columns contain accidental leading spaces (e.g. `' Destination Port'`, `' Flow Duration'`, `' Total Fwd Packets'`). These must be stripped during ingestion.
2. **Infinite Values (`Infinity` / `-Infinity`)**: Features measuring rates (such as `Flow Bytes/s` and `Flow Packets/s`) contain divisions by zero when flow duration is 0 microseconds. These must be replaced with the maximum observed finite value or median imputed.
3. **Missing Values (`NaN`)**: Sparse missing values in flow variance fields require explicit statistical imputation (`SimpleImputer`).
4. **Non-Generalizable Identity Columns**: Columns such as `Flow ID`, `Source IP`, `Destination IP`, and `Timestamp` allow machine learning models to "memorize" the experimental testbed IP subnet (e.g., `192.168.10.50`), causing severe artificial data leakage. They must be dropped before training.
5. **Severe Class Imbalance**: Benign flows make up approximately 80–84% of total traffic. Evaluation must rely on Precision, Recall, F1-Score, and False Positive Rate rather than raw accuracy alone.

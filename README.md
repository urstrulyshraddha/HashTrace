# HashTrace (`hace`) 🔍

[![PyPI version](https://img.shields.io/pypi/v/hashtrace.svg)](https://pypi.org/project/hashtrace/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A dependency-free digital forensics and file integrity CLI. 

**HashTrace** computes cryptographic file digests across multiple algorithms in a single disk pass, verifies forensic replicas, inspects UTC MACB timestamps, and exports machine-readable JSON artifacts.

---

## ⚡ Quick Installation

### Method 1: Install from PyPI (Recommended)
```bash
pip install hashtrace
```

### Method 2: Install directly from GitHub
```bash
pip install git+[https://github.com/your-username/hashtrace.git](https://github.com/your-username/hashtrace.git)
```

> **Note:** Once installed, you can invoke the tool using either the full command **`hashtrace`** or the shortcut alias **`hace`**.

---

## 🚀 Quick Start & Usage

### 1. Basic Triage (Default: MD5, SHA-1, SHA-256)
Compute file digests along with filesystem size and timestamps:
```bash
hace sample.txt
```

### 2. Custom Algorithm Selection
Select specific algorithms dynamically using `-a` or `--algos`:
```bash
hace disk_dump.img -a md5 sha256 sha512
```

### 3. Verify Against a Known Signature
Verify a file against an expected hash (e.g., malware hash or vendor checksum):
```bash
hace firmware.bin --verify 05ade08fcfb104f40b2536a14dfcd6e916d643f5cf8044b19028b607ae8f4908
```

### 4. Forensic Replica Verification (Diff Mode)
Ensure an evidence image matches the original bit-for-bit:
```bash
hace --compare evidence.raw evidence_copy.raw
```

### 5. Export JSON Evidence Artifact
Export findings to a structured JSON file for reporting:
```bash
hace sample.txt -o case_report.json
```

---

## 🔬 Forensic Features

* **Single-Pass Multi-Hashing:** Reads files in 64 KB memory-safe chunks, streaming each block simultaneously to all selected hash engines without re-reading the disk.
* **UTC MACB Timestamps:** Extracts Modified, Accessed, and Created timestamps normalized to UTC for reliable timeline reconstruction.
* **Zero External Dependencies:** Built entirely with Python standard library modules (`hashlib`, `pathlib`, `argparse`, `json`).
* **Non-Destructive:** Operates in strict read-only binary mode (`rb`), ensuring file integrity remains untouched.

---

## 🧪 Running Tests

To run the validation test suite:
```bash
python test_hasher.py
```

---

## 📄 License

This project is licensed under the MIT License.

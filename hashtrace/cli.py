"""
HashTrace - Digital Forensics File Integrity & Triage CLI
Calculates multi-algorithm cryptographic digests, verifies file integrity,
and generates forensic acquisition reports.
"""

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

BUFFER_SIZE = 65536  # 64 KB memory-safe chunk size
DEFAULT_ALGORITHMS = ["md5", "sha1", "sha256"]
SUPPORTED_ALGORITHMS = sorted(hashlib.algorithms_guaranteed)


def format_bytes(size: int) -> str:
    """Formats file size into human-readable units."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024.0
    return f"{size:.2f} PB"


def get_file_metadata(filepath: Path) -> Dict[str, str]:
    """Extracts UTC MACB timestamps (Modified, Accessed, Created) for forensic integrity."""
    stat = filepath.stat()

    # st_ctime on Windows represents file creation; on Unix it represents inode change time
    created_or_metadata = datetime.datetime.fromtimestamp(
        stat.st_ctime, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    modified = datetime.datetime.fromtimestamp(
        stat.st_mtime, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    accessed = datetime.datetime.fromtimestamp(
        stat.st_atime, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "size_bytes": stat.st_size,
        "size_human": format_bytes(stat.st_size),
        "created_utc": created_or_metadata,
        "modified_utc": modified,
        "accessed_utc": accessed,
    }


def compute_hashes(filepath: Path, algorithms: List[str]) -> Dict[str, str]:
    """
    Streams file in binary chunks, feeding data to all requested hashing engines
    in a single disk I/O pass.
    """
    # Normalize algorithms to lowercase
    algos = [algo.lower() for algo in algorithms]
    engines = {algo: hashlib.new(algo) for algo in algos}

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            for engine in engines.values():
                engine.update(chunk)

    return {algo.upper(): engine.hexdigest() for algo, engine in engines.items()}


def generate_forensic_report(filepath: Path, algorithms: List[str]) -> Dict:
    """Combines path data, filesystem metadata, and cryptographic hashes into an artifact."""
    meta = get_file_metadata(filepath)
    digests = compute_hashes(filepath, algorithms)
    analysis_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "analysis_timestamp_utc": analysis_time,
        "file_name": filepath.name,
        "absolute_path": str(filepath.resolve()),
        "metadata": meta,
        "hashes": digests,
    }


def print_forensic_report(report: Dict) -> None:
    """Renders human-readable forensic summary to standard output."""
    meta = report["metadata"]
    print("\n" + "=" * 58)
    print("           HASHTRACE: FORENSIC ACQUISITION REPORT         ")
    print("=" * 58)
    print(f"Timestamp    : {report['analysis_timestamp_utc']}")
    print(f"File Name    : {report['file_name']}")
    print(f"Full Path    : {report['absolute_path']}")
    print(f"Size         : {meta['size_human']} ({meta['size_bytes']:,} bytes)")
    print("-" * 58)
    print("TIMESTAMPS (MACB):")
    print(f"  Created/Metadata : {meta['created_utc']}")
    print(f"  Last Modified    : {meta['modified_utc']}")
    print(f"  Last Accessed    : {meta['accessed_utc']}")
    print("-" * 58)
    print("CRYPTOGRAPHIC DIGESTS:")
    for algo, digest in report["hashes"].items():
        print(f"  {algo:<8} : {digest}")
    print("=" * 58 + "\n")


def compare_two_files(path1: Path, path2: Path, algorithm: str = "sha256") -> None:
    """Verifies evidence parity between an original source and an acquisition replica."""
    print(f"\nComparing files via {algorithm.upper()}...")
    hash1 = compute_hashes(path1, [algorithm])[algorithm.upper()]
    hash2 = compute_hashes(path2, [algorithm])[algorithm.upper()]

    print(f"File 1 ({path1.name}): {hash1}")
    print(f"File 2 ({path2.name}): {hash2}")

    if hash1 == hash2:
        print("[+] VERIFICATION SUCCESS: Files are bit-for-bit IDENTICAL.")
    else:
        print("[!] VERIFICATION FAILURE: Hashes do NOT match. Evidence tampering or corruption detected.")


def build_parser() -> argparse.ArgumentParser:
    """Defines command-line arguments and options."""
    parser = argparse.ArgumentParser(
        prog="hashtrace",
        description="Forensic file integrity engine & cryptographic hash generator.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        type=Path,
        help="Target file path for hashing.",
    )
    parser.add_argument(
        "-a",
        "--algos",
        nargs="+",
        default=DEFAULT_ALGORITHMS,
        help=f"Hash algorithms to execute. Defaults: {DEFAULT_ALGORITHMS}. Supported: {SUPPORTED_ALGORITHMS}",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        type=Path,
        metavar=("FILE1", "FILE2"),
        help="Compare two files bit-for-bit using SHA-256.",
    )
    parser.add_argument(
        "--verify",
        type=str,
        metavar="EXPECTED_HASH",
        help="Verify the file against a known target hash.",
    )
    parser.add_argument(
        "-o",
        "--output-json",
        type=Path,
        help="Export report directly into a structured JSON file.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Case 1: File comparison mode
    if args.compare:
        f1, f2 = args.compare
        for target in (f1, f2):
            if not target.is_file():
                print(f"[!] Error: Path is not a valid file: {target}", file=sys.stderr)
                sys.exit(1)
        compare_two_files(f1, f2)
        return

    # Case 2: Target file resolution (CLI flag or interactive prompt fallback)
    target_path = args.file
    if target_path is None:
        try:
            user_input = input("Enter target file path: ").strip()
            if not user_input:
                print("[!] No file path entered. Exiting.")
                return
            target_path = Path(user_input)
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled by user.")
            return

    target_path = target_path.expanduser().resolve()
    if not target_path.exists():
        print(f"[!] Error: File does not exist: {target_path}", file=sys.stderr)
        sys.exit(1)
    if not target_path.is_file():
        print(f"[!] Error: Path is not a file: {target_path}", file=sys.stderr)
        sys.exit(1)

    # Validate algorithm choices
    chosen_algos = []
    for a in args.algos:
        if a.lower() not in hashlib.algorithms_available:
            print(f"[!] Unsupported algorithm: {a}. Available: {SUPPORTED_ALGORITHMS}", file=sys.stderr)
            sys.exit(1)
        chosen_algos.append(a.lower())

    # Generate the artifact report
    report = generate_forensic_report(target_path, chosen_algos)
    print_forensic_report(report)

    # Case 3: Verify against known signature
    if args.verify:
        expected = args.verify.strip().lower()
        match_found = False
        for algo, calculated in report["hashes"].items():
            if calculated.lower() == expected:
                print(f"[+] VERIFY MATCH: Target hash matches calculated {algo} digest.")
                match_found = True
                break
        if not match_found:
            print("[!] VERIFY MISMATCH: The provided hash does not match any computed digests.")

    # Case 4: Export to JSON artifact
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as out:
                json.dump(report, out, indent=4)
            print(f"[+] Forensic report successfully saved to: {args.output_json.resolve()}")
        except OSError as err:
            print(f"[!] Failed to write JSON output: {err}", file=sys.stderr)


if __name__ == "__main__":
    main()
